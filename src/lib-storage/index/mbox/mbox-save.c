/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "hostpid.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "write-full.h"
#include "istream-header-filter.h"
#include "ostream-crlf.h"
#include "message-parser.h"
#include "mbox-storage.h"
#include "mbox-file.h"
#include "mbox-from.h"
#include "mbox-lock.h"
#include "mbox-sync-private.h"

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <netdb.h>

struct mbox_save_context {
	struct mail_save_context ctx;

	struct index_mailbox *ibox;
	struct mail_index_transaction *trans;
	uoff_t append_offset, mail_offset;

	string_t *headers;
	size_t space_end_idx;
	uint32_t seq, next_uid;

	struct istream *input;
	struct ostream *output, *body_output;
	uoff_t extra_hdr_offset, eoh_offset, eoh_input_offset;
	char last_char;

	struct index_mail mail;
	const struct mail_full_flags *flags;

	unsigned int synced:1;
	unsigned int failed:1;
	unsigned int save_crlf:1;
};

static char my_hostdomain[256] = "";

static void write_error(struct mbox_save_context *ctx)
{
	if (ENOSPACE(errno)) {
		mail_storage_set_error(ctx->ibox->box.storage,
				       "Not enough disk space");
	} else {
                mbox_set_syscall_error(ctx->ibox, "write()");
	}
}

static int mbox_seek_to_end(struct mbox_save_context *ctx, uoff_t *offset)
{
	struct stat st;
	char ch;
	int fd;

	fd = ctx->ibox->mbox_fd;
	if (fstat(fd, &st) < 0)
                return mbox_set_syscall_error(ctx->ibox, "fstat()");

	*offset = (uoff_t)st.st_size;
	if (st.st_size == 0)
		return 0;

	if (lseek(fd, st.st_size-1, SEEK_SET) < 0)
                return mbox_set_syscall_error(ctx->ibox, "lseek()");

	if (read(fd, &ch, 1) != 1)
		return mbox_set_syscall_error(ctx->ibox, "read()");

	if (ch != '\n') {
		if (write_full(fd, "\n", 1) < 0) {
			write_error(ctx);
			return -1;
		}
		*offset += 1;
	}

	return 0;
}

static int mbox_append_lf(struct mbox_save_context *ctx)
{
	if (o_stream_send(ctx->output, "\n", 1) < 0) {
		write_error(ctx);
		return -1;
	}

	return 0;
}

static int write_from_line(struct mbox_save_context *ctx, time_t received_date,
			   const char *from_envelope)
{
	const char *line, *name;
	int ret;

	if (*my_hostdomain == '\0') {
		struct hostent *hent;

		hent = gethostbyname(my_hostname);

		name = hent != NULL ? hent->h_name : NULL;
		if (name == NULL) {
			/* failed, use just the hostname */
			name = my_hostname;
		}

		strocpy(my_hostdomain, name, sizeof(my_hostdomain));
	}

	t_push();
	if (from_envelope == NULL) {
		from_envelope = t_strconcat(ctx->ibox->storage->user, "@",
					    my_hostdomain, NULL);
	}

	/* save in local timezone, no matter what it was given with */
	line = mbox_from_create(from_envelope, received_date);

	if ((ret = o_stream_send_str(ctx->output, line)) < 0)
		write_error(ctx);
	t_pop();

	return ret;
}

static int mbox_write_content_length(struct mbox_save_context *ctx)
{
	uoff_t end_offset;
	const char *str;
	size_t len;
	int ret = 0;

	end_offset = ctx->output->offset;

	/* write Content-Length headers */
	t_push();
	str = t_strdup_printf("\nContent-Length: %s",
			      dec2str(end_offset - ctx->eoh_offset));
	len = strlen(str);

	if (o_stream_seek(ctx->output, ctx->extra_hdr_offset +
			  ctx->space_end_idx - len) < 0) {
		mbox_set_syscall_error(ctx->ibox, "o_stream_seek()");
		ret = -1;
	} else if (o_stream_send(ctx->output, str, len) < 0) {
		write_error(ctx);
		ret = -1;
	} else {
		if (o_stream_seek(ctx->output, end_offset) < 0) {
			mbox_set_syscall_error(ctx->ibox, "o_stream_seek()");
			ret = -1;
		}
	}

	t_pop();
	return ret;
}

static int mbox_save_init_sync(struct mbox_transaction_context *t)
{
	struct mbox_save_context *ctx = t->save_ctx;
	const struct mail_index_header *hdr;

	if (mail_index_get_header(t->ictx.trans_view, &hdr) < 0) {
		mail_storage_set_index_error(ctx->ibox);
		return -1;
	}
	ctx->next_uid = hdr->next_uid;
	ctx->synced = TRUE;
        t->mbox_modified = TRUE;

	index_mail_init(&t->ictx, &ctx->mail, 0, NULL);
	return 0;
}

static void status_flags_append(string_t *str, enum mail_flags flags,
				const struct mbox_flag_type *flags_list)
{
	int i;

	for (i = 0; flags_list[i].chr != 0; i++) {
		if ((flags & flags_list[i].flag) != 0)
			str_append_c(str, flags_list[i].chr);
	}
}

static void mbox_save_append_flag_headers(string_t *str, enum mail_flags flags)
{
	if ((flags & STATUS_FLAGS_MASK) != 0) {
		str_append(str, "Status: ");
		status_flags_append(str, flags, mbox_status_flags);
		str_append_c(str, '\n');
	}

	if ((flags & XSTATUS_FLAGS_MASK) != 0) {
		str_append(str, "X-Status: ");
		status_flags_append(str, flags, mbox_xstatus_flags);
		str_append_c(str, '\n');
	}
}

static void mbox_save_append_keyword_headers(struct mbox_save_context *ctx,
					     const char *const *keywords,
					     unsigned int count)
{
	unsigned char space[MBOX_HEADER_PADDING+1 +
			    sizeof("Content-Length: \n")-1 + MAX_INT_STRLEN];
	unsigned int i;

	str_append(ctx->headers, "X-Keywords:");
	for (i = 0; i < count; i++) {
		str_append_c(ctx->headers, ' ');
		str_append(ctx->headers, keywords[i]);
	}

	memset(space, ' ', sizeof(space));
	str_append_n(ctx->headers, space, sizeof(space));
	ctx->space_end_idx = str_len(ctx->headers);
	str_append_c(ctx->headers, '\n');
}

static int
mbox_save_init_file(struct mbox_save_context *ctx,
		    struct mbox_transaction_context *t, int want_mail)
{
	struct index_mailbox *ibox = ctx->ibox;
	int ret;

	if (ctx->append_offset == (uoff_t)-1) {
		/* first appended mail in this transaction */
		if (ibox->mbox_lock_type != F_WRLCK) {
			if (mbox_lock(ibox, F_WRLCK, &t->mbox_lock_id) <= 0)
				return -1;
		}

		if (ibox->mbox_fd == -1) {
			if (mbox_file_open(ibox) < 0)
				return -1;
		}

		if (!want_mail) {
			/* assign UIDs only if mbox doesn't require syncing */
			ret = mbox_sync_has_changed(ibox);
			if (ret < 0)
				return -1;
			if (ret == 0) {
				if (mbox_save_init_sync(t) < 0)
					return -1;
			}
		}

		if (mbox_seek_to_end(ctx, &ctx->append_offset) < 0)
			return -1;

		ctx->output = o_stream_create_file(ibox->mbox_fd, default_pool,
						   0, FALSE);
	}

	if (!ctx->synced && want_mail) {
		/* we'll need to assign UID for the mail immediately. */
		if (mbox_sync(ibox, FALSE, FALSE, FALSE) < 0)
			return -1;
		if (mbox_save_init_sync(t) < 0)
			return -1;
	}

	return 0;
}

static void save_header_callback(struct message_header_line *hdr,
				 int *matched __attr_unused__, void *context)
{
	struct mbox_save_context *ctx = context;

	if ((hdr == NULL && ctx->eoh_input_offset == (uoff_t)-1) ||
	    (hdr != NULL && hdr->eoh))
		ctx->eoh_input_offset = ctx->input->v_offset;
}

struct mail_save_context *
mbox_save_init(struct mailbox_transaction_context *_t,
	       const struct mail_full_flags *flags,
	       time_t received_date, int timezone_offset __attr_unused__,
	       const char *from_envelope, struct istream *input, int want_mail)
{
	struct mbox_transaction_context *t =
		(struct mbox_transaction_context *)_t;
	struct index_mailbox *ibox = t->ictx.ibox;
	struct mbox_save_context *ctx = t->save_ctx;
	enum mail_flags save_flags;
	keywords_mask_t keywords;
	uint64_t offset;

	/* FIXME: we could write timezone_offset to From-line.. */
	if (received_date == (time_t)-1)
		received_date = ioloop_time;

	if (ctx == NULL) {
		ctx = t->save_ctx = i_new(struct mbox_save_context, 1);
		ctx->ctx.box = &ibox->box;
		ctx->ibox = ibox;
		ctx->trans = t->ictx.trans;
		ctx->append_offset = (uoff_t)-1;
		ctx->headers = str_new(default_pool, 512);
		ctx->save_crlf = getenv("MAIL_SAVE_CRLF") != NULL;
		ctx->mail_offset = (uoff_t)-1;
	}

	ctx->failed = FALSE;
	ctx->seq = 0;

	ctx->flags = flags;

	if (mbox_save_init_file(ctx, t, want_mail) < 0) {
		ctx->failed = TRUE;
		return &ctx->ctx;
	}

	save_flags = (flags->flags & ~MAIL_RECENT) | MAIL_RECENT;
	str_truncate(ctx->headers, 0);
	if (ctx->synced) {
		str_printfa(ctx->headers, "X-UID: %u\n", ctx->next_uid);
		if (!ibox->keep_recent)
			save_flags &= ~MAIL_RECENT;

		memset(keywords, 0, INDEX_KEYWORDS_BYTE_COUNT);
		// FIXME: set keywords
		mail_index_append(ctx->trans, ctx->next_uid, &ctx->seq);
		mail_index_update_flags(ctx->trans, ctx->seq, MODIFY_REPLACE,
					save_flags, keywords);

		offset = ctx->output->offset == 0 ? 0 :
			ctx->output->offset - 1;
		mail_index_update_extra_rec(ctx->trans, ctx->seq,
					    ibox->mbox_extra_idx, &offset);
		ctx->next_uid++;
	}
	mbox_save_append_flag_headers(ctx->headers,
				      save_flags ^ MBOX_NONRECENT);
	mbox_save_append_keyword_headers(ctx, flags->keywords,
					 flags->keywords_count);
	str_append_c(ctx->headers, '\n');

	i_assert(ibox->mbox_lock_type == F_WRLCK);

	ctx->mail_offset = ctx->output->offset;
	ctx->eoh_input_offset = (uoff_t)-1;
	ctx->eoh_offset = (uoff_t)-1;
	ctx->last_char = '\n';

	if (write_from_line(ctx, received_date, from_envelope) < 0)
		ctx->failed = TRUE;
	else {
		ctx->input =
			i_stream_create_header_filter(input,
						      HEADER_FILTER_EXCLUDE |
                                                      HEADER_FILTER_NO_CR,
						      mbox_hide_headers,
						      mbox_hide_headers_count,
						      save_header_callback,
						      ctx);
		ctx->body_output = getenv("MAIL_SAVE_CRLF") != NULL ?
			o_stream_create_crlf(default_pool, ctx->output) :
			o_stream_create_lf(default_pool, ctx->output);
	}

	return &ctx->ctx;
}

int mbox_save_continue(struct mail_save_context *_ctx)
{
	struct mbox_save_context *ctx = (struct mbox_save_context *)_ctx;
	const unsigned char *data;
	size_t size, hdr_size;
	ssize_t ret;

	if (ctx->failed)
		return -1;

	if (ctx->eoh_offset != (uoff_t)-1) {
		/* writing body */
		if (o_stream_send_istream(ctx->body_output, ctx->input) < 0) {
			ctx->failed = TRUE;
			return -1;
		}
		return 0;
	}

	while ((ret = i_stream_read(ctx->input)) != -1) {
		if (ret == 0)
			return 0;

		data = i_stream_get_data(ctx->input, &size);
		if (ctx->eoh_input_offset != (uoff_t)-1 &&
		    ctx->input->v_offset + size >= ctx->eoh_input_offset) {
			/* found end of headers. write the rest of them. */
			size = ctx->eoh_input_offset - ctx->input->v_offset;
			if (o_stream_send(ctx->output, data, hdr_size) < 0) {
				ctx->failed = TRUE;
				return -1;
			}
			if (hdr_size > 0)
				ctx->last_char = data[hdr_size-1];
			i_stream_skip(ctx->input, size + 1);
			break;
		}

		if (o_stream_send(ctx->output, data, size) < 0) {
			ctx->failed = TRUE;
			return -1;
		}
		ctx->last_char = data[size-1];
		i_stream_skip(ctx->input, size);
	}

	if (ctx->last_char != '\n') {
		if (o_stream_send(ctx->output, "\n", 1) < 0) {
			ctx->failed = TRUE;
			return -1;
		}
	}

	/* append our own headers and ending empty line */
	ctx->extra_hdr_offset = ctx->output->offset;
	if (o_stream_send(ctx->output, str_data(ctx->headers),
			  str_len(ctx->headers)) < 0) {
		ctx->failed = TRUE;
		return -1;
	}
	ctx->eoh_offset = ctx->output->offset;

	/* write body */
	return ctx->input->eof ? 0 : mbox_save_continue(_ctx);
}

int mbox_save_finish(struct mail_save_context *_ctx, struct mail **mail_r)
{
	struct mbox_save_context *ctx = (struct mbox_save_context *)_ctx;

	if (!ctx->failed) {
		if (mbox_write_content_length(ctx) < 0 ||
		    mbox_append_lf(ctx) < 0)
			ctx->failed = TRUE;
	}

	if (ctx->input != NULL) {
		i_stream_unref(ctx->input);
		ctx->input = NULL;
	}
	if (ctx->body_output != NULL) {
		o_stream_unref(ctx->body_output);
		ctx->body_output = NULL;
	}

	if (ctx->failed && ctx->mail_offset != (uoff_t)-1) {
		/* saving this mail failed - truncate back to beginning of it */
		if (ftruncate(ctx->ibox->mbox_fd, (off_t)ctx->mail_offset) < 0)
			mbox_set_syscall_error(ctx->ibox, "ftruncate()");
		ctx->mail_offset = (uoff_t)-1;
	}

	if (ctx->failed) {
		errno = ctx->output->stream_errno;
		if (ENOSPACE(errno)) {
			mail_storage_set_error(ctx->ibox->box.storage,
					       "Not enough disk space");
		} else if (errno != 0) {
			mail_storage_set_critical(ctx->ibox->box.storage,
				"write(%s) failed: %m", ctx->ibox->path);
		}
		return -1;
	}

	if (mail_r != NULL) {
		i_assert(ctx->seq != 0);

		if (index_mail_next(&ctx->mail, ctx->seq) < 0)
			return -1;
		*mail_r = &ctx->mail.mail;
	}

	return 0;
}

void mbox_save_cancel(struct mail_save_context *_ctx)
{
	struct mbox_save_context *ctx = (struct mbox_save_context *)_ctx;

	ctx->failed = TRUE;
	(void)mbox_save_finish(_ctx, NULL);
}

static void mbox_transaction_save_deinit(struct mbox_save_context *ctx)
{
	i_assert(ctx->body_output == NULL);

	if (ctx->mail.pool != NULL)
		index_mail_deinit(&ctx->mail);

	if (ctx->output != NULL)
		o_stream_unref(ctx->output);
	str_free(ctx->headers);
	i_free(ctx);
}

int mbox_transaction_save_commit(struct mbox_save_context *ctx)
{
	int ret = 0;

	if (ctx->synced) {
		mail_index_update_header(ctx->trans,
			offsetof(struct mail_index_header, next_uid),
			&ctx->next_uid, sizeof(ctx->next_uid));
	}

	if (!ctx->synced && ctx->ibox->mbox_fd != -1) {
		if (fdatasync(ctx->ibox->mbox_fd) < 0) {
			mbox_set_syscall_error(ctx->ibox, "fsync()");
			ret = -1;
		}
	}

	mbox_transaction_save_deinit(ctx);
	return ret;
}

void mbox_transaction_save_rollback(struct mbox_save_context *ctx)
{
	struct index_mailbox *ibox = ctx->ibox;

	if (ctx->append_offset != (uoff_t)-1 && ibox->mbox_fd != -1) {
		i_assert(ibox->mbox_lock_type == F_WRLCK);

		/* failed, truncate file back to original size.
		   output stream needs to be flushed before truncating
		   so unref() won't write anything. */
		o_stream_flush(ctx->output);

		if (ftruncate(ibox->mbox_fd, (off_t)ctx->append_offset) < 0)
			mbox_set_syscall_error(ibox, "ftruncate()");
	}

	mbox_transaction_save_deinit(ctx);
}
