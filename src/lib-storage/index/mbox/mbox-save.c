/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "base64.h"
#include "hostpid.h"
#include "randgen.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "write-full.h"
#include "istream-header-filter.h"
#include "istream-crlf.h"
#include "istream-concat.h"
#include "message-parser.h"
#include "mail-user.h"
#include "index-mail.h"
#include "mbox-storage.h"
#include "mbox-file.h"
#include "mbox-from.h"
#include "mbox-lock.h"
#include "mbox-md5.h"
#include "mbox-sync-private.h"

#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <utime.h>

#define MBOX_DELIVERY_ID_RAND_BYTES (64/8)

struct mbox_save_context {
	struct mail_save_context ctx;

	struct mbox_mailbox *mbox;
	struct mail_index_transaction *trans;
	uoff_t append_offset, mail_offset;
	time_t orig_atime;

	string_t *headers;
	size_t space_end_idx;
	uint32_t seq, next_uid, uid_validity;

	struct istream *input;
	struct ostream *output;
	uoff_t extra_hdr_offset, eoh_offset;
	char last_char;

	struct mbox_md5_context *mbox_md5_ctx;
	char *x_delivery_id_header;

	bool synced:1;
	bool failed:1;
	bool finished:1;
};

#define MBOX_SAVECTX(s)		container_of(s, struct mbox_save_context, ctx)

static void write_error(struct mbox_save_context *ctx)
{
	mbox_set_syscall_error(ctx->mbox, "write()");
	ctx->failed = TRUE;
}

static int mbox_seek_to_end(struct mbox_save_context *ctx, uoff_t *offset)
{
	struct stat st;
	char ch;
	int fd;

	if (ctx->mbox->mbox_writeonly) {
		*offset = 0;
		return 0;
	}

	fd = ctx->mbox->mbox_fd;
	if (fstat(fd, &st) < 0) {
		mbox_set_syscall_error(ctx->mbox, "fstat()");
		return -1;
	}

	ctx->orig_atime = st.st_atime;

	*offset = (uoff_t)st.st_size;
	if (st.st_size == 0)
		return 0;

	if (lseek(fd, st.st_size-1, SEEK_SET) < 0) {
                mbox_set_syscall_error(ctx->mbox, "lseek()");
		return -1;
	}

	if (read(fd, &ch, 1) != 1) {
		mbox_set_syscall_error(ctx->mbox, "read()");
		return -1;
	}

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
	int ret;

	T_BEGIN {
		const char *line;

		if (from_envelope == NULL) {
			struct mail_storage *storage =
				&ctx->mbox->storage->storage;

			from_envelope =
				strchr(storage->user->username, '@') != NULL ?
				storage->user->username :
				t_strconcat(storage->user->username,
					    "@", my_hostdomain(), NULL);
		} else if (*from_envelope == '\0') {
			/* can't write empty envelope */
			from_envelope = "MAILER-DAEMON";
		}

		/* save in local timezone, no matter what it was given with */
		line = mbox_from_create(from_envelope, received_date);

		if ((ret = o_stream_send_str(ctx->output, line)) < 0)
			write_error(ctx);
	} T_END;
	return ret;
}

static int mbox_write_content_length(struct mbox_save_context *ctx)
{
	uoff_t end_offset;
	const char *str;
	size_t len;

	i_assert(ctx->eoh_offset != (uoff_t)-1);

	if (ctx->mbox->mbox_writeonly) {
		/* we can't seek, don't set Content-Length */
		return 0;
	}

	end_offset = ctx->output->offset;

	/* write Content-Length headers */
	str = t_strdup_printf("\nContent-Length: %s",
			      dec2str(end_offset - ctx->eoh_offset));
	len = strlen(str);

	/* flush manually here so that we don't confuse seek() errors with
	   buffer flushing errors */
	if (o_stream_flush(ctx->output) < 0) {
		write_error(ctx);
		return -1;
	}
	if (o_stream_seek(ctx->output, ctx->extra_hdr_offset +
			  ctx->space_end_idx - len) < 0) {
		mbox_set_syscall_error(ctx->mbox, "lseek()");
		return -1;
	}

	if (o_stream_send(ctx->output, str, len) < 0 ||
	    o_stream_flush(ctx->output) < 0) {
		write_error(ctx);
		return -1;
	}

	if (o_stream_seek(ctx->output, end_offset) < 0) {
		mbox_set_syscall_error(ctx->mbox, "lseek()");
		return -1;
	}
	return 0;
}

static void mbox_save_init_sync(struct mailbox_transaction_context *t)
{
	struct mbox_mailbox *mbox = MBOX_MAILBOX(t->box);
	struct mbox_save_context *ctx = MBOX_SAVECTX(t->save_ctx);
	const struct mail_index_header *hdr;
	struct mail_index_view *view;

	/* open a new view to get the header. this is required if we just
	   synced the mailbox so we can get updated next_uid. */
	mail_index_refresh(mbox->box.index);
	view = mail_index_view_open(mbox->box.index);
	hdr = mail_index_get_header(view);

	ctx->next_uid = hdr->next_uid;
	ctx->uid_validity = hdr->uid_validity;
	ctx->synced = TRUE;

	mail_index_view_close(&view);
}

static void status_flags_append(string_t *str, enum mail_flags flags,
				const struct mbox_flag_type *flags_list)
{
	int i;

	flags ^= MBOX_NONRECENT_KLUDGE;
	for (i = 0; flags_list[i].chr != 0; i++) {
		if ((flags & flags_list[i].flag) != 0)
			str_append_c(str, flags_list[i].chr);
	}
}

static void mbox_save_append_flag_headers(string_t *str, enum mail_flags flags)
{
	/* write the Status: header always. It always gets added soon anyway. */
	str_append(str, "Status: ");
	status_flags_append(str, flags, mbox_status_flags);
	str_append_c(str, '\n');

	if ((flags & XSTATUS_FLAGS_MASK) != 0) {
		str_append(str, "X-Status: ");
		status_flags_append(str, flags, mbox_xstatus_flags);
		str_append_c(str, '\n');
	}
}

static void
mbox_save_append_keyword_headers(struct mbox_save_context *ctx,
				 struct mail_keywords *keywords)
{
	unsigned char space[MBOX_HEADER_PADDING+1 +
			    sizeof("Content-Length: \n")-1 + MAX_INT_STRLEN];
	const ARRAY_TYPE(keywords) *keyword_names_list;
	const char *const *keyword_names;
	unsigned int i, count, keyword_names_count;

	keyword_names_list = mail_index_get_keywords(ctx->mbox->box.index);
	keyword_names = array_get(keyword_names_list, &keyword_names_count);

	str_append(ctx->headers, "X-Keywords:");
	count = keywords == NULL ? 0 : keywords->count;
	for (i = 0; i < count; i++) {
		i_assert(keywords->idx[i] < keyword_names_count);

		str_append_c(ctx->headers, ' ');
		str_append(ctx->headers, keyword_names[keywords->idx[i]]);
	}

	memset(space, ' ', sizeof(space));
	str_append_data(ctx->headers, space, sizeof(space));
	ctx->space_end_idx = str_len(ctx->headers);
	str_append_c(ctx->headers, '\n');
}

static int
mbox_save_init_file(struct mbox_save_context *ctx,
		    struct mbox_transaction_context *t)
{
	struct mailbox_transaction_context *_t = &t->t;
	struct mbox_mailbox *mbox = ctx->mbox;
	struct mail_storage *storage = &mbox->storage->storage;
	int ret;

	if (mbox_is_backend_readonly(ctx->mbox)) {
		mail_storage_set_error(storage, MAIL_ERROR_PERM,
				       "Read-only mbox");
		return -1;
	}

	if (ctx->append_offset == (uoff_t)-1) {
		/* first appended mail in this transaction */
		if (t->write_lock_id == 0) {
			if (mbox_lock(mbox, F_WRLCK, &t->write_lock_id) <= 0)
				return -1;
		}

		if (mbox->mbox_fd == -1) {
			if (mbox_file_open(mbox) < 0)
				return -1;
		}

		/* update mbox_sync_dirty state */
		ret = mbox_sync_has_changed(mbox, TRUE);
		if (ret < 0)
			return -1;
	}

	if (!ctx->synced) {
		/* we'll need to assign UID for the mail immediately. */
		if (mbox_sync(mbox, 0) < 0)
			return -1;
		mbox_save_init_sync(_t);
	}

	/* the syncing above could have changed the append offset */
	if (ctx->append_offset == (uoff_t)-1) {
		if (mbox_seek_to_end(ctx, &ctx->append_offset) < 0)
			return -1;

		i_assert(mbox->mbox_fd != -1);
		ctx->output = o_stream_create_fd_file(mbox->mbox_fd,
						      ctx->append_offset,
						      FALSE);
		o_stream_cork(ctx->output);
	}
	return 0;
}

static void
save_header_callback(struct header_filter_istream *input ATTR_UNUSED,
		     struct message_header_line *hdr,
		     bool *matched, struct mbox_save_context *ctx)
{
	if (hdr != NULL) {
		if (str_begins(hdr->name, "From ")) {
			/* we can't allow From_-lines in headers. there's no
			   legitimate reason for allowing them in any case,
			   so just drop them. */
			*matched = TRUE;
			return;
		}

		if (!*matched && ctx->mbox_md5_ctx != NULL)
			ctx->mbox->md5_v.more(ctx->mbox_md5_ctx, hdr);
	}
}

static void mbox_save_x_delivery_id(struct mbox_save_context *ctx)
{
	unsigned char md5_result[MD5_RESULTLEN];
	buffer_t *buf;
	string_t *str;
	void *randbuf;

	buf = t_buffer_create(256);
	buffer_append(buf, &ioloop_time, sizeof(ioloop_time));
	buffer_append(buf, &ioloop_timeval.tv_usec,
		      sizeof(ioloop_timeval.tv_usec));

	randbuf = buffer_append_space_unsafe(buf, MBOX_DELIVERY_ID_RAND_BYTES);
	random_fill(randbuf, MBOX_DELIVERY_ID_RAND_BYTES);

	md5_get_digest(buf->data, buf->used, md5_result);

	str = t_str_new(128);
	str_append(str, "X-Delivery-ID: ");
	base64_encode(md5_result, sizeof(md5_result), str);
	str_append_c(str, '\n');

	ctx->x_delivery_id_header = i_strdup(str_c(str));
}

static struct istream *
mbox_save_get_input_stream(struct mbox_save_context *ctx, struct istream *input)
{
	struct istream *filter, *ret, *cache_input, *streams[3];

	/* filter out unwanted headers and keep track of headers' MD5 sum */
	filter = i_stream_create_header_filter(input, HEADER_FILTER_EXCLUDE |
					       HEADER_FILTER_NO_CR |
					       HEADER_FILTER_ADD_MISSING_EOH |
					       HEADER_FILTER_END_BODY_WITH_LF,
					       mbox_save_drop_headers,
					       mbox_save_drop_headers_count,
					       save_header_callback, ctx);

	if ((ctx->mbox->storage->storage.flags &
	     MAIL_STORAGE_FLAG_KEEP_HEADER_MD5) != 0) {
		/* we're using MD5 sums to generate POP3 UIDLs.
		   clients don't like it much if there are duplicates,
		   so make sure that there can't be any by appending
		   our own X-Delivery-ID header. */
		const char *hdr;

		T_BEGIN {
			mbox_save_x_delivery_id(ctx);
		} T_END;
		hdr = ctx->x_delivery_id_header;

		streams[0] = i_stream_create_from_data(hdr, strlen(hdr));
		streams[1] = filter;
		streams[2] = NULL;
		ret = i_stream_create_concat(streams);
		i_stream_unref(&filter);
		filter = ret;
	}

	/* convert linefeeds to wanted format */
	ret = ctx->mbox->storage->storage.set->mail_save_crlf ?
		i_stream_create_crlf(filter) : i_stream_create_lf(filter);
	i_stream_unref(&filter);

	/* caching creates a tee stream */
	cache_input = index_mail_cache_parse_init(ctx->ctx.dest_mail, ret);
	i_stream_unref(&ret);
	ret = cache_input;
	return ret;
}

struct mail_save_context *
mbox_save_alloc(struct mailbox_transaction_context *t)
{
	struct mbox_mailbox *mbox = MBOX_MAILBOX(t->box);
	struct mbox_save_context *ctx;

	i_assert((t->flags & MAILBOX_TRANSACTION_FLAG_EXTERNAL) != 0);

	if (t->save_ctx == NULL) {
		ctx = i_new(struct mbox_save_context, 1);
		ctx->ctx.transaction = t;
		ctx->mbox = mbox;
		ctx->trans = t->itrans;
		ctx->append_offset = (uoff_t)-1;
		ctx->headers = str_new(default_pool, 512);
		ctx->mail_offset = (uoff_t)-1;
		t->save_ctx = &ctx->ctx;
	}
	return t->save_ctx;
}

int mbox_save_begin(struct mail_save_context *_ctx, struct istream *input)
{
	struct mbox_save_context *ctx = MBOX_SAVECTX(_ctx);
	struct mail_save_data *mdata = &_ctx->data;
	struct mbox_transaction_context *t = MBOX_TRANSCTX(_ctx->transaction);
	enum mail_flags save_flags;
	uint64_t offset;

	/* FIXME: we could write timezone_offset to From-line.. */
	if (mdata->received_date == (time_t)-1)
		mdata->received_date = ioloop_time;

	ctx->failed = FALSE;
	ctx->seq = 0;

	if (mbox_save_init_file(ctx, t) < 0) {
		ctx->failed = TRUE;
		return -1;
	}

	save_flags = mdata->flags;
	if (mdata->uid == 0)
		save_flags |= MAIL_RECENT;
	str_truncate(ctx->headers, 0);
	if (ctx->synced) {
		if (ctx->mbox->mbox_save_md5)
			ctx->mbox_md5_ctx = ctx->mbox->md5_v.init();
		if (ctx->next_uid < mdata->uid) {
			/* we can use the wanted UID */
			ctx->next_uid = mdata->uid;
		}
		if (ctx->output->offset == 0) {
			/* writing the first mail. Insert X-IMAPbase as well. */
			str_printfa(ctx->headers, "X-IMAPbase: %u %010u\n",
				    ctx->uid_validity, ctx->next_uid);
		}
		str_printfa(ctx->headers, "X-UID: %u\n", ctx->next_uid);

		mail_index_append(ctx->trans, ctx->next_uid, &ctx->seq);
		mail_index_update_flags(ctx->trans, ctx->seq, MODIFY_REPLACE,
					save_flags & ~MAIL_RECENT);
		if (mdata->keywords != NULL) {
			mail_index_update_keywords(ctx->trans, ctx->seq,
						   MODIFY_REPLACE,
						   mdata->keywords);
		}
		if (mdata->min_modseq != 0) {
			mail_index_update_modseq(ctx->trans, ctx->seq,
						 mdata->min_modseq);
		}

		offset = ctx->output->offset == 0 ? 0 :
			ctx->output->offset - 1;
		mail_index_update_ext(ctx->trans, ctx->seq,
				      ctx->mbox->mbox_ext_idx, &offset, NULL);
		ctx->next_uid++;

		/* parse and cache the mail headers as we read it */
		mail_set_seq_saving(_ctx->dest_mail, ctx->seq);
	}
	mbox_save_append_flag_headers(ctx->headers, save_flags);
	mbox_save_append_keyword_headers(ctx, mdata->keywords);
	str_append_c(ctx->headers, '\n');

	i_assert(ctx->mbox->mbox_lock_type == F_WRLCK);

	ctx->mail_offset = ctx->output->offset;
	ctx->eoh_offset = (uoff_t)-1;
	ctx->last_char = '\n';

	if (write_from_line(ctx, mdata->received_date, mdata->from_envelope) < 0)
		ctx->failed = TRUE;
	else
		ctx->input = mbox_save_get_input_stream(ctx, input);
	return ctx->failed ? -1 : 0;
}

static int mbox_save_body_input(struct mbox_save_context *ctx)
{
	const unsigned char *data;
	size_t size;

	data = i_stream_get_data(ctx->input, &size);
	if (size > 0) {
		if (o_stream_send(ctx->output, data, size) < 0) {
			write_error(ctx);
			return -1;
		}
		ctx->last_char = data[size-1];
		i_stream_skip(ctx->input, size);
	}
	return 0;
}

static int mbox_save_body(struct mbox_save_context *ctx)
{
	ssize_t ret;

	while ((ret = i_stream_read(ctx->input)) != -1) {
		if (mbox_save_body_input(ctx) < 0)
			return -1;
		/* i_stream_read() may have returned 0 at EOF
		   because of this parser */
		index_mail_cache_parse_continue(ctx->ctx.dest_mail);
		if (ret == 0)
			return 0;
	}

	i_assert(ctx->last_char == '\n');
	return 0;
}

static int mbox_save_finish_headers(struct mbox_save_context *ctx)
{
	i_assert(ctx->eoh_offset == (uoff_t)-1);

	/* append our own headers and ending empty line */
	ctx->extra_hdr_offset = ctx->output->offset;
	if (o_stream_send(ctx->output, str_data(ctx->headers),
			  str_len(ctx->headers)) < 0) {
		write_error(ctx);
		return -1;
	}
	ctx->eoh_offset = ctx->output->offset;
	return 0;
}

int mbox_save_continue(struct mail_save_context *_ctx)
{
	struct mbox_save_context *ctx = MBOX_SAVECTX(_ctx);
	const unsigned char *data;
	size_t i, size;
	ssize_t ret;

	if (ctx->failed)
		return -1;

	if (ctx->eoh_offset != (uoff_t)-1) {
		/* writing body */
		return mbox_save_body(ctx);
	}

	while ((ret = i_stream_read_more(ctx->input, &data, &size)) > 0) {
		for (i = 0; i < size; i++) {
			if (data[i] == '\n' &&
			    ((i == 0 && ctx->last_char == '\n') ||
			     (i > 0 && data[i-1] == '\n'))) {
				/* end of headers. we don't need to worry about
				   CRs because they're dropped */
				break;
			}
		}
		if (i != size) {
			/* found end of headers. write the rest of them
			   (not including the finishing empty line) */
			if (o_stream_send(ctx->output, data, i) < 0) {
				write_error(ctx);
				return -1;
			}
			ctx->last_char = '\n';
			i_stream_skip(ctx->input, i + 1);
			break;
		}

		if (o_stream_send(ctx->output, data, size) < 0) {
			write_error(ctx);
			return -1;
		}
		i_assert(size > 0);
		ctx->last_char = data[size-1];
		i_stream_skip(ctx->input, size);
		index_mail_cache_parse_continue(ctx->ctx.dest_mail);
	}
	if (ret == 0)
		return 0;
	if (ctx->input->stream_errno != 0) {
		i_error("read(%s) failed: %s", i_stream_get_name(ctx->input),
			i_stream_get_error(ctx->input));
		ctx->failed = TRUE;
		return -1;
	}

	i_assert(ctx->last_char == '\n');

	if (ctx->mbox_md5_ctx != NULL) {
		unsigned char hdr_md5_sum[16];

		if (ctx->x_delivery_id_header != NULL) {
			struct message_header_line hdr;

			i_zero(&hdr);
			hdr.name = ctx->x_delivery_id_header;
			hdr.name_len = sizeof("X-Delivery-ID")-1;
			hdr.middle = (const unsigned char *)hdr.name +
				hdr.name_len;
			hdr.middle_len = 2;
			hdr.value = hdr.full_value =
				hdr.middle + hdr.middle_len;
			hdr.value_len = strlen((const char *)hdr.value);
			ctx->mbox->md5_v.more(ctx->mbox_md5_ctx, &hdr);
		}
		ctx->mbox->md5_v.finish(ctx->mbox_md5_ctx, hdr_md5_sum);
		mail_index_update_ext(ctx->trans, ctx->seq,
				      ctx->mbox->md5hdr_ext_idx,
				      hdr_md5_sum, NULL);
	}

	if (mbox_save_finish_headers(ctx) < 0)
		return -1;

	/* write body */
	if (mbox_save_body_input(ctx) < 0)
		return -1;
	return ctx->input->eof ? 0 : mbox_save_body(ctx);
}

int mbox_save_finish(struct mail_save_context *_ctx)
{
	struct mbox_save_context *ctx = MBOX_SAVECTX(_ctx);

	if (!ctx->failed && ctx->eoh_offset == (uoff_t)-1)
		(void)mbox_save_finish_headers(ctx);

	if (ctx->output != NULL) {
		/* make sure everything is written */
		if (o_stream_flush(ctx->output) < 0)
			write_error(ctx);
	}

	ctx->finished = TRUE;
	if (!ctx->failed) {
		i_assert(ctx->output != NULL);
		T_BEGIN {
			if (mbox_write_content_length(ctx) < 0 ||
			    mbox_append_lf(ctx) < 0)
				ctx->failed = TRUE;
		} T_END;
	}

	index_mail_cache_parse_deinit(ctx->ctx.dest_mail,
				      ctx->ctx.data.received_date,
				      !ctx->failed);
	if (ctx->input != NULL)
		i_stream_destroy(&ctx->input);

	if (ctx->failed && ctx->mail_offset != (uoff_t)-1) {
		/* saving this mail failed - truncate back to beginning of it */
		i_assert(ctx->output != NULL);
		(void)o_stream_flush(ctx->output);
		if (ftruncate(ctx->mbox->mbox_fd, (off_t)ctx->mail_offset) < 0)
			mbox_set_syscall_error(ctx->mbox, "ftruncate()");
		(void)o_stream_seek(ctx->output, ctx->mail_offset);
		ctx->mail_offset = (uoff_t)-1;
	}

	if (ctx->seq != 0 && ctx->failed) {
		index_storage_save_abort_last(&ctx->ctx, ctx->seq);
	}
	index_save_context_free(_ctx);
	return ctx->failed ? -1 : 0;
}

void mbox_save_cancel(struct mail_save_context *_ctx)
{
	struct mbox_save_context *ctx = MBOX_SAVECTX(_ctx);

	ctx->failed = TRUE;
	(void)mbox_save_finish(_ctx);
}

static void mbox_transaction_save_deinit(struct mbox_save_context *ctx)
{
	o_stream_destroy(&ctx->output);
	str_free(&ctx->headers);
}

static void mbox_save_truncate(struct mbox_save_context *ctx)
{
	if (ctx->append_offset == (uoff_t)-1 || ctx->mbox->mbox_fd == -1)
		return;

	i_assert(ctx->mbox->mbox_lock_type == F_WRLCK);

	/* failed, truncate file back to original size. output stream needs to
	   be flushed before truncating so unref() won't write anything. */
	if (ctx->output != NULL)
		(void)o_stream_flush(ctx->output);

	if (ftruncate(ctx->mbox->mbox_fd, (off_t)ctx->append_offset) < 0)
		mbox_set_syscall_error(ctx->mbox, "ftruncate()");
}

int mbox_transaction_save_commit_pre(struct mail_save_context *_ctx)
{
	struct mbox_save_context *ctx = MBOX_SAVECTX(_ctx);
	struct mailbox_transaction_context *_t = _ctx->transaction;
	struct mbox_mailbox *mbox = ctx->mbox;
	struct stat st;
	int ret = 0;

	i_assert(ctx->finished);
	i_assert(mbox->mbox_fd != -1);

	if (fstat(mbox->mbox_fd, &st) < 0) {
		mbox_set_syscall_error(mbox, "fstat()");
		ret = -1;
	}

	if (ctx->synced) {
		_t->changes->uid_validity = ctx->uid_validity;
		mail_index_append_finish_uids(ctx->trans, 0,
					      &_t->changes->saved_uids);

		mail_index_update_header(ctx->trans,
			offsetof(struct mail_index_header, next_uid),
			&ctx->next_uid, sizeof(ctx->next_uid), FALSE);

		if (ret == 0) {
			mbox->mbox_hdr.sync_mtime = st.st_mtime;
			mbox->mbox_hdr.sync_size = st.st_size;
			mail_index_update_header_ext(ctx->trans,
						     mbox->mbox_ext_idx,
						     0, &mbox->mbox_hdr,
						     sizeof(mbox->mbox_hdr));
		}
	}

	if (ret == 0 && ctx->orig_atime != st.st_atime) {
		/* try to set atime back to its original value.
		   (it'll fail with EPERM for shared mailboxes where we aren't
		   the file's owner) */
		struct utimbuf buf;

		buf.modtime = st.st_mtime;
		buf.actime = ctx->orig_atime;
		if (utime(mailbox_get_path(&mbox->box), &buf) < 0 &&
		    errno != EPERM)
			mbox_set_syscall_error(mbox, "utime()");
	}

	if (ctx->output != NULL) {
		/* flush the final LF */
		if (o_stream_flush(ctx->output) < 0)
			write_error(ctx);
	}
	if (mbox->mbox_fd != -1 && !mbox->mbox_writeonly &&
	    mbox->storage->storage.set->parsed_fsync_mode != FSYNC_MODE_NEVER) {
		if (fdatasync(mbox->mbox_fd) < 0) {
			mbox_set_syscall_error(mbox, "fdatasync()");
			mbox_save_truncate(ctx);
			ret = -1;
		}
	}

	mbox_transaction_save_deinit(ctx);
	if (ret < 0)
		i_free(ctx);
	return ret;
}

void mbox_transaction_save_commit_post(struct mail_save_context *_ctx,
				       struct mail_index_transaction_commit_result *result ATTR_UNUSED)
{
	struct mbox_save_context *ctx = MBOX_SAVECTX(_ctx);

	i_assert(ctx->mbox->mbox_lock_type == F_WRLCK);

	if (ctx->synced) {
		/* after saving mails with UIDs we need to update
		   the last-uid */
		(void)mbox_sync(ctx->mbox, MBOX_SYNC_HEADER |
				MBOX_SYNC_REWRITE);
	}
	i_free(ctx);
}

void mbox_transaction_save_rollback(struct mail_save_context *_ctx)
{
	struct mbox_save_context *ctx = MBOX_SAVECTX(_ctx);

	if (!ctx->finished)
		mbox_save_cancel(&ctx->ctx);

	mbox_save_truncate(ctx);
	mbox_transaction_save_deinit(ctx);
	i_free(ctx);
}
