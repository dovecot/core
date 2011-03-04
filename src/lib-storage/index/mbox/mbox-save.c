/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

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
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <utime.h>

#define MBOX_DELIVERY_ID_RAND_BYTES (64/8)

struct mbox_save_context {
	struct mail_save_context ctx;

	struct mbox_mailbox *mbox;
	struct mail_index_transaction *trans;
	struct mail *mail;
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

	unsigned int synced:1;
	unsigned int failed:1;
	unsigned int finished:1;
};

static int write_error(struct mbox_save_context *ctx)
{
	mbox_set_syscall_error(ctx->mbox, "write()");
	ctx->failed = TRUE;
	return -1;
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
	if (fstat(fd, &st) < 0)
                return mbox_set_syscall_error(ctx->mbox, "fstat()");

	ctx->orig_atime = st.st_atime;

	*offset = (uoff_t)st.st_size;
	if (st.st_size == 0)
		return 0;

	if (lseek(fd, st.st_size-1, SEEK_SET) < 0)
                return mbox_set_syscall_error(ctx->mbox, "lseek()");

	if (read(fd, &ch, 1) != 1)
		return mbox_set_syscall_error(ctx->mbox, "read()");

	if (ch != '\n') {
		if (write_full(fd, "\n", 1) < 0)
			return write_error(ctx);
		*offset += 1;
	}

	return 0;
}

static int mbox_append_lf(struct mbox_save_context *ctx)
{
	if (o_stream_send(ctx->output, "\n", 1) < 0)
		return write_error(ctx);

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
	if (o_stream_flush(ctx->output) < 0)
		return write_error(ctx);
	if (o_stream_seek(ctx->output, ctx->extra_hdr_offset +
			  ctx->space_end_idx - len) < 0)
		return mbox_set_syscall_error(ctx->mbox, "o_stream_seek()");

	if (o_stream_send(ctx->output, str, len) < 0 ||
	    o_stream_flush(ctx->output) < 0)
		return write_error(ctx);

	if (o_stream_seek(ctx->output, end_offset) < 0)
		return mbox_set_syscall_error(ctx->mbox, "o_stream_seek()");
	return 0;
}

static void mbox_save_init_sync(struct mailbox_transaction_context *t)
{
	struct mbox_mailbox *mbox = (struct mbox_mailbox *)t->box;
	struct mbox_save_context *ctx = (struct mbox_save_context *)t->save_ctx;
	const struct mail_index_header *hdr;
	struct mail_index_view *view;

	/* open a new view to get the header. this is required if we just
	   synced the mailbox so we can get updated next_uid. */
	(void)mail_index_refresh(mbox->box.index);
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
	str_append_n(ctx->headers, space, sizeof(space));
	ctx->space_end_idx = str_len(ctx->headers);
	str_append_c(ctx->headers, '\n');
}

static int
mbox_save_init_file(struct mbox_save_context *ctx,
		    struct mbox_transaction_context *t, bool want_mail)
{
	struct mailbox_transaction_context *_t = &t->ictx.mailbox_ctx;
	struct mbox_mailbox *mbox = ctx->mbox;
	struct mail_storage *storage = &mbox->storage->storage;
	bool empty = FALSE;
	int ret;

	if (ctx->mbox->box.backend_readonly) {
		mail_storage_set_error(storage, MAIL_ERROR_PERM,
				       "Read-only mbox");
		return -1;
	}

	if ((_t->flags & MAILBOX_TRANSACTION_FLAG_ASSIGN_UIDS) != 0 ||
	    ctx->ctx.uid != 0)
		want_mail = TRUE;

	if (ctx->append_offset == (uoff_t)-1) {
		/* first appended mail in this transaction */
		if (mbox->mbox_lock_type != F_WRLCK) {
			if (mbox->mbox_lock_type == F_RDLCK) {
				/* FIXME: we shouldn't fail here. it's just
				   a locking issue that should be possible to
				   fix.. */
				mail_storage_set_error(storage,
					MAIL_ERROR_NOTPOSSIBLE,
					"Can't copy mails inside same mailbox");
				return -1;
			}
			if (mbox_lock(mbox, F_WRLCK, &t->mbox_lock_id) <= 0)
				return -1;
		}

		if (mbox->mbox_fd == -1) {
			if (mbox_file_open(mbox) < 0)
				return -1;
		}

		/* update mbox_sync_dirty state */
		ret = mbox_sync_has_changed_full(mbox, TRUE, &empty);
		if (ret < 0)
			return -1;
		if (!want_mail && ret == 0) {
			/* we're not required to assign UIDs for the appended
			   mails immediately. do it only if it doesn't require
			   syncing. */
			mbox_save_init_sync(_t);
		}
	}

	if (!ctx->synced && (want_mail || empty)) {
		/* we'll need to assign UID for the mail immediately. */
		if (mbox_sync(mbox, 0) < 0)
			return -1;
		mbox_save_init_sync(_t);
	}

	/* the syncing above could have changed the append offset */
	if (ctx->append_offset == (uoff_t)-1) {
		if (mbox_seek_to_end(ctx, &ctx->append_offset) < 0)
			return -1;

		ctx->output = o_stream_create_fd_file(mbox->mbox_fd,
						      ctx->append_offset,
						      FALSE);
		o_stream_cork(ctx->output);
	}
	return 0;
}

static void save_header_callback(struct message_header_line *hdr,
				 bool *matched, struct mbox_save_context *ctx)
{
	if (hdr != NULL) {
		if (strncmp(hdr->name, "From ", 5) == 0) {
			/* we can't allow From_-lines in headers. there's no
			   legitimate reason for allowing them in any case,
			   so just drop them. */
			*matched = TRUE;
			return;
		}

		if (!*matched && ctx->mbox_md5_ctx != NULL)
			mbox_md5_continue(ctx->mbox_md5_ctx, hdr);
	}
}

static void mbox_save_x_delivery_id(struct mbox_save_context *ctx)
{
	unsigned char md5_result[MD5_RESULTLEN];
	buffer_t *buf;
	string_t *str;
	void *randbuf;

	buf = buffer_create_dynamic(pool_datastack_create(), 256);
	buffer_append(buf, &ioloop_time, sizeof(ioloop_time));
	buffer_append(buf, &ioloop_timeval.tv_usec,
		      sizeof(ioloop_timeval.tv_usec));

	randbuf = buffer_append_space_unsafe(buf, MBOX_DELIVERY_ID_RAND_BYTES);
	random_fill_weak(randbuf, MBOX_DELIVERY_ID_RAND_BYTES);

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

	if (ctx->ctx.dest_mail != NULL) {
		/* caching creates a tee stream */
		cache_input =
			index_mail_cache_parse_init(ctx->ctx.dest_mail, ret);
		i_stream_unref(&ret);
		ret = cache_input;
	}
	return ret;
}

struct mail_save_context *
mbox_save_alloc(struct mailbox_transaction_context *t)
{
	struct mbox_mailbox *mbox = (struct mbox_mailbox *)t->box;
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
	struct mbox_save_context *ctx = (struct mbox_save_context *)_ctx;
	struct mbox_transaction_context *t =
		(struct mbox_transaction_context *)_ctx->transaction;
	enum mail_flags save_flags;
	uint64_t offset;

	/* FIXME: we could write timezone_offset to From-line.. */
	if (_ctx->received_date == (time_t)-1)
		_ctx->received_date = ioloop_time;

	ctx->failed = FALSE;
	ctx->seq = 0;

	if (mbox_save_init_file(ctx, t, _ctx->dest_mail != NULL) < 0) {
		ctx->failed = TRUE;
		return -1;
	}

	save_flags = _ctx->flags;
	if (_ctx->uid == 0)
		save_flags |= MAIL_RECENT;
	str_truncate(ctx->headers, 0);
	if (ctx->synced) {
		if (ctx->mbox->mbox_save_md5)
			ctx->mbox_md5_ctx = mbox_md5_init();
		if (ctx->next_uid < _ctx->uid) {
			/* we can use the wanted UID */
			ctx->next_uid = _ctx->uid;
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
		if (_ctx->keywords != NULL) {
			mail_index_update_keywords(ctx->trans, ctx->seq,
						   MODIFY_REPLACE,
						   _ctx->keywords);
		}
		if (_ctx->min_modseq != 0) {
			mail_index_update_modseq(ctx->trans, ctx->seq,
						 _ctx->min_modseq);
		}

		offset = ctx->output->offset == 0 ? 0 :
			ctx->output->offset - 1;
		mail_index_update_ext(ctx->trans, ctx->seq,
				      ctx->mbox->mbox_ext_idx, &offset, NULL);
		ctx->next_uid++;

		/* parse and cache the mail headers as we read it */
		if (_ctx->dest_mail == NULL) {
			if (ctx->mail == NULL) {
				ctx->mail = mail_alloc(_ctx->transaction,
						       0, NULL);
			}
			_ctx->dest_mail = ctx->mail;
		}
		mail_set_seq(_ctx->dest_mail, ctx->seq);
		_ctx->dest_mail->saving = TRUE;
	}
	mbox_save_append_flag_headers(ctx->headers, save_flags);
	mbox_save_append_keyword_headers(ctx, _ctx->keywords);
	str_append_c(ctx->headers, '\n');

	i_assert(ctx->mbox->mbox_lock_type == F_WRLCK);

	ctx->mail_offset = ctx->output->offset;
	ctx->eoh_offset = (uoff_t)-1;
	ctx->last_char = '\n';

	if (write_from_line(ctx, _ctx->received_date, _ctx->from_envelope) < 0)
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
		if (o_stream_send(ctx->output, data, size) < 0)
			return write_error(ctx);
		ctx->last_char = data[size-1];
		i_stream_skip(ctx->input, size);
	}
	return 0;
}

static int mbox_save_body(struct mbox_save_context *ctx)
{
	ssize_t ret;

	while ((ret = i_stream_read(ctx->input)) != -1) {
		if (ctx->ctx.dest_mail != NULL) {
			/* i_stream_read() may have returned 0 at EOF
			   because of this parser */
			index_mail_cache_parse_continue(ctx->ctx.dest_mail);
		}
		if (ret == 0)
			return 0;

		if (mbox_save_body_input(ctx) < 0)
			return -1;
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
			  str_len(ctx->headers)) < 0)
		return write_error(ctx);
	ctx->eoh_offset = ctx->output->offset;
	return 0;
}

int mbox_save_continue(struct mail_save_context *_ctx)
{
	struct mbox_save_context *ctx = (struct mbox_save_context *)_ctx;
	const unsigned char *data;
	size_t i, size;
	ssize_t ret;

	if (ctx->failed)
		return -1;

	if (ctx->eoh_offset != (uoff_t)-1) {
		/* writing body */
		return mbox_save_body(ctx);
	}

	while ((ret = i_stream_read(ctx->input)) > 0) {
		if (ctx->ctx.dest_mail != NULL)
			index_mail_cache_parse_continue(ctx->ctx.dest_mail);

		data = i_stream_get_data(ctx->input, &size);
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
			if (o_stream_send(ctx->output, data, i) < 0)
				return write_error(ctx);
			ctx->last_char = '\n';
			i_stream_skip(ctx->input, i + 1);
			break;
		}

		if (o_stream_send(ctx->output, data, size) < 0)
			return write_error(ctx);
		ctx->last_char = data[size-1];
		i_stream_skip(ctx->input, size);
	}
	if (ret == 0)
		return 0;

	i_assert(ctx->last_char == '\n');

	if (ctx->mbox_md5_ctx) {
		unsigned char hdr_md5_sum[16];

		if (ctx->x_delivery_id_header != NULL) {
			struct message_header_line hdr;

			memset(&hdr, 0, sizeof(hdr));
			hdr.name = ctx->x_delivery_id_header;
			hdr.name_len = sizeof("X-Delivery-ID")-1;
			hdr.middle = (const unsigned char *)hdr.name +
				hdr.name_len;
			hdr.middle_len = 2;
			hdr.value = hdr.full_value =
				hdr.middle + hdr.middle_len;
			hdr.value_len = strlen((const char *)hdr.value);
			mbox_md5_continue(ctx->mbox_md5_ctx, &hdr);
		}
		mbox_md5_finish(ctx->mbox_md5_ctx, hdr_md5_sum);
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
	struct mbox_save_context *ctx = (struct mbox_save_context *)_ctx;

	if (!ctx->failed && ctx->eoh_offset == (uoff_t)-1)
		(void)mbox_save_finish_headers(ctx);

	if (ctx->output != NULL) {
		/* make sure everything is written */
		if (o_stream_flush(ctx->output) < 0)
			write_error(ctx);
	}

	ctx->finished = TRUE;
	if (!ctx->failed) {
		T_BEGIN {
			if (mbox_write_content_length(ctx) < 0 ||
			    mbox_append_lf(ctx) < 0)
				ctx->failed = TRUE;
		} T_END;
	}

	if (ctx->ctx.dest_mail != NULL) {
		index_mail_cache_parse_deinit(ctx->ctx.dest_mail,
					      ctx->ctx.received_date,
					      !ctx->failed);
	}
	if (ctx->input != NULL)
		i_stream_destroy(&ctx->input);

	if (ctx->failed && ctx->mail_offset != (uoff_t)-1) {
		/* saving this mail failed - truncate back to beginning of it */
		(void)o_stream_flush(ctx->output);
		if (ftruncate(ctx->mbox->mbox_fd, (off_t)ctx->mail_offset) < 0)
			mbox_set_syscall_error(ctx->mbox, "ftruncate()");
		o_stream_seek(ctx->output, ctx->mail_offset);
		ctx->mail_offset = (uoff_t)-1;
	}

	index_save_context_free(_ctx);
	return ctx->failed ? -1 : 0;
}

void mbox_save_cancel(struct mail_save_context *_ctx)
{
	struct mbox_save_context *ctx = (struct mbox_save_context *)_ctx;

	ctx->failed = TRUE;
	(void)mbox_save_finish(_ctx);
}

static void mbox_transaction_save_deinit(struct mbox_save_context *ctx)
{
	if (ctx->output != NULL)
		o_stream_destroy(&ctx->output);
	if (ctx->mail != NULL)
		mail_free(&ctx->mail);
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
		o_stream_flush(ctx->output);

	if (ftruncate(ctx->mbox->mbox_fd, (off_t)ctx->append_offset) < 0)
		mbox_set_syscall_error(ctx->mbox, "ftruncate()");
}

int mbox_transaction_save_commit_pre(struct mail_save_context *_ctx)
{
	struct mbox_save_context *ctx = (struct mbox_save_context *)_ctx;
	struct mailbox_transaction_context *_t = _ctx->transaction;
	struct mbox_mailbox *mbox = ctx->mbox;
	struct stat st;
	int ret = 0;

	i_assert(ctx->finished);

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
		if (utime(mbox->box.path, &buf) < 0 && errno != EPERM)
			mbox_set_syscall_error(mbox, "utime()");
	}

	if (ctx->output != NULL) {
		/* flush the final LF */
		o_stream_flush(ctx->output);
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
	struct mbox_save_context *ctx = (struct mbox_save_context *)_ctx;

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
	struct mbox_save_context *ctx = (struct mbox_save_context *)_ctx;

	if (!ctx->finished)
		mbox_save_cancel(&ctx->ctx);

	mbox_save_truncate(ctx);
	mbox_transaction_save_deinit(ctx);
	i_free(ctx);
}
