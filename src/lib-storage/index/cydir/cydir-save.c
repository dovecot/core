/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hostpid.h"
#include "istream.h"
#include "istream-crlf.h"
#include "ostream.h"
#include "str.h"
#include "index-mail.h"
#include "cydir-storage.h"
#include "cydir-sync.h"

#include <stdio.h>
#include <utime.h>

struct cydir_save_context {
	struct mail_save_context ctx;

	struct cydir_mailbox *mbox;
	struct mail_index_transaction *trans;

	char *tmp_basename;
	unsigned int mail_count;

	struct cydir_sync_context *sync_ctx;

	/* updated for each appended mail: */
	uint32_t seq;
	struct istream *input;
	struct mail *mail;
	int fd;

	unsigned int failed:1;
	unsigned int finished:1;
};

static char *cydir_generate_tmp_filename(void)
{
	static unsigned int create_count = 0;

	return i_strdup_printf("temp.%s.P%sQ%uM%s.%s",
			       dec2str(ioloop_timeval.tv_sec), my_pid,
			       create_count++,
			       dec2str(ioloop_timeval.tv_usec), my_hostname);
}

static const char *
cydir_get_save_path(struct cydir_save_context *ctx, unsigned int num)
{
	const char *dir;

	dir = mailbox_list_get_path(ctx->mbox->box.list, ctx->mbox->box.name,
				    MAILBOX_LIST_PATH_TYPE_MAILBOX);
	return t_strdup_printf("%s/%s.%u", dir, ctx->tmp_basename, num);
}

struct mail_save_context *
cydir_save_alloc(struct mailbox_transaction_context *t)
{
	struct cydir_mailbox *mbox = (struct cydir_mailbox *)t->box;
	struct cydir_save_context *ctx;

	i_assert((t->flags & MAILBOX_TRANSACTION_FLAG_EXTERNAL) != 0);

	if (t->save_ctx == NULL) {
		ctx = i_new(struct cydir_save_context, 1);
		ctx->ctx.transaction = t;
		ctx->mbox = mbox;
		ctx->trans = t->itrans;
		ctx->tmp_basename = cydir_generate_tmp_filename();
		ctx->fd = -1;
		t->save_ctx = &ctx->ctx;
	}
	return t->save_ctx;
}

int cydir_save_begin(struct mail_save_context *_ctx, struct istream *input)
{
	struct cydir_save_context *ctx = (struct cydir_save_context *)_ctx;
	struct mailbox_transaction_context *trans = _ctx->transaction;
	enum mail_flags save_flags;
	struct istream *crlf_input;

	ctx->failed = FALSE;

	T_BEGIN {
		const char *path;

		path = cydir_get_save_path(ctx, ctx->mail_count);
		ctx->fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0660);
		if (ctx->fd != -1) {
			_ctx->output =
				o_stream_create_fd_file(ctx->fd, 0, FALSE);
			o_stream_cork(_ctx->output);
		} else {
			mail_storage_set_critical(trans->box->storage,
						  "open(%s) failed: %m", path);
			ctx->failed = TRUE;
		}
	} T_END;
	if (ctx->failed)
		return -1;

	/* add to index */
	save_flags = _ctx->flags & ~MAIL_RECENT;
	mail_index_append(ctx->trans, 0, &ctx->seq);
	mail_index_update_flags(ctx->trans, ctx->seq, MODIFY_REPLACE,
				save_flags);
	if (_ctx->keywords != NULL) {
		mail_index_update_keywords(ctx->trans, ctx->seq,
					   MODIFY_REPLACE, _ctx->keywords);
	}
	if (_ctx->min_modseq != 0) {
		mail_index_update_modseq(ctx->trans, ctx->seq,
					 _ctx->min_modseq);
	}

	if (_ctx->dest_mail == NULL) {
		if (ctx->mail == NULL)
			ctx->mail = mail_alloc(trans, 0, NULL);
		_ctx->dest_mail = ctx->mail;
	}
	mail_set_seq(_ctx->dest_mail, ctx->seq);
	_ctx->dest_mail->saving = TRUE;

	crlf_input = i_stream_create_crlf(input);
	ctx->input = index_mail_cache_parse_init(_ctx->dest_mail, crlf_input);
	i_stream_unref(&crlf_input);
	return ctx->failed ? -1 : 0;
}

int cydir_save_continue(struct mail_save_context *_ctx)
{
	struct cydir_save_context *ctx = (struct cydir_save_context *)_ctx;
	struct mail_storage *storage = &ctx->mbox->storage->storage;

	if (ctx->failed)
		return -1;

	do {
		if (o_stream_send_istream(_ctx->output, ctx->input) < 0) {
			if (!mail_storage_set_error_from_errno(storage)) {
				mail_storage_set_critical(storage,
					"o_stream_send_istream(%s) failed: %m",
					cydir_get_save_path(ctx, ctx->mail_count));
			}
			ctx->failed = TRUE;
			return -1;
		}
		index_mail_cache_parse_continue(_ctx->dest_mail);

		/* both tee input readers may consume data from our primary
		   input stream. we'll have to make sure we don't return with
		   one of the streams still having data in them. */
	} while (i_stream_read(ctx->input) > 0);
	return 0;
}

static int cydir_save_flush(struct cydir_save_context *ctx, const char *path)
{
	struct mail_storage *storage = &ctx->mbox->storage->storage;
	struct stat st;
	int ret = 0;

	if (o_stream_flush(ctx->ctx.output) < 0) {
		mail_storage_set_critical(storage,
			"o_stream_flush(%s) failed: %m", path);
		ret = -1;
	}

	if (storage->set->parsed_fsync_mode != FSYNC_MODE_NEVER) {
		if (fsync(ctx->fd) < 0) {
			mail_storage_set_critical(storage,
						  "fsync(%s) failed: %m", path);
			ret = -1;
		}
	}

	if (ctx->ctx.received_date == (time_t)-1) {
		if (fstat(ctx->fd, &st) == 0)
			ctx->ctx.received_date = st.st_mtime;
		else {
			mail_storage_set_critical(storage,
						  "fstat(%s) failed: %m", path);
			ret = -1;
		}
	} else {
		struct utimbuf ut;

		ut.actime = ioloop_time;
		ut.modtime = ctx->ctx.received_date;
		if (utime(path, &ut) < 0) {
			mail_storage_set_critical(storage,
						  "utime(%s) failed: %m", path);
			ret = -1;
		}
	}

	o_stream_destroy(&ctx->ctx.output);
	if (close(ctx->fd) < 0) {
		mail_storage_set_critical(storage,
					  "close(%s) failed: %m", path);
		ret = -1;
	}
	ctx->fd = -1;
	return ret;
}

int cydir_save_finish(struct mail_save_context *_ctx)
{
	struct cydir_save_context *ctx = (struct cydir_save_context *)_ctx;
	const char *path = cydir_get_save_path(ctx, ctx->mail_count);

	ctx->finished = TRUE;

	if (ctx->fd != -1) {
		if (cydir_save_flush(ctx, path) < 0)
			ctx->failed = TRUE;
	}

	if (!ctx->failed)
		ctx->mail_count++;
	else {
		if (unlink(path) < 0) {
			mail_storage_set_critical(&ctx->mbox->storage->storage,
				"unlink(%s) failed: %m", path);
		}
	}

	index_mail_cache_parse_deinit(_ctx->dest_mail,
				      _ctx->received_date, !ctx->failed);
	if (ctx->input != NULL)
		i_stream_unref(&ctx->input);

	index_save_context_free(_ctx);
	return ctx->failed ? -1 : 0;
}

void cydir_save_cancel(struct mail_save_context *_ctx)
{
	struct cydir_save_context *ctx = (struct cydir_save_context *)_ctx;

	ctx->failed = TRUE;
	(void)cydir_save_finish(_ctx);
}

int cydir_transaction_save_commit_pre(struct mail_save_context *_ctx)
{
	struct cydir_save_context *ctx = (struct cydir_save_context *)_ctx;
	struct mailbox_transaction_context *_t = _ctx->transaction;
	const struct mail_index_header *hdr;
	struct seq_range_iter iter;
	uint32_t uid;
	const char *dir;
	string_t *src_path, *dest_path;
	unsigned int n, src_prefixlen, dest_prefixlen;

	i_assert(ctx->finished);

	if (cydir_sync_begin(ctx->mbox, &ctx->sync_ctx, TRUE) < 0) {
		ctx->failed = TRUE;
		cydir_transaction_save_rollback(_ctx);
		return -1;
	}

	hdr = mail_index_get_header(ctx->sync_ctx->sync_view);
	mail_index_append_finish_uids(ctx->trans, hdr->next_uid,
				      &_t->changes->saved_uids);
	_t->changes->uid_validity = ctx->sync_ctx->uid_validity;

	dir = mailbox_list_get_path(ctx->mbox->box.list, ctx->mbox->box.name,
				    MAILBOX_LIST_PATH_TYPE_MAILBOX);

	src_path = t_str_new(256);
	str_printfa(src_path, "%s/%s.", dir, ctx->tmp_basename);
	src_prefixlen = str_len(src_path);

	dest_path = t_str_new(256);
	str_append(dest_path, dir);
	str_append_c(dest_path, '/');
	dest_prefixlen = str_len(dest_path);

	seq_range_array_iter_init(&iter, &_t->changes->saved_uids); n = 0;
	while (seq_range_array_iter_nth(&iter, n++, &uid) > 0) {
		str_truncate(src_path, src_prefixlen);
		str_truncate(dest_path, dest_prefixlen);
		str_printfa(src_path, "%u", n-1);
		str_printfa(dest_path, "%u.", uid);

		if (rename(str_c(src_path), str_c(dest_path)) < 0) {
			mail_storage_set_critical(&ctx->mbox->storage->storage,
				"rename(%s, %s) failed: %m",
				str_c(src_path), str_c(dest_path));
			ctx->failed = TRUE;
			cydir_transaction_save_rollback(_ctx);
			return -1;
		}
	}

	if (ctx->mail != NULL)
		mail_free(&ctx->mail);
	return 0;
}

void cydir_transaction_save_commit_post(struct mail_save_context *_ctx,
					struct mail_index_transaction_commit_result *result)
{
	struct cydir_save_context *ctx = (struct cydir_save_context *)_ctx;

	_ctx->transaction = NULL; /* transaction is already freed */

	mail_index_sync_set_commit_result(ctx->sync_ctx->index_sync_ctx,
					  result);

	(void)cydir_sync_finish(&ctx->sync_ctx, TRUE);
	cydir_transaction_save_rollback(_ctx);
}

void cydir_transaction_save_rollback(struct mail_save_context *_ctx)
{
	struct cydir_save_context *ctx = (struct cydir_save_context *)_ctx;

	if (!ctx->finished)
		cydir_save_cancel(&ctx->ctx);

	if (ctx->sync_ctx != NULL)
		(void)cydir_sync_finish(&ctx->sync_ctx, FALSE);

	if (ctx->mail != NULL)
		mail_free(&ctx->mail);
	i_free(ctx->tmp_basename);
	i_free(ctx);
}
