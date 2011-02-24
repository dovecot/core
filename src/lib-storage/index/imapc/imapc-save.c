/* Copyright (c) 2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "istream-crlf.h"
#include "ostream.h"
#include "imap-date.h"
#include "imap-util.h"
#include "index-mail.h"
#include "mail-copy.h"
#include "imapc-client.h"
#include "imapc-storage.h"
#include "imapc-sync.h"

struct imapc_save_context {
	struct mail_save_context ctx;

	struct imapc_mailbox *mbox;
	struct mail_index_transaction *trans;

	int fd;
	char *temp_path;
	struct istream *input;

	uint32_t dest_uid_validity;
	ARRAY_TYPE(seq_range) dest_saved_uids;

	unsigned int failed:1;
	unsigned int finished:1;
};

struct imapc_save_cmd_context {
	struct imapc_save_context *ctx;
	int ret;
};

void imapc_transaction_save_rollback(struct mail_save_context *_ctx);

struct mail_save_context *
imapc_save_alloc(struct mailbox_transaction_context *t)
{
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)t->box;
	struct imapc_save_context *ctx;

	i_assert((t->flags & MAILBOX_TRANSACTION_FLAG_EXTERNAL) != 0);

	if (t->save_ctx == NULL) {
		ctx = i_new(struct imapc_save_context, 1);
		ctx->ctx.transaction = t;
		ctx->mbox = mbox;
		ctx->trans = t->itrans;
		ctx->fd = -1;
		t->save_ctx = &ctx->ctx;
	}
	return t->save_ctx;
}

int imapc_save_begin(struct mail_save_context *_ctx, struct istream *input)
{
	struct imapc_save_context *ctx = (struct imapc_save_context *)_ctx;
	struct mail_storage *storage = _ctx->transaction->box->storage;
	const char *path;

	i_assert(ctx->fd == -1);

	ctx->fd = imapc_client_create_temp_fd(ctx->mbox->storage->client, &path);
	if (ctx->fd == -1) {
		mail_storage_set_critical(storage,
					  "Couldn't create temp file %s", path);
		ctx->failed = TRUE;
		return -1;
	}
	/* we may not know the size of the input, or be sure that it contains
	   only CRLFs. so we'll always first write the mail to a temp file and
	   upload it from there to remote server. */
	ctx->finished = FALSE;
	ctx->temp_path = i_strdup(path);
	ctx->input = i_stream_create_crlf(input);
	_ctx->output = o_stream_create_fd_file(ctx->fd, 0, FALSE);
	o_stream_cork(_ctx->output);
	return 0;
}

int imapc_save_continue(struct mail_save_context *_ctx)
{
	struct imapc_save_context *ctx = (struct imapc_save_context *)_ctx;
	struct mail_storage *storage = _ctx->transaction->box->storage;

	if (ctx->failed)
		return -1;

	if (o_stream_send_istream(_ctx->output, ctx->input) < 0) {
		if (!mail_storage_set_error_from_errno(storage)) {
			mail_storage_set_critical(storage,
				"o_stream_send_istream(%s) failed: %m",
				ctx->temp_path);
		}
		ctx->failed = TRUE;
		return -1;
	}
	return 0;
}

static void imapc_save_appenduid(struct imapc_save_context *ctx,
				 const struct imapc_command_reply *reply)
{
	const char *const *args;
	uint32_t uid_validity, dest_uid;

	/* <uidvalidity> <dest uid-set> */
	args = t_strsplit(reply->resp_text_value, " ");
	if (str_array_length(args) != 2)
		return;

	if (str_to_uint32(args[0], &uid_validity) < 0)
		return;
	if (ctx->dest_uid_validity == 0)
		ctx->dest_uid_validity = uid_validity;
	else if (ctx->dest_uid_validity != uid_validity)
		return;

	if (str_to_uint32(args[1], &dest_uid) == 0)
		seq_range_array_add(&ctx->dest_saved_uids, 0, dest_uid);
}

static void imapc_save_callback(const struct imapc_command_reply *reply,
				void *context)
{
	struct imapc_save_cmd_context *ctx = context;

	if (reply->state == IMAPC_COMMAND_STATE_OK) {
		if (strcasecmp(reply->resp_text_key, "APPENDUID") == 0)
			imapc_save_appenduid(ctx->ctx, reply);
		ctx->ret = 0;
	} else if (reply->state == IMAPC_COMMAND_STATE_NO) {
		imapc_copy_error_from_reply(ctx->ctx->mbox->storage,
					    MAIL_ERROR_PARAMS, reply);
		ctx->ret = -1;
	} else {
		mail_storage_set_critical(&ctx->ctx->mbox->storage->storage,
			"imapc: COPY failed: %s", reply->text_full);
		ctx->ret = -1;
	}
	imapc_client_stop(ctx->ctx->mbox->storage->client);
}

static void
imapc_append_keywords(string_t *str, struct mail_keywords *kw)
{
	const ARRAY_TYPE(keywords) *kw_arr;
	const char *const *kw_p;
	unsigned int i;

	kw_arr = mail_index_get_keywords(kw->index);
	for (i = 0; i < kw->count; i++) {
		kw_p = array_idx(kw_arr, kw->idx[i]);
		if (str_len(str) > 1)
			str_append_c(str, ' ');
		str_append(str, *kw_p);
	}
}

static int imapc_save_append(struct imapc_save_context *ctx)
{
	struct mail_save_context *_ctx = &ctx->ctx;
	struct imapc_save_cmd_context sctx;
	struct istream *input;
	const char *flags = "", *internaldate = "";

	if (_ctx->flags != 0 || _ctx->keywords != NULL) {
		string_t *str = t_str_new(64);

		str_append(str, " (");
		imap_write_flags(str, _ctx->flags & ~MAIL_RECENT, NULL);
		if (_ctx->keywords != NULL)
			imapc_append_keywords(str, _ctx->keywords);
		str_append_c(str, ')');
		flags = str_c(str);
	}
	if (_ctx->received_date != (time_t)-1) {
		internaldate = t_strdup_printf(" \"%s\"",
			imap_to_datetime(_ctx->received_date));
	}

	input = i_stream_create_fd(ctx->fd, IO_BLOCK_SIZE, FALSE);
	sctx.ctx = ctx;
	imapc_client_cmdf(ctx->mbox->storage->client,
			  imapc_save_callback, &sctx, "APPEND %s%1s%1s %p",
			  ctx->mbox->box.name, flags, internaldate, input);
	i_stream_unref(&input);
	imapc_client_run(ctx->mbox->storage->client);
	return sctx.ret;
}

int imapc_save_finish(struct mail_save_context *_ctx)
{
	struct imapc_save_context *ctx = (struct imapc_save_context *)_ctx;
	struct mail_storage *storage = _ctx->transaction->box->storage;

	ctx->finished = TRUE;

	if (!ctx->failed) {
		if (o_stream_flush(_ctx->output) < 0) {
			if (!mail_storage_set_error_from_errno(storage)) {
				mail_storage_set_critical(storage,
					"o_stream_flush(%s) failed: %m",
					ctx->temp_path);
			}
			ctx->failed = TRUE;
		}
	}

	if (!ctx->failed) {
		if (imapc_save_append(ctx) < 0)
			ctx->failed = TRUE;
	}

	if (_ctx->output != NULL)
		o_stream_unref(&_ctx->output);
	if (ctx->input != NULL)
		i_stream_unref(&ctx->input);
	if (ctx->fd != -1) {
		if (close(ctx->fd) < 0)
			i_error("close(%s) failed: %m", ctx->temp_path);
		ctx->fd = -1;
	}
	i_free(ctx->temp_path);
	index_save_context_free(_ctx);
	return ctx->failed ? -1 : 0;
}

void imapc_save_cancel(struct mail_save_context *_ctx)
{
	struct imapc_save_context *ctx = (struct imapc_save_context *)_ctx;

	ctx->failed = TRUE;
	(void)imapc_save_finish(_ctx);
}

int imapc_transaction_save_commit_pre(struct mail_save_context *_ctx)
{
	struct imapc_save_context *ctx = (struct imapc_save_context *)_ctx;
	struct mail_transaction_commit_changes *changes =
		_ctx->transaction->changes;

	i_assert(ctx->finished);

	if (array_is_created(&ctx->dest_saved_uids)) {
		changes->uid_validity = ctx->dest_uid_validity;
		array_append_array(&changes->saved_uids, &ctx->dest_saved_uids);
	}
	return 0;
}

void imapc_transaction_save_commit_post(struct mail_save_context *_ctx,
					struct mail_index_transaction_commit_result *result ATTR_UNUSED)
{
	imapc_transaction_save_rollback(_ctx);
}

void imapc_transaction_save_rollback(struct mail_save_context *_ctx)
{
	struct imapc_save_context *ctx = (struct imapc_save_context *)_ctx;

	/* FIXME: if we really want to rollback, we should expunge messages
	   we already saved */

	if (!ctx->finished)
		imapc_save_cancel(_ctx);

	if (array_is_created(&ctx->dest_saved_uids))
		array_free(&ctx->dest_saved_uids);
	i_free(ctx);
}

static void imapc_save_copyuid(struct imapc_save_context *ctx,
			       const struct imapc_command_reply *reply)
{
	const char *const *args;
	uint32_t uid_validity, dest_uid;

	/* <uidvalidity> <source uid-set> <dest uid-set> */
	args = t_strsplit(reply->resp_text_value, " ");
	if (str_array_length(args) != 3)
		return;

	if (str_to_uint32(args[0], &uid_validity) < 0)
		return;
	if (ctx->dest_uid_validity == 0)
		ctx->dest_uid_validity = uid_validity;
	else if (ctx->dest_uid_validity != uid_validity)
		return;

	if (str_to_uint32(args[2], &dest_uid) == 0)
		seq_range_array_add(&ctx->dest_saved_uids, 0, dest_uid);
}

static void imapc_copy_callback(const struct imapc_command_reply *reply,
				void *context)
{
	struct imapc_save_cmd_context *ctx = context;

	if (reply->state == IMAPC_COMMAND_STATE_OK) {
		if (strcasecmp(reply->resp_text_key, "COPYUID") == 0)
			imapc_save_copyuid(ctx->ctx, reply);
		ctx->ret = 0;
	} else if (reply->state == IMAPC_COMMAND_STATE_NO) {
		imapc_copy_error_from_reply(ctx->ctx->mbox->storage,
					    MAIL_ERROR_PARAMS, reply);
		ctx->ret = -1;
	} else {
		mail_storage_set_critical(&ctx->ctx->mbox->storage->storage,
			"imapc: COPY failed: %s", reply->text_full);
		ctx->ret = -1;
	}
	imapc_client_stop(ctx->ctx->mbox->storage->client);
}

int imapc_copy(struct mail_save_context *_ctx, struct mail *mail)
{
	struct imapc_save_context *ctx = (struct imapc_save_context *)_ctx;
	struct mailbox_transaction_context *_t = _ctx->transaction;
	struct imapc_mailbox *src_mbox = (struct imapc_mailbox *)mail->box;
	struct imapc_save_cmd_context sctx;

	i_assert((_t->flags & MAILBOX_TRANSACTION_FLAG_EXTERNAL) != 0);

	if (_t->box->storage == mail->box->storage) {
		/* same server, we can use COPY for the mail */
		sctx.ret = -2;
		sctx.ctx = ctx;
		imapc_client_mailbox_cmdf(src_mbox->client_box,
					  imapc_copy_callback, &sctx,
					  "UID COPY %u %s",
					  mail->uid, _t->box->name);
		imapc_client_run(src_mbox->storage->client);
		i_assert(sctx.ret != -2);
		ctx->finished = TRUE;
		return sctx.ret;
	}
	return mail_storage_copy(_ctx, mail);
}
