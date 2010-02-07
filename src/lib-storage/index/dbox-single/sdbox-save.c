/* Copyright (c) 2007-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "fdatasync-path.h"
#include "hex-binary.h"
#include "hex-dec.h"
#include "str.h"
#include "istream.h"
#include "istream-crlf.h"
#include "ostream.h"
#include "write-full.h"
#include "index-mail.h"
#include "mail-copy.h"
#include "dbox-save.h"
#include "sdbox-storage.h"
#include "sdbox-file.h"
#include "sdbox-sync.h"

#include <stdlib.h>

struct sdbox_save_context {
	struct dbox_save_context ctx;

	struct sdbox_mailbox *mbox;
	struct sdbox_sync_context *sync_ctx;
	struct dbox_file_append_context *append_ctx;

	uint32_t first_saved_seq;
	ARRAY_DEFINE(files, struct dbox_file *);
};

struct dbox_file *
sdbox_save_file_get_file(struct mailbox_transaction_context *t, uint32_t seq)
{
	struct sdbox_save_context *ctx =
		(struct sdbox_save_context *)t->save_ctx;
	struct dbox_file *const *files;
	unsigned int count;

	i_assert(seq >= ctx->first_saved_seq);

	files = array_get(&ctx->files, &count);
	i_assert(count > 0);

	return files[seq - ctx->first_saved_seq];
}

struct mail_save_context *
sdbox_save_alloc(struct mailbox_transaction_context *t)
{
	struct index_transaction_context *it =
		(struct index_transaction_context *)t;
	struct sdbox_mailbox *mbox = (struct sdbox_mailbox *)t->box;
	struct sdbox_save_context *ctx =
		(struct sdbox_save_context *)t->save_ctx;

	i_assert((t->flags & MAILBOX_TRANSACTION_FLAG_EXTERNAL) != 0);

	if (ctx != NULL) {
		/* use the existing allocated structure */
		ctx->ctx.finished = FALSE;
		return &ctx->ctx.ctx;
	}

	ctx = i_new(struct sdbox_save_context, 1);
	ctx->ctx.ctx.transaction = t;
	ctx->ctx.trans = it->trans;
	ctx->mbox = mbox;
	i_array_init(&ctx->files, 32);
	t->save_ctx = &ctx->ctx.ctx;
	return t->save_ctx;
}

int sdbox_save_begin(struct mail_save_context *_ctx, struct istream *input)
{
	struct sdbox_save_context *ctx = (struct sdbox_save_context *)_ctx;
	struct dbox_file *file;
	int ret;

	if (mail_index_is_deleted(_ctx->transaction->box->index)) {
		mailbox_set_deleted(_ctx->transaction->box);
		return -1;
	}

	file = sdbox_file_init(ctx->mbox, 0);
	ctx->append_ctx = dbox_file_append_init(file);
	ret = dbox_file_get_append_stream(ctx->append_ctx,
					  &ctx->ctx.cur_output);
	if (ret <= 0) {
		i_assert(ret != 0);
		dbox_file_append_rollback(&ctx->append_ctx);
		dbox_file_unref(&file);
		ctx->ctx.failed = TRUE;
		return -1;
	}
	ctx->ctx.cur_file = file;
	dbox_save_begin(&ctx->ctx, input);

	if (ctx->first_saved_seq == 0)
		ctx->first_saved_seq = ctx->ctx.seq;

	array_append(&ctx->files, &file, 1);
	return ctx->ctx.failed ? -1 : 0;
}

static int dbox_save_mail_write_metadata(struct dbox_save_context *ctx,
					 struct dbox_file *file)
{
	struct dbox_message_header dbox_msg_hdr;
	uoff_t message_size;
	uint8_t guid_128[MAIL_GUID_128_SIZE];

	i_assert(file->msg_header_size == sizeof(dbox_msg_hdr));

	message_size = ctx->cur_output->offset -
		file->msg_header_size - file->file_header_size;

	dbox_save_write_metadata(&ctx->ctx, ctx->cur_output, NULL, guid_128);
	dbox_msg_header_fill(&dbox_msg_hdr, message_size);
	if (o_stream_pwrite(ctx->cur_output, &dbox_msg_hdr,
			    sizeof(dbox_msg_hdr),
			    file->file_header_size) < 0) {
		dbox_file_set_syscall_error(file, "pwrite()");
		return -1;
	}
	return 0;
}

static int dbox_save_finish_write(struct mail_save_context *_ctx)
{
	struct sdbox_save_context *ctx = (struct sdbox_save_context *)_ctx;
	struct dbox_file *const *files;

	ctx->ctx.finished = TRUE;
	if (ctx->ctx.cur_output == NULL)
		return -1;

	index_mail_cache_parse_deinit(_ctx->dest_mail,
				      _ctx->received_date, !ctx->ctx.failed);

	files = array_idx_modifiable(&ctx->files, array_count(&ctx->files) - 1);

	if (!ctx->ctx.failed) T_BEGIN {
		if (dbox_save_mail_write_metadata(&ctx->ctx, *files) < 0)
			ctx->ctx.failed = TRUE;
	} T_END;

	if (ctx->ctx.failed)
		dbox_file_append_rollback(&ctx->append_ctx);
	else if (dbox_file_append_commit(&ctx->append_ctx) < 0)
		ctx->ctx.failed = TRUE;

	i_stream_unref(&ctx->ctx.input);
	dbox_file_close(*files);
	ctx->ctx.cur_output = NULL;

	return ctx->ctx.failed ? -1 : 0;
}

int sdbox_save_finish(struct mail_save_context *ctx)
{
	int ret;

	ret = dbox_save_finish_write(ctx);
	index_save_context_free(ctx);
	return ret;
}

void sdbox_save_cancel(struct mail_save_context *_ctx)
{
	struct dbox_save_context *ctx = (struct dbox_save_context *)_ctx;

	ctx->failed = TRUE;
	(void)sdbox_save_finish(_ctx);
}

static int dbox_save_assign_uids(struct sdbox_save_context *ctx,
				 const ARRAY_TYPE(seq_range) *uids)
{
	struct dbox_file *const *files;
	struct seq_range_iter iter;
	unsigned int i, count, n = 0;
	uint32_t uid;
	bool ret;

	seq_range_array_iter_init(&iter, uids);
	files = array_get(&ctx->files, &count);
	for (i = 0; i < count; i++) {
		struct sdbox_file *sfile = (struct sdbox_file *)files[i];

		ret = seq_range_array_iter_nth(&iter, n++, &uid);
		i_assert(ret);
		if (sdbox_file_assign_uid(sfile, uid) < 0)
			return -1;
	}
	i_assert(!seq_range_array_iter_nth(&iter, n, &uid));
	return 0;
}

static void dbox_save_unref_files(struct sdbox_save_context *ctx)
{
	struct mail_storage *storage = &ctx->mbox->storage->storage.storage;
	struct dbox_file **files;
	unsigned int i, count;

	files = array_get_modifiable(&ctx->files, &count);
	for (i = 0; i < count; i++) {
		if (ctx->ctx.failed) {
			if (unlink(files[i]->cur_path) < 0) {
				mail_storage_set_critical(storage,
					"unlink(%s) failed: %m",
					files[i]->cur_path);
			}
		}
		dbox_file_unref(&files[i]);
	}
	array_free(&ctx->files);
}

int sdbox_transaction_save_commit_pre(struct mail_save_context *_ctx)
{
	struct sdbox_save_context *ctx = (struct sdbox_save_context *)_ctx;
	struct mailbox_transaction_context *_t = _ctx->transaction;
	const struct mail_index_header *hdr;

	i_assert(ctx->ctx.finished);

	if (array_count(&ctx->files) == 0)
		return 0;

	if (sdbox_sync_begin(ctx->mbox, SDBOX_SYNC_FLAG_FORCE |
			     SDBOX_SYNC_FLAG_FSYNC, &ctx->sync_ctx) < 0) {
		sdbox_transaction_save_rollback(_ctx);
		return -1;
	}

	/* assign UIDs for new messages */
	hdr = mail_index_get_header(ctx->sync_ctx->sync_view);
	mail_index_append_finish_uids(ctx->ctx.trans, hdr->next_uid,
				      &_t->changes->saved_uids);
	if (dbox_save_assign_uids(ctx, &_t->changes->saved_uids) < 0) {
		sdbox_transaction_save_rollback(_ctx);
		return -1;
	}

	if (ctx->ctx.mail != NULL)
		mail_free(&ctx->ctx.mail);

	_t->changes->uid_validity = hdr->uid_validity;
	return 0;
}

void sdbox_transaction_save_commit_post(struct mail_save_context *_ctx,
					struct mail_index_transaction_commit_result *result)
{
	struct sdbox_save_context *ctx = (struct sdbox_save_context *)_ctx;

	_ctx->transaction = NULL; /* transaction is already freed */

	if (array_count(&ctx->files) == 0) {
		sdbox_transaction_save_rollback(_ctx);
		return;
	}

	mail_index_sync_set_commit_result(ctx->sync_ctx->index_sync_ctx,
					  result);

	if (sdbox_sync_finish(&ctx->sync_ctx, TRUE) < 0)
		ctx->ctx.failed = TRUE;

	if (!ctx->mbox->storage->storage.storage.set->fsync_disable) {
		if (fdatasync_path(ctx->mbox->ibox.box.path) < 0) {
			i_error("fdatasync_path(%s) failed: %m",
				ctx->mbox->ibox.box.path);
		}
	}
	sdbox_transaction_save_rollback(_ctx);
}

void sdbox_transaction_save_rollback(struct mail_save_context *_ctx)
{
	struct sdbox_save_context *ctx = (struct sdbox_save_context *)_ctx;

	if (!ctx->ctx.finished)
		sdbox_save_cancel(_ctx);
	dbox_save_unref_files(ctx);

	if (ctx->sync_ctx != NULL)
		(void)sdbox_sync_finish(&ctx->sync_ctx, FALSE);

	if (ctx->ctx.mail != NULL)
		mail_free(&ctx->ctx.mail);
	i_free(ctx);
}

int sdbox_copy(struct mail_save_context *_ctx, struct mail *mail)
{
	struct dbox_save_context *ctx = (struct dbox_save_context *)_ctx;

	/* FIXME: use hard linking */

	ctx->finished = TRUE;
	return mail_storage_copy(_ctx, mail);
}
