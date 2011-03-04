/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

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
#include "mdbox-storage.h"
#include "mdbox-map.h"
#include "mdbox-file.h"
#include "mdbox-sync.h"

#include <stdlib.h>

struct dbox_save_mail {
	struct dbox_file_append_context *file_append;
	uint32_t seq;
	uint32_t append_offset;
};

struct mdbox_save_context {
	struct dbox_save_context ctx;

	struct mdbox_mailbox *mbox;
	struct mdbox_sync_context *sync_ctx;

	struct dbox_file_append_context *cur_file_append;
	struct mdbox_map_append_context *append_ctx;

	ARRAY_TYPE(uint32_t) copy_map_uids;
	struct mdbox_map_atomic_context *atomic;
	struct mdbox_map_transaction_context *map_trans;

	ARRAY_DEFINE(mails, struct dbox_save_mail);
};

static struct dbox_file *
mdbox_copy_file_get_file(struct mailbox_transaction_context *t,
			 uint32_t seq, uoff_t *offset_r)
{
	struct mdbox_save_context *ctx =
		(struct mdbox_save_context *)t->save_ctx;
	const struct mdbox_mail_index_record *rec;
	const void *data;
	bool expunged;
	uint32_t file_id;

	mail_index_lookup_ext(t->view, seq, ctx->mbox->ext_id,
			      &data, &expunged);
	rec = data;

	if (mdbox_map_lookup(ctx->mbox->storage->map, rec->map_uid,
			     &file_id, offset_r) <= 0)
		i_unreached();

	return mdbox_file_init(ctx->mbox->storage, file_id);
}

struct dbox_file *
mdbox_save_file_get_file(struct mailbox_transaction_context *t,
			 uint32_t seq, uoff_t *offset_r)
{
	struct mdbox_save_context *ctx =
		(struct mdbox_save_context *)t->save_ctx;
	const struct dbox_save_mail *mails, *mail;
	unsigned int count;

	mails = array_get(&ctx->mails, &count);
	i_assert(count > 0);
	i_assert(seq >= mails[0].seq);

	mail = &mails[seq - mails[0].seq];
	i_assert(mail->seq == seq);

	if (mail->file_append == NULL) {
		/* copied mail */
		return mdbox_copy_file_get_file(t, seq, offset_r);
	}

	/* saved mail */
	if (dbox_file_append_flush(mail->file_append) < 0)
		ctx->ctx.failed = TRUE;

	mail->file_append->file->refcount++;
	*offset_r = mail->append_offset;
	return mail->file_append->file;
}

struct mail_save_context *
mdbox_save_alloc(struct mailbox_transaction_context *t)
{
	struct mdbox_mailbox *mbox = (struct mdbox_mailbox *)t->box;
	struct mdbox_save_context *ctx =
		(struct mdbox_save_context *)t->save_ctx;

	i_assert((t->flags & MAILBOX_TRANSACTION_FLAG_EXTERNAL) != 0);

	if (ctx != NULL) {
		/* use the existing allocated structure */
		ctx->ctx.failed = FALSE;
		ctx->ctx.finished = FALSE;
		ctx->ctx.cur_file = NULL;
		ctx->ctx.dbox_output = NULL;
		ctx->cur_file_append = NULL;
		return &ctx->ctx.ctx;
	}

	ctx = i_new(struct mdbox_save_context, 1);
	ctx->ctx.ctx.transaction = t;
	ctx->ctx.trans = t->itrans;
	ctx->mbox = mbox;
	ctx->atomic = mdbox_map_atomic_begin(mbox->storage->map);
	ctx->append_ctx = mdbox_map_append_begin(ctx->atomic);
	i_array_init(&ctx->mails, 32);
	t->save_ctx = &ctx->ctx.ctx;
	return t->save_ctx;
}

int mdbox_save_begin(struct mail_save_context *_ctx, struct istream *input)
{
	struct mdbox_save_context *ctx = (struct mdbox_save_context *)_ctx;
	struct dbox_save_mail *save_mail;
	uoff_t mail_size, append_offset;

	/* get the size of the mail to be saved, if possible */
	if (i_stream_get_size(input, TRUE, &mail_size) <= 0) {
		const struct stat *st;

		/* we couldn't find out the exact size. fallback to non-exact,
		   maybe it'll give something useful. the mail size is used
		   only to figure out if it's causing mdbox file to grow
		   too large. */
		st = i_stream_stat(input, FALSE);
		mail_size = st->st_size > 0 ? st->st_size : 0;
	}
	if (mdbox_map_append_next(ctx->append_ctx, mail_size, 0,
				  &ctx->cur_file_append,
				  &ctx->ctx.dbox_output) < 0) {
		ctx->ctx.failed = TRUE;
		return -1;
	}
	i_assert(ctx->ctx.dbox_output->offset <= (uint32_t)-1);
	append_offset = ctx->ctx.dbox_output->offset;

	ctx->ctx.cur_file = ctx->cur_file_append->file;
	dbox_save_begin(&ctx->ctx, input);

	save_mail = array_append_space(&ctx->mails);
	save_mail->file_append = ctx->cur_file_append;
	save_mail->seq = ctx->ctx.seq;
	save_mail->append_offset = append_offset;
	return ctx->ctx.failed ? -1 : 0;
}

static int mdbox_save_mail_write_metadata(struct mdbox_save_context *ctx,
					  struct dbox_save_mail *mail)
{
	struct dbox_file *file = mail->file_append->file;
	struct dbox_message_header dbox_msg_hdr;
	uoff_t message_size;
	uint8_t guid_128[MAIL_GUID_128_SIZE];

	i_assert(file->msg_header_size == sizeof(dbox_msg_hdr));

	message_size = ctx->ctx.dbox_output->offset -
		mail->append_offset - mail->file_append->file->msg_header_size;

	dbox_save_write_metadata(&ctx->ctx.ctx, ctx->ctx.dbox_output,
				 message_size, ctx->mbox->box.name, guid_128);
	/* save the 128bit GUID to index so if the map index gets corrupted
	   we can still find the message */
	mail_index_update_ext(ctx->ctx.trans, ctx->ctx.seq,
			      ctx->mbox->guid_ext_id, guid_128, NULL);

	dbox_msg_header_fill(&dbox_msg_hdr, message_size);
	if (o_stream_pwrite(ctx->ctx.dbox_output, &dbox_msg_hdr,
			    sizeof(dbox_msg_hdr), mail->append_offset) < 0) {
		dbox_file_set_syscall_error(file, "pwrite()");
		return -1;
	}
	return 0;
}

static int mdbox_save_finish_write(struct mail_save_context *_ctx)
{
	struct mdbox_save_context *ctx = (struct mdbox_save_context *)_ctx;
	struct dbox_save_mail *mail;

	ctx->ctx.finished = TRUE;
	if (ctx->ctx.dbox_output == NULL)
		return -1;

	dbox_save_end(&ctx->ctx);
	index_mail_cache_parse_deinit(_ctx->dest_mail,
				      _ctx->received_date, !ctx->ctx.failed);

	mail = array_idx_modifiable(&ctx->mails, array_count(&ctx->mails) - 1);
	if (!ctx->ctx.failed) T_BEGIN {
		if (mdbox_save_mail_write_metadata(ctx, mail) < 0)
			ctx->ctx.failed = TRUE;
		else
			mdbox_map_append_finish(ctx->append_ctx);
	} T_END;

	if (mail->file_append->file->input != NULL) {
		/* if we try to read the saved mail before unlocking file,
		   make sure the input stream doesn't have stale data */
		i_stream_sync(mail->file_append->file->input);
	}
	i_stream_unref(&ctx->ctx.input);

	if (ctx->ctx.failed) {
		mdbox_map_append_abort(ctx->append_ctx);
		array_delete(&ctx->mails, array_count(&ctx->mails) - 1, 1);
		return -1;
	}
	return 0;
}

int mdbox_save_finish(struct mail_save_context *ctx)
{
	int ret;

	ret = mdbox_save_finish_write(ctx);
	index_save_context_free(ctx);
	return ret;
}

void mdbox_save_cancel(struct mail_save_context *_ctx)
{
	struct dbox_save_context *ctx = (struct dbox_save_context *)_ctx;

	ctx->failed = TRUE;
	(void)mdbox_save_finish(_ctx);
}

static void
mdbox_save_set_map_uids(struct mdbox_save_context *ctx,
			uint32_t first_map_uid, uint32_t last_map_uid)
{
	struct mdbox_mailbox *mbox = ctx->mbox;
	struct mail_index_view *view = ctx->ctx.ctx.transaction->view;
	const struct mdbox_mail_index_record *old_rec;
	struct mdbox_mail_index_record rec;
	const struct dbox_save_mail *mails;
	unsigned int i, count;
	const void *data;
	bool expunged;
	uint32_t next_map_uid = first_map_uid;

	mdbox_update_header(mbox, ctx->ctx.trans, NULL);

	memset(&rec, 0, sizeof(rec));
	rec.save_date = ioloop_time;
	mails = array_get(&ctx->mails, &count);
	for (i = 0; i < count; i++) {
		mail_index_lookup_ext(view, mails[i].seq, mbox->ext_id,
				      &data, &expunged);
		old_rec = data;
		if (old_rec != NULL && old_rec->map_uid != 0) {
			/* message was copied. keep the existing map uid */
			continue;
		}

		rec.map_uid = next_map_uid++;
		mail_index_update_ext(ctx->ctx.trans, mails[i].seq,
				      mbox->ext_id, &rec, NULL);
	}
	i_assert(next_map_uid == last_map_uid + 1);
}

int mdbox_transaction_save_commit_pre(struct mail_save_context *_ctx)
{
	struct mdbox_save_context *ctx = (struct mdbox_save_context *)_ctx;
	struct mailbox_transaction_context *_t = _ctx->transaction;
	const struct mail_index_header *hdr;
	uint32_t first_map_uid, last_map_uid;

	i_assert(ctx->ctx.finished);

	/* make sure the map gets locked */
	if (mdbox_map_atomic_lock(ctx->atomic) < 0) {
		mdbox_transaction_save_rollback(_ctx);
		return -1;
	}

	/* assign map UIDs for newly saved messages. they're written to
	   transaction log immediately within this function, but the map
	   is left locked. */
	if (mdbox_map_append_assign_map_uids(ctx->append_ctx, &first_map_uid,
					     &last_map_uid) < 0) {
		mdbox_transaction_save_rollback(_ctx);
		return -1;
	}

	/* lock the mailbox after map to avoid deadlocks. */
	if (mdbox_sync_begin(ctx->mbox, MDBOX_SYNC_FLAG_NO_PURGE |
			     MDBOX_SYNC_FLAG_FORCE |
			     MDBOX_SYNC_FLAG_FSYNC, ctx->atomic,
			     &ctx->sync_ctx) < 0) {
		mdbox_transaction_save_rollback(_ctx);
		return -1;
	}

	/* assign UIDs for new messages */
	hdr = mail_index_get_header(ctx->sync_ctx->sync_view);
	mail_index_append_finish_uids(ctx->ctx.trans, hdr->next_uid,
				      &_t->changes->saved_uids);

	/* save map UIDs to mailbox index */
	if (first_map_uid != 0)
		mdbox_save_set_map_uids(ctx, first_map_uid, last_map_uid);

	/* increase map's refcount for copied mails */
	if (array_is_created(&ctx->copy_map_uids)) {
		ctx->map_trans = mdbox_map_transaction_begin(ctx->atomic, FALSE);
		if (mdbox_map_update_refcounts(ctx->map_trans,
					       &ctx->copy_map_uids, 1) < 0) {
			mdbox_transaction_save_rollback(_ctx);
			return -1;
		}
	}

	if (ctx->ctx.mail != NULL)
		mail_free(&ctx->ctx.mail);

	_t->changes->uid_validity = hdr->uid_validity;
	return 0;
}

void mdbox_transaction_save_commit_post(struct mail_save_context *_ctx,
					struct mail_index_transaction_commit_result *result)
{
	struct mdbox_save_context *ctx = (struct mdbox_save_context *)_ctx;
	struct mail_storage *storage = _ctx->transaction->box->storage;

	_ctx->transaction = NULL; /* transaction is already freed */

	mail_index_sync_set_commit_result(ctx->sync_ctx->index_sync_ctx,
					  result);

	/* finish writing the mailbox APPENDs */
	if (mdbox_sync_finish(&ctx->sync_ctx, TRUE) == 0) {
		/* commit refcount increases for copied mails */
		if (ctx->map_trans != NULL) {
			if (mdbox_map_transaction_commit(ctx->map_trans) < 0)
				mdbox_map_atomic_set_failed(ctx->atomic);
		}
		/* flush file append writes */
		if (mdbox_map_append_commit(ctx->append_ctx) < 0)
			mdbox_map_atomic_set_failed(ctx->atomic);
	}
	mdbox_map_append_free(&ctx->append_ctx);
	/* update the sync tail offset, everything else
	   was already written at this point. */
	(void)mdbox_map_atomic_finish(&ctx->atomic);

	if (storage->set->parsed_fsync_mode != FSYNC_MODE_NEVER) {
		if (fdatasync_path(ctx->mbox->box.path) < 0) {
			mail_storage_set_critical(storage,
				"fdatasync_path(%s) failed: %m",
				ctx->mbox->box.path);
		}
	}
	mdbox_transaction_save_rollback(_ctx);
}

void mdbox_transaction_save_rollback(struct mail_save_context *_ctx)
{
	struct mdbox_save_context *ctx = (struct mdbox_save_context *)_ctx;

	if (!ctx->ctx.finished)
		mdbox_save_cancel(&ctx->ctx.ctx);
	if (ctx->append_ctx != NULL)
		mdbox_map_append_free(&ctx->append_ctx);
	if (ctx->map_trans != NULL)
		mdbox_map_transaction_free(&ctx->map_trans);
	if (ctx->atomic != NULL)
		(void)mdbox_map_atomic_finish(&ctx->atomic);
	if (array_is_created(&ctx->copy_map_uids))
		array_free(&ctx->copy_map_uids);

	if (ctx->sync_ctx != NULL)
		(void)mdbox_sync_finish(&ctx->sync_ctx, FALSE);

	if (ctx->ctx.mail != NULL)
		mail_free(&ctx->ctx.mail);
	array_free(&ctx->mails);
	i_free(ctx);
}

int mdbox_copy(struct mail_save_context *_ctx, struct mail *mail)
{
	struct mdbox_save_context *ctx = (struct mdbox_save_context *)_ctx;
	struct dbox_save_mail *save_mail;
	struct mdbox_mailbox *src_mbox;
	struct mdbox_mail_index_record rec;
	const void *data;
	bool expunged;

	ctx->ctx.finished = TRUE;

	if (mail->box->storage != _ctx->transaction->box->storage ||
	    _ctx->transaction->box->disable_reflink_copy_to ||
	    _ctx->guid != NULL)
		return mail_storage_copy(_ctx, mail);
	src_mbox = (struct mdbox_mailbox *)mail->box;

	memset(&rec, 0, sizeof(rec));
	rec.save_date = ioloop_time;
	if (mdbox_mail_lookup(src_mbox, mail->transaction->view, mail->seq,
			      &rec.map_uid) < 0)
		return -1;

	/* remember the map_uid so we can later increase its refcount */
	if (!array_is_created(&ctx->copy_map_uids))
		i_array_init(&ctx->copy_map_uids, 32);
	array_append(&ctx->copy_map_uids, &rec.map_uid, 1);

	/* add message to mailbox index */
	dbox_save_add_to_index(&ctx->ctx);
	mail_index_update_ext(ctx->ctx.trans, ctx->ctx.seq,
			      ctx->mbox->ext_id, &rec, NULL);

	mail_index_lookup_ext(mail->transaction->view, mail->seq,
			      src_mbox->guid_ext_id, &data, &expunged);
	if (data != NULL) {
		mail_index_update_ext(ctx->ctx.trans, ctx->ctx.seq,
				      ctx->mbox->guid_ext_id, data, NULL);
	}
	index_copy_cache_fields(_ctx, mail, ctx->ctx.seq);

	save_mail = array_append_space(&ctx->mails);
	save_mail->seq = ctx->ctx.seq;

	if (_ctx->dest_mail != NULL) {
		mail_set_seq(_ctx->dest_mail, ctx->ctx.seq);
		_ctx->dest_mail->saving = TRUE;
	}
	return 0;
}
