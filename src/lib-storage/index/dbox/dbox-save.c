/* Copyright (C) 2005 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "hex-dec.h"
#include "write-full.h"
#include "ostream.h"
#include "dbox-uidlist.h"
#include "dbox-sync.h"
#include "dbox-storage.h"

#include <stddef.h>

struct dbox_save_context {
	struct mail_save_context ctx;

	struct dbox_mailbox *mbox;
	struct mail_index_transaction *trans;
	struct dbox_uidlist_append_ctx *append_ctx;

	uint32_t first_append_seq;
	struct mail_index_sync_ctx *index_sync_ctx;

	/* updated for each appended mail: */
	uint32_t seq;
	struct istream *input;
	struct ostream *output;
        struct dbox_file *file;
	uint64_t hdr_offset;
	uint64_t mail_offset;

	bool failed;
};

struct mail_save_context *
dbox_save_init(struct mailbox_transaction_context *_t,
	       enum mail_flags flags, struct mail_keywords *keywords,
	       time_t received_date, int timezone_offset __attr_unused__,
	       const char *from_envelope __attr_unused__,
	       struct istream *input, bool want_mail __attr_unused__)
{
	struct dbox_transaction_context *t =
		(struct dbox_transaction_context *)_t;
	struct dbox_mailbox *mbox = (struct dbox_mailbox *)t->ictx.ibox;
	struct dbox_save_context *ctx = t->save_ctx;
	struct dbox_mail_header hdr;
	enum mail_flags save_flags;
	unsigned int left;
	char buf[128];
	int ret;

	i_assert((t->ictx.flags & MAILBOX_TRANSACTION_FLAG_EXTERNAL) != 0);

	if (received_date == (time_t)-1)
		received_date = ioloop_time;

	if (ctx == NULL) {
		ctx = t->save_ctx = i_new(struct dbox_save_context, 1);
		ctx->ctx.transaction = &t->ictx.mailbox_ctx;
		ctx->mbox = mbox;
		ctx->trans = t->ictx.trans;
		ctx->append_ctx = dbox_uidlist_append_init(mbox->uidlist);

		if ((ret = dbox_sync_if_changed(mbox)) < 0) {
			ctx->failed = TRUE;
			return &ctx->ctx;
		}
		if (ret > 0) {
			if (dbox_sync(mbox, FALSE) < 0) {
				ctx->failed = TRUE;
				return &ctx->ctx;
			}
		}
	}
	ctx->input = input;

	if (dbox_uidlist_append_locked(ctx->append_ctx, &ctx->file) < 0) {
		ctx->failed = TRUE;
		return &ctx->ctx;
	}
	ctx->hdr_offset = ctx->file->output->offset;

	/* append mail header. UID and mail size are written later. */
	memset(&hdr, '0', sizeof(hdr));
	memcpy(hdr.magic, DBOX_MAIL_HEADER_MAGIC, sizeof(hdr.magic));
	DEC2HEX(hdr.received_time_hex, received_date);
	hdr.answered = (flags & MAIL_ANSWERED) != 0 ? '1' : '0';
	hdr.flagged = (flags & MAIL_FLAGGED) != 0 ? '1' : '0';
	hdr.deleted = (flags & MAIL_DELETED) != 0 ? '1' : '0';
	hdr.seen = (flags & MAIL_SEEN) != 0 ? '1' : '0';
	hdr.draft = (flags & MAIL_DRAFT) != 0 ? '1' : '0';
	hdr.expunged = '0';
	// FIXME: keywords
	o_stream_send(ctx->file->output, &hdr, sizeof(hdr));

	/* write rest of the header with '0' characters */
	left = ctx->file->mail_header_size - sizeof(hdr);
	memset(buf, '0', sizeof(buf));
	while (left > sizeof(buf)) {
		o_stream_send(ctx->file->output, buf, sizeof(buf));
		left -= sizeof(buf);
	}
	o_stream_send(ctx->file->output, buf, left);
	ctx->mail_offset = ctx->file->output->offset;

	/* add to index */
	save_flags = (flags & ~MAIL_RECENT) | MAIL_RECENT;
	mail_index_append(ctx->trans, 0, &ctx->seq);
	mail_index_update_flags(ctx->trans, ctx->seq, MODIFY_REPLACE,
				save_flags);
	if (keywords != NULL) {
		mail_index_update_keywords(ctx->trans, ctx->seq,
					   MODIFY_REPLACE, keywords);
	}
	mail_index_update_ext(ctx->trans, ctx->seq, mbox->dbox_file_ext_idx,
			      &ctx->file->file_seq, NULL);
	mail_index_update_ext(ctx->trans, ctx->seq,
			      mbox->dbox_offset_ext_idx, &ctx->hdr_offset,
			      NULL);

	if (ctx->first_append_seq == 0)
		ctx->first_append_seq = ctx->seq;
	return &ctx->ctx;
}

int dbox_save_continue(struct mail_save_context *_ctx)
{
	struct dbox_save_context *ctx = (struct dbox_save_context *)_ctx;

	if (ctx->failed)
		return -1;

	if (o_stream_send_istream(ctx->file->output, ctx->input) < 0) {
		if (ENOSPACE(ctx->file->output->stream_errno)) {
			mail_storage_set_error(STORAGE(ctx->mbox->storage),
					       "Not enough disk space");
		} else {
			mail_storage_set_critical(STORAGE(ctx->mbox->storage),
				"o_stream_send_istream(%s) failed: %m",
				ctx->file->path);
		}
		ctx->failed = TRUE;
		return -1;
	}
	return 0;
}

int dbox_save_finish(struct mail_save_context *_ctx, struct mail *dest_mail)
{
	struct dbox_save_context *ctx = (struct dbox_save_context *)_ctx;
	struct dbox_mail_header hdr;

	if (!ctx->failed) {
		/* write mail size to header */
		DEC2HEX(hdr.mail_size_hex,
			ctx->file->output->offset - ctx->mail_offset);

		if (pwrite_full(ctx->file->fd, hdr.mail_size_hex,
				sizeof(hdr.mail_size_hex), ctx->hdr_offset +
				offsetof(struct dbox_mail_header,
					 mail_size_hex)) < 0) {
			mail_storage_set_critical(STORAGE(ctx->mbox->storage),
						  "pwrite_full(%s) failed: %m",
						  ctx->file->path);
			ctx->failed = TRUE;
		}
	}

	if (ctx->failed)
		return -1;

	dbox_uidlist_append_finish_mail(ctx->append_ctx, ctx->file);

	if (dest_mail != NULL) {
		i_assert(ctx->seq != 0);

		if (mail_set_seq(dest_mail, ctx->seq) < 0)
			return -1;
	}
	return 0;
}

void dbox_save_cancel(struct mail_save_context *_ctx)
{
	struct dbox_save_context *ctx = (struct dbox_save_context *)_ctx;

	ctx->failed = TRUE;
	(void)dbox_save_finish(_ctx, NULL);
}

int dbox_transaction_save_commit_pre(struct dbox_save_context *ctx)
{
	struct index_transaction_context *idx_trans =
		(struct index_transaction_context *)ctx->ctx.transaction;
	struct dbox_mail_header hdr;
	struct dbox_file *file;
	struct mail_index_view *view;
	uint32_t seq, uid, last_uid, file_seq;
	uoff_t offset;
	int ret;

	/* we want the index file to be locked from here until the appends
	   have been written to transaction log */
	if (mail_index_sync_begin(ctx->mbox->ibox.index, &ctx->index_sync_ctx,
				  &view, (uint32_t)-1, (uoff_t)-1,
				  FALSE, FALSE) < 0) {
		ctx->failed = TRUE;
		dbox_transaction_save_rollback(ctx);
		return -1;
	}

	/* uidlist gets locked here. do it after starting index syncing to
	   avoid deadlocks */
	if (dbox_uidlist_append_get_first_uid(ctx->append_ctx, &uid) < 0) {
		ctx->failed = TRUE;
		dbox_transaction_save_rollback(ctx);
		return -1;
	}
	mail_index_append_assign_uids(ctx->trans, uid, &last_uid);

	/* update UIDs */
	for (seq = ctx->first_append_seq; seq <= ctx->seq; seq++, uid++) {
		ret = dbox_mail_lookup_offset(idx_trans, seq,
					      &file_seq, &offset);
		i_assert(ret > 0); /* it's in memory, shouldn't fail! */

		DEC2HEX(hdr.uid_hex, uid);

		file = dbox_uidlist_append_lookup_file(ctx->append_ctx,
						       file_seq);
		if (pwrite_full(ctx->file->fd, hdr.uid_hex,
				sizeof(hdr.uid_hex), offset +
				offsetof(struct dbox_mail_header,
					 uid_hex)) < 0) {
			mail_storage_set_critical(STORAGE(ctx->mbox->storage),
						  "pwrite_full(%s) failed: %m",
						  ctx->file->path);
			ctx->failed = TRUE;
                        dbox_transaction_save_rollback(ctx);
			return -1;
		}
	}

	if (dbox_uidlist_append_commit(ctx->append_ctx) < 0) {
		mail_index_sync_rollback(&ctx->index_sync_ctx);
		i_free(ctx);
		return -1;
	}
	return 0;
}

void dbox_transaction_save_commit_post(struct dbox_save_context *ctx)
{
	mail_index_sync_rollback(&ctx->index_sync_ctx);
	i_free(ctx);
}

void dbox_transaction_save_rollback(struct dbox_save_context *ctx)
{
	if (ctx->index_sync_ctx != NULL)
		mail_index_sync_rollback(&ctx->index_sync_ctx);

        dbox_uidlist_append_rollback(ctx->append_ctx);
	i_free(ctx);
}
