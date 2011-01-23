/* Copyright (c) 2007-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "index-sync-private.h"
#include "imapc-storage.h"
#include "imapc-client.h"
#include "imapc-seqmap.h"
#include "imapc-sync.h"

static void imapc_sync_index(struct imapc_sync_context *ctx)
{
	struct mailbox *box = &ctx->mbox->box;
	struct mail_index_sync_rec sync_rec;
	uint32_t seq1, seq2;

	while (mail_index_sync_next(ctx->index_sync_ctx, &sync_rec)) {
		if (!mail_index_lookup_seq_range(ctx->sync_view,
						 sync_rec.uid1, sync_rec.uid2,
						 &seq1, &seq2)) {
			/* already expunged, nothing to do. */
			continue;
		}

		switch (sync_rec.type) {
		case MAIL_INDEX_SYNC_TYPE_APPEND:
			/* don't care */
			break;
		case MAIL_INDEX_SYNC_TYPE_EXPUNGE:
			//imapc_sync_expunge(ctx, seq1, seq2);
			break;
		case MAIL_INDEX_SYNC_TYPE_FLAGS:
		case MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD:
		case MAIL_INDEX_SYNC_TYPE_KEYWORD_REMOVE:
		case MAIL_INDEX_SYNC_TYPE_KEYWORD_RESET:
			/* FIXME: should be bother calling sync_notify()? */
			break;
		}
	}

	if (box->v.sync_notify != NULL)
		box->v.sync_notify(box, 0, 0);
}

static int
imapc_sync_begin(struct imapc_mailbox *mbox,
		 struct imapc_sync_context **ctx_r, bool force)
{
	struct imapc_sync_context *ctx;
	enum mail_index_sync_flags sync_flags;
	int ret;

	ctx = i_new(struct imapc_sync_context, 1);
	ctx->mbox = mbox;

	sync_flags = index_storage_get_sync_flags(&mbox->box) |
		MAIL_INDEX_SYNC_FLAG_FLUSH_DIRTY;
	if (!force)
		sync_flags |= MAIL_INDEX_SYNC_FLAG_REQUIRE_CHANGES;

	ret = mail_index_sync_begin(mbox->box.index, &ctx->index_sync_ctx,
				    &ctx->sync_view, &ctx->trans,
				    sync_flags);
	if (ret <= 0) {
		if (ret < 0)
			mail_storage_set_index_error(&mbox->box);
		i_free(ctx);
		*ctx_r = NULL;
		return ret;
	}

	imapc_sync_index(ctx);
	*ctx_r = ctx;
	return 0;
}

static int imapc_sync_finish(struct imapc_sync_context **_ctx, bool success)
{
	struct imapc_sync_context *ctx = *_ctx;
	int ret = success ? 0 : -1;

	*_ctx = NULL;
	if (success) {
		if (mail_index_sync_commit(&ctx->index_sync_ctx) < 0) {
			mail_storage_set_index_error(&ctx->mbox->box);
			ret = -1;
		}
	} else {
		mail_index_sync_rollback(&ctx->index_sync_ctx);
	}
	i_free(ctx);
	return ret;
}

static int imapc_sync(struct imapc_mailbox *mbox)
{
	struct imapc_sync_context *sync_ctx;

	if (imapc_sync_begin(mbox, &sync_ctx, FALSE) < 0)
		return -1;

	return sync_ctx == NULL ? 0 :
		imapc_sync_finish(&sync_ctx, TRUE);
}

struct mailbox_sync_context *
imapc_mailbox_sync_init(struct mailbox *box, enum mailbox_sync_flags flags)
{
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)box;
	enum imapc_capability capabilities;
	int ret = 0;

	if (!box->opened) {
		if (mailbox_open(box) < 0)
			ret = -1;
	}

	capabilities = imapc_client_get_capabilities(mbox->storage->client);
	if ((capabilities & IMAPC_CAPABILITY_IDLE) == 0) {
		/* IDLE not supported. do NOOP to get latest changes
		   before starting sync. */
		imapc_client_mailbox_cmdf(mbox->client_box,
					  imapc_async_stop_callback,
					  mbox->storage, "NOOP");
		imapc_client_run(mbox->storage->client);
	}

	if (mbox->delayed_sync_view != NULL)
		mail_index_view_close(&mbox->delayed_sync_view);
	if (mbox->delayed_sync_trans != NULL) {
		if (mail_index_transaction_commit(&mbox->delayed_sync_trans) < 0) {
			// FIXME: mark inconsistent
			mail_storage_set_index_error(&mbox->box);
			ret = -1;
		}
	}

	if (index_mailbox_want_full_sync(&mbox->box, flags) && ret == 0)
		ret = imapc_sync(mbox);

	return index_mailbox_sync_init(box, flags, ret < 0);
}

int imapc_mailbox_sync_deinit(struct mailbox_sync_context *ctx,
			      struct mailbox_sync_status *status_r)
{
	struct index_mailbox_sync_context *ictx =
		(struct index_mailbox_sync_context *)ctx;
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)ctx->box;
	struct imapc_seqmap *seqmap;
	int ret;

	ret = index_mailbox_sync_deinit(ctx, status_r);
	if (mbox->client_box == NULL)
		return ret;

	if ((ictx->flags & MAILBOX_SYNC_FLAG_NO_EXPUNGES) == 0 && ret == 0) {
		seqmap = imapc_client_mailbox_get_seqmap(mbox->client_box);
		imapc_seqmap_reset(seqmap);
	}
	imapc_client_mailbox_idle(mbox->client_box);
	return ret;
}
