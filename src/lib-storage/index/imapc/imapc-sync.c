/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "imap-util.h"
#include "index-sync-private.h"
#include "imapc-storage.h"
#include "imapc-client.h"
#include "imapc-seqmap.h"
#include "imapc-sync.h"

static void imapc_sync_callback(const struct imapc_command_reply *reply,
				void *context)
{
	struct imapc_sync_context *ctx = context;

	i_assert(ctx->sync_command_count > 0);

	if (reply->state == IMAPC_COMMAND_STATE_OK)
		;
	else if (reply->state == IMAPC_COMMAND_STATE_NO) {
		/* maybe the message was expunged already.
		   some servers fail STOREs with NO in such situation. */
	} else if (reply->state == IMAPC_COMMAND_STATE_DISCONNECTED) {
		/* the disconnection is already logged, don't flood
		   the logs unnecessarily */
		mail_storage_set_internal_error(&ctx->mbox->storage->storage);
		ctx->failed = TRUE;
	} else {
		mail_storage_set_critical(&ctx->mbox->storage->storage,
			"imapc: Sync command failed: %s", reply->text_full);
		ctx->failed = TRUE;
	}
	
	if (--ctx->sync_command_count == 0)
		imapc_client_stop(ctx->mbox->storage->client);
}

static void imapc_sync_cmd(struct imapc_sync_context *ctx, const char *cmd)
{
	ctx->sync_command_count++;
	imapc_client_mailbox_cmd(ctx->mbox->client_box, cmd,
				 imapc_sync_callback, ctx);
}

static void
imapc_sync_add_missing_deleted_flags(struct imapc_sync_context *ctx,
				     uint32_t seq1, uint32_t seq2)
{
	const struct mail_index_record *rec;
	uint32_t seq, uid1, uid2;
	const char *cmd;

	/* if any of them has a missing \Deleted flag,
	   just add it to all of them. */
	for (seq = seq1; seq <= seq2; seq++) {
		rec = mail_index_lookup(ctx->sync_view, seq);
		if ((rec->flags & MAIL_DELETED) == 0)
			break;
	}

	if (seq <= seq2) {
		mail_index_lookup_uid(ctx->sync_view, seq1, &uid1);
		mail_index_lookup_uid(ctx->sync_view, seq2, &uid2);
		cmd = t_strdup_printf("UID STORE %u:%u +FLAGS \\Deleted",
				      uid1, uid2);
		imapc_sync_cmd(ctx, cmd);
	}
}

static void imapc_sync_index_flags(struct imapc_sync_context *ctx,
				   const struct mail_index_sync_rec *sync_rec)
{
	string_t *str = t_str_new(128);

	i_assert(sync_rec->type == MAIL_INDEX_SYNC_TYPE_FLAGS);

	if (sync_rec->add_flags != 0) {
		i_assert((sync_rec->add_flags & MAIL_RECENT) == 0);
		str_printfa(str, "UID STORE %u:%u +FLAGS (",
			    sync_rec->uid1, sync_rec->uid2);
		imap_write_flags(str, sync_rec->add_flags, NULL);
		str_append_c(str, ')');
		imapc_sync_cmd(ctx, str_c(str));
	}

	if (sync_rec->remove_flags != 0) {
		i_assert((sync_rec->remove_flags & MAIL_RECENT) == 0);
		str_truncate(str, 0);
		str_printfa(str, "UID STORE %u:%u -FLAGS (",
			    sync_rec->uid1, sync_rec->uid2);
		imap_write_flags(str, sync_rec->remove_flags, NULL);
		str_append_c(str, ')');
		imapc_sync_cmd(ctx, str_c(str));
	}
}

static void
imapc_sync_index_keyword(struct imapc_sync_context *ctx,
			 const struct mail_index_sync_rec *sync_rec)
{
	string_t *str = t_str_new(128);
	const char *const *kw_p;
	char change_char;

	switch (sync_rec->type) {
	case MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD:
		change_char = '+';
		break;
	case MAIL_INDEX_SYNC_TYPE_KEYWORD_REMOVE:
		change_char = '-';
		break;
	default:
		i_unreached();
	}

	str_printfa(str, "UID STORE %u:%u %cFLAGS (",
		    sync_rec->uid1, sync_rec->uid2, change_char);

	kw_p = array_idx(ctx->keywords, sync_rec->keyword_idx);
	str_append(str, *kw_p);
	str_append_c(str, ')');
	imapc_sync_cmd(ctx, str_c(str));
}

static void
imapc_sync_index_keyword_reset(struct imapc_sync_context *ctx,
			       uint32_t seq1, uint32_t seq2)
{
	const struct mail_index_record *rec;
	string_t *str = t_str_new(128);
	uint32_t seq;

	for (seq = seq1; seq <= seq2; seq++) {
		rec = mail_index_lookup(ctx->sync_view, seq);
		i_assert((rec->flags & MAIL_RECENT) == 0);

		str_truncate(str, 0);
		str_printfa(str, "UID STORE %u FLAGS (", rec->uid);
		imap_write_flags(str, rec->flags, NULL);
		str_append_c(str, ')');
		imapc_sync_cmd(ctx, str_c(str));
	}
}

static void imapc_sync_expunge_finish(struct imapc_sync_context *ctx)
{
	string_t *str;
	enum imapc_capability caps;
	const struct seq_range *range;
	unsigned int i, count;

	if (array_count(&ctx->expunged_uids) == 0)
		return;

	caps = imapc_client_get_capabilities(ctx->mbox->storage->client);
	if ((caps & IMAPC_CAPABILITY_UIDPLUS) == 0) {
		/* just expunge everything */
		imapc_sync_cmd(ctx, "EXPUNGE");
		return;
	}

	/* build a list of UIDs to expunge */
	str = t_str_new(128);
	str_append(str, "UID EXPUNGE");

	range = array_get(&ctx->expunged_uids, &count);
	for (i = 0; i < count; i++) {
		str_printfa(str, " %u", range[i].seq1);
		if (range[i].seq1 == range[i].seq2)
			str_printfa(str, ":%u", range[i].seq2);
	}
	imapc_sync_cmd(ctx, str_c(str));
}

static void imapc_sync_index(struct imapc_sync_context *ctx)
{
	struct mailbox *box = &ctx->mbox->box;
	struct mail_index_sync_rec sync_rec;
	uint32_t seq1, seq2;

	i_array_init(&ctx->expunged_uids, 64);
	ctx->keywords = mail_index_get_keywords(box->index);

	while (mail_index_sync_next(ctx->index_sync_ctx, &sync_rec)) T_BEGIN {
		if (!mail_index_lookup_seq_range(ctx->sync_view,
						 sync_rec.uid1, sync_rec.uid2,
						 &seq1, &seq2)) {
			/* already expunged, nothing to do. */
		} else switch (sync_rec.type) {
		case MAIL_INDEX_SYNC_TYPE_APPEND:
			/* don't care */
			break;
		case MAIL_INDEX_SYNC_TYPE_EXPUNGE:
			imapc_sync_add_missing_deleted_flags(ctx, seq1, seq2);
			seq_range_array_add_range(&ctx->expunged_uids,
						  sync_rec.uid1, sync_rec.uid2);
			break;
		case MAIL_INDEX_SYNC_TYPE_FLAGS:
			imapc_sync_index_flags(ctx, &sync_rec);
			break;
		case MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD:
		case MAIL_INDEX_SYNC_TYPE_KEYWORD_REMOVE:
			imapc_sync_index_keyword(ctx, &sync_rec);
			break;
		case MAIL_INDEX_SYNC_TYPE_KEYWORD_RESET:
			imapc_sync_index_keyword_reset(ctx, seq1, seq2);
			break;
		}
	} T_END;

	imapc_sync_expunge_finish(ctx);
	while (ctx->sync_command_count > 0)
		imapc_client_run(ctx->mbox->storage->client);
	array_free(&ctx->expunged_uids);

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

	i_assert(mbox->delayed_sync_trans == NULL);
	mbox->sync_view = ctx->sync_view;
	mbox->delayed_sync_view =
		mail_index_transaction_open_updated_view(ctx->trans);
	mbox->delayed_sync_trans = ctx->trans;

	imapc_sync_index(ctx);

	mail_index_view_close(&mbox->delayed_sync_view);
	mbox->delayed_sync_trans = NULL;
	mbox->sync_view = NULL;

	*ctx_r = ctx;
	return 0;
}

static int imapc_sync_finish(struct imapc_sync_context **_ctx)
{
	struct imapc_sync_context *ctx = *_ctx;
	int ret = ctx->failed ? -1 : 0;

	*_ctx = NULL;
	if (ret == 0) {
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
	struct imapc_seqmap *seqmap;

	/* if there are any pending expunges, they're now committed. syncing
	   will return a view where they no longer exist, so reset the seqmap
	   before syncing. */
	seqmap = imapc_client_mailbox_get_seqmap(mbox->client_box);
	imapc_seqmap_reset(seqmap);

	if (imapc_sync_begin(mbox, &sync_ctx, FALSE) < 0)
		return -1;
	if (sync_ctx == NULL)
		return 0;
	if (imapc_sync_finish(&sync_ctx) < 0)
		return -1;

	/* syncing itself may have also seen new expunges, which are also now
	   committed and synced. reset the seqmap again. */
	imapc_seqmap_reset(seqmap);
	return 0;
}

struct mailbox_sync_context *
imapc_mailbox_sync_init(struct mailbox *box, enum mailbox_sync_flags flags)
{
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)box;
	enum imapc_capability capabilities;
	bool changes = FALSE;
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
			mail_storage_set_index_error(&mbox->box);
			ret = -1;
		}
		changes = TRUE;
	}
	if (mbox->sync_view != NULL)
		mail_index_view_close(&mbox->sync_view);

	if ((changes || index_mailbox_want_full_sync(&mbox->box, flags)) &&
	    ret == 0)
		ret = imapc_sync(mbox);

	if (changes && ret < 0) {
		/* we're now out of sync and can't safely continue */
		mail_index_mark_corrupted(mbox->box.index);
	}
	return index_mailbox_sync_init(box, flags, ret < 0);
}

int imapc_mailbox_sync_deinit(struct mailbox_sync_context *ctx,
			      struct mailbox_sync_status *status_r)
{
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)ctx->box;
	int ret;

	ret = index_mailbox_sync_deinit(ctx, status_r);
	ctx = NULL;

	if (mbox->client_box == NULL)
		return ret;

	imapc_client_mailbox_idle(mbox->client_box);
	return ret;
}
