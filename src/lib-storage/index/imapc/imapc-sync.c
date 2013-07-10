/* Copyright (c) 2007-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "imap-util.h"
#include "index-sync-private.h"
#include "imapc-client.h"
#include "imapc-msgmap.h"
#include "imapc-storage.h"
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
		imapc_client_stop(ctx->mbox->storage->client->client);
}

static void imapc_sync_cmd(struct imapc_sync_context *ctx, const char *cmd_str)
{
	struct imapc_command *cmd;

	ctx->sync_command_count++;
	cmd = imapc_client_mailbox_cmd(ctx->mbox->client_box,
				       imapc_sync_callback, ctx);
	imapc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_RETRIABLE);
	imapc_command_send(cmd, cmd_str);
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

static void imapc_sync_expunge_finish(struct imapc_sync_context *ctx)
{
	string_t *str;
	enum imapc_capability caps;

	if (array_count(&ctx->expunged_uids) == 0)
		return;

	caps = imapc_client_get_capabilities(ctx->mbox->storage->client->client);
	if ((caps & IMAPC_CAPABILITY_UIDPLUS) == 0) {
		/* just expunge everything */
		imapc_sync_cmd(ctx, "EXPUNGE");
		return;
	}

	/* build a list of UIDs to expunge */
	str = t_str_new(128);
	str_append(str, "UID EXPUNGE ");
	imap_write_seq_range(str, &ctx->expunged_uids);
	imapc_sync_cmd(ctx, str_c(str));
}

static void imapc_sync_expunge_eom(struct imapc_sync_context *ctx)
{
	struct imapc_mailbox *mbox = ctx->mbox;
	uint32_t lseq, uid, msg_count;

	if (mbox->sync_next_lseq == 0)
		return;

	/* if we haven't seen FETCH reply for some messages at the end of
	   mailbox they've been externally expunged. */
	msg_count = mail_index_view_get_messages_count(ctx->sync_view);
	for (lseq = mbox->sync_next_lseq; lseq <= msg_count; lseq++) {
		mail_index_lookup_uid(ctx->sync_view, lseq, &uid);
		if (uid >= mbox->sync_uid_next) {
			/* another process already added new messages to index
			   that our IMAP connection hasn't seen yet */
			break;
		}
		mail_index_expunge(ctx->trans, lseq);
	}

	mbox->sync_next_lseq = 0;
	mbox->sync_next_rseq = 0;
}

static void imapc_sync_uid_validity(struct imapc_sync_context *ctx)
{
	struct imapc_mailbox *mbox = ctx->mbox;
	const struct mail_index_header *hdr;

	hdr = mail_index_get_header(ctx->sync_view);
	if (hdr->uid_validity != mbox->sync_uid_validity &&
	    mbox->sync_uid_validity != 0) {
		if (hdr->uid_validity != 0) {
			/* uidvalidity changed, reset the entire mailbox */
			mail_index_reset(ctx->trans);
			mbox->sync_fetch_first_uid = 1;
		}
		mail_index_update_header(ctx->trans,
			offsetof(struct mail_index_header, uid_validity),
			&mbox->sync_uid_validity,
			sizeof(mbox->sync_uid_validity), TRUE);
	}
}

static void imapc_sync_uid_next(struct imapc_sync_context *ctx)
{
	struct imapc_mailbox *mbox = ctx->mbox;
	const struct mail_index_header *hdr;
	uint32_t uid_next = mbox->sync_uid_next;

	if (uid_next < mbox->min_append_uid)
		uid_next = mbox->min_append_uid;

	hdr = mail_index_get_header(ctx->sync_view);
	if (hdr->next_uid < uid_next) {
		mail_index_update_header(ctx->trans,
			offsetof(struct mail_index_header, next_uid),
			&uid_next, sizeof(uid_next), FALSE);
	}
}

static void
imapc_initial_sync_check(struct imapc_sync_context *ctx, bool nooped)
{
	struct imapc_msgmap *msgmap =
		imapc_client_mailbox_get_msgmap(ctx->mbox->client_box);
	struct mail_index_view *view = ctx->mbox->delayed_sync_view;
	const struct mail_index_header *hdr = mail_index_get_header(view);
	uint32_t rseq, lseq, ruid, luid, rcount, lcount;

	rseq = lseq = 1;
	rcount = imapc_msgmap_count(msgmap);
	lcount = mail_index_view_get_messages_count(view);
	while (rseq <= rcount || lseq <= lcount) {
		if (rseq <= rcount)
			ruid = imapc_msgmap_rseq_to_uid(msgmap, rseq);
		else
			ruid = (uint32_t)-1;
		if (lseq <= lcount)
			mail_index_lookup_uid(view, lseq, &luid);
		else
			luid = (uint32_t)-1;

		if (ruid == luid) {
			/* message exists in index and in remote server */
			lseq++; rseq++;
		} else if (luid < ruid) {
			/* message exists in index but not in remote server */
			if (luid >= ctx->mbox->sync_uid_next) {
				/* the message was added to index by another
				   imapc session, and it's not visible yet
				   in this session */
				break;
			}
			/* it's already expunged and we should have marked it */
			i_assert(mail_index_is_expunged(view, lseq));
			lseq++;
		} else {
			/* message doesn't exist in index, but exists in
			   remote server */
			if (lseq > lcount && ruid >= hdr->next_uid) {
				/* the message hasn't been yet added to index */
				break;
			}

			/* another imapc session expunged it =>
			   NOOP should send us an EXPUNGE event */
			if (!nooped) {
				imapc_mailbox_noop(ctx->mbox);
				imapc_initial_sync_check(ctx, TRUE);
				return;
			}
			/* already nooped => index is corrupted */
			imapc_mailbox_set_corrupted(ctx->mbox,
				"Expunged message uid=%u reappeared", ruid);
			ctx->failed = TRUE;
			rseq++;
		}
	}
}

static void imapc_sync_index(struct imapc_sync_context *ctx)
{
	struct imapc_mailbox *mbox = ctx->mbox;
	struct mail_index_sync_rec sync_rec;
	uint32_t seq1, seq2;

	i_array_init(&ctx->expunged_uids, 64);
	ctx->keywords = mail_index_get_keywords(mbox->box.index);

	imapc_sync_uid_validity(ctx);
	while (mail_index_sync_next(ctx->index_sync_ctx, &sync_rec)) T_BEGIN {
		if (!mail_index_lookup_seq_range(ctx->sync_view,
						 sync_rec.uid1, sync_rec.uid2,
						 &seq1, &seq2)) {
			/* already expunged, nothing to do. */
		} else switch (sync_rec.type) {
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
		}
	} T_END;

	if (!mbox->initial_sync_done) {
		/* with initial syncing we're fetching all messages' flags and
		   expunge mails from local index that no longer exist on
		   remote server */
		i_assert(mbox->sync_fetch_first_uid == 1);
		mbox->sync_next_lseq = 1;
		mbox->sync_next_rseq = 1;
	}
	if (mbox->sync_fetch_first_uid != 0) {
		/* we'll resync existing messages' flags and add new messages.
		   adding new messages requires sync locking to avoid
		   duplicates. */
		imapc_sync_cmd(ctx, t_strdup_printf(
			"UID FETCH %u:* FLAGS", mbox->sync_fetch_first_uid));
		mbox->sync_fetch_first_uid = 0;
	}

	imapc_sync_expunge_finish(ctx);
	while (ctx->sync_command_count > 0)
		imapc_storage_run(mbox->storage);
	array_free(&ctx->expunged_uids);

	/* add uidnext after all appends */
	imapc_sync_uid_next(ctx);

	if (!ctx->failed)
		imapc_sync_expunge_eom(ctx);
	if (mbox->box.v.sync_notify != NULL)
		mbox->box.v.sync_notify(&mbox->box, 0, 0);

	if (!mbox->initial_sync_done) {
		if (!ctx->failed)
			imapc_initial_sync_check(ctx, FALSE);
		mbox->initial_sync_done = TRUE;
	}
}

void imapc_sync_mailbox_reopened(struct imapc_mailbox *mbox)
{
	struct imapc_sync_context *ctx = mbox->sync_ctx;

	i_assert(mbox->syncing);

	/* we got disconnected while syncing. need to
	   re-fetch everything */
	mbox->sync_next_lseq = 1;
	mbox->sync_next_rseq = 1;

	imapc_sync_cmd(ctx, "UID FETCH 1:* FLAGS");
}

static int
imapc_sync_begin(struct imapc_mailbox *mbox,
		 struct imapc_sync_context **ctx_r, bool force)
{
	struct imapc_sync_context *ctx;
	enum mail_index_sync_flags sync_flags;
	int ret;

	i_assert(!mbox->syncing);

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
			mailbox_set_index_error(&mbox->box);
		i_free(ctx);
		*ctx_r = NULL;
		return ret;
	}

	i_assert(mbox->delayed_sync_trans == NULL);
	mbox->sync_view = ctx->sync_view;
	mbox->delayed_sync_view =
		mail_index_transaction_open_updated_view(ctx->trans);
	mbox->delayed_sync_trans = ctx->trans;
	mbox->min_append_uid = mail_index_get_header(ctx->sync_view)->next_uid;

	mbox->syncing = TRUE;
	mbox->sync_ctx = ctx;
	if (!mbox->box.deleting)
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
	bool changes;
	int ret = ctx->failed ? -1 : 0;

	*_ctx = NULL;
	if (ret == 0) {
		if (mail_index_sync_commit(&ctx->index_sync_ctx) < 0) {
			mailbox_set_index_error(&ctx->mbox->box);
			ret = -1;
		}
	} else {
		mail_index_sync_rollback(&ctx->index_sync_ctx);
	}
	ctx->mbox->syncing = FALSE;
	ctx->mbox->sync_ctx = NULL;

	/* this is done simply to commit delayed expunges if there are any
	   (has to be done after sync is committed) */
	if (imapc_mailbox_commit_delayed_trans(ctx->mbox, &changes) < 0)
		ctx->failed = TRUE;

	i_free(ctx);
	return ret;
}

static int imapc_sync(struct imapc_mailbox *mbox)
{
	struct imapc_sync_context *sync_ctx;
	bool force = mbox->sync_fetch_first_uid != 0;

	if (imapc_sync_begin(mbox, &sync_ctx, force) < 0)
		return -1;
	if (sync_ctx == NULL)
		return 0;
	if (imapc_sync_finish(&sync_ctx) < 0)
		return -1;
	return 0;
}

struct mailbox_sync_context *
imapc_mailbox_sync_init(struct mailbox *box, enum mailbox_sync_flags flags)
{
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)box;
	enum imapc_capability capabilities;
	bool changes;
	int ret = 0;

	if (!box->opened) {
		if (mailbox_open(box) < 0)
			ret = -1;
	}

	capabilities = imapc_client_get_capabilities(mbox->storage->client->client);
	if ((capabilities & IMAPC_CAPABILITY_IDLE) == 0) {
		/* IDLE not supported. do NOOP to get latest changes
		   before starting sync. */
		imapc_mailbox_noop(mbox);
	}

	if (imapc_mailbox_commit_delayed_trans(mbox, &changes) < 0)
		ret = -1;
	if ((changes || mbox->sync_fetch_first_uid != 0 ||
	     index_mailbox_want_full_sync(&mbox->box, flags)) &&
	    ret == 0)
		ret = imapc_sync(mbox);

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
