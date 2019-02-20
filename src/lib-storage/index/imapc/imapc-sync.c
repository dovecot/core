/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "hash.h"
#include "str.h"
#include "sort.h"
#include "imap-util.h"
#include "mail-cache.h"
#include "mail-index-modseq.h"
#include "index-sync-private.h"
#include "imapc-msgmap.h"
#include "imapc-list.h"
#include "imapc-storage.h"
#include "imapc-sync.h"

struct imapc_sync_command {
	struct imapc_sync_context *ctx;
	char *cmd_str;
	bool ignore_no;
};

static void imapc_sync_callback(const struct imapc_command_reply *reply,
				void *context)
{
	struct imapc_sync_command *cmd = context;
	struct imapc_sync_context *ctx = cmd->ctx;

	i_assert(ctx->sync_command_count > 0);

	if (reply->state == IMAPC_COMMAND_STATE_OK)
		;
	else if (reply->state == IMAPC_COMMAND_STATE_NO && cmd->ignore_no) {
		/* maybe the message was expunged already.
		   some servers fail STOREs with NO in such situation. */
	} else if (reply->state == IMAPC_COMMAND_STATE_DISCONNECTED) {
		/* the disconnection is already logged, don't flood
		   the logs unnecessarily */
		mail_storage_set_internal_error(&ctx->mbox->storage->storage);
		ctx->failed = TRUE;
	} else {
		mailbox_set_critical(&ctx->mbox->box,
				     "imapc: Sync command '%s' failed: %s",
				     cmd->cmd_str, reply->text_full);
		ctx->failed = TRUE;
	}
	
	if (--ctx->sync_command_count == 0)
		imapc_client_stop(ctx->mbox->storage->client->client);
	i_free(cmd->cmd_str);
	i_free(cmd);
}

static struct imapc_command *
imapc_sync_cmd_full(struct imapc_sync_context *ctx, const char *cmd_str,
		    bool ignore_no)
{
	struct imapc_sync_command *sync_cmd;
	struct imapc_command *cmd;

	sync_cmd = i_new(struct imapc_sync_command, 1);
	sync_cmd->ctx = ctx;
	sync_cmd->cmd_str = i_strdup(cmd_str);
	sync_cmd->ignore_no = ignore_no;

	ctx->sync_command_count++;
	cmd = imapc_client_mailbox_cmd(ctx->mbox->client_box,
				       imapc_sync_callback, sync_cmd);
	imapc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_RETRIABLE);
	imapc_command_send(cmd, cmd_str);
	return cmd;
}

static struct imapc_command *
imapc_sync_cmd(struct imapc_sync_context *ctx, const char *cmd_str)
{
	return imapc_sync_cmd_full(ctx, cmd_str, FALSE);
}

static unsigned int imapc_sync_store_hash(const struct imapc_sync_store *store)
{
	return str_hash(store->flags) ^ store->modify_type;
}

static int imapc_sync_store_cmp(const struct imapc_sync_store *store1,
				const struct imapc_sync_store *store2)
{
	if (store1->modify_type != store2->modify_type)
		return 1;
	return strcmp(store1->flags, store2->flags);
}

static const char *imapc_sync_flags_sort(const char *flags)
{
	if (strchr(flags, ' ') == NULL)
		return flags;

	const char **str = t_strsplit(flags, " ");
	i_qsort(str, str_array_length(str), sizeof(const char *),
		i_strcasecmp_p);
	return t_strarray_join(str, " ");
}

static void
imapc_sync_store_flush(struct imapc_sync_context *ctx)
{
	struct imapc_sync_store *store;
	const char *sorted_flags;

	if (ctx->prev_uid1 == 0)
		return;

	sorted_flags = imapc_sync_flags_sort(str_c(ctx->prev_flags));
	struct imapc_sync_store store_lookup = {
		.modify_type = ctx->prev_modify_type,
		.flags = sorted_flags,
	};
	store = hash_table_lookup(ctx->stores, &store_lookup);
	if (store == NULL) {
		store = p_new(ctx->pool, struct imapc_sync_store, 1);
		store->modify_type = ctx->prev_modify_type;
		store->flags = p_strdup(ctx->pool, sorted_flags);
		p_array_init(&store->uids, ctx->pool, 4);
		hash_table_insert(ctx->stores, store, store);
	}
	seq_range_array_add_range(&store->uids, ctx->prev_uid1, ctx->prev_uid2);
}

static void
imapc_sync_store(struct imapc_sync_context *ctx,
		 enum modify_type modify_type, uint32_t uid1, uint32_t uid2,
		 const char *flags)
{
	if (ctx->prev_flags == NULL) {
		ctx->prev_flags = str_new(ctx->pool, 128);
		hash_table_create(&ctx->stores, ctx->pool, 0,
				  imapc_sync_store_hash, imapc_sync_store_cmp);
	}

	if (ctx->prev_uid1 != uid1 || ctx->prev_uid2 != uid2 ||
	    ctx->prev_modify_type != modify_type) {
		imapc_sync_store_flush(ctx);
		ctx->prev_uid1 = uid1;
		ctx->prev_uid2 = uid2;
		ctx->prev_modify_type = modify_type;
		str_truncate(ctx->prev_flags, 0);
	}
	if (str_len(ctx->prev_flags) > 0)
		str_append_c(ctx->prev_flags, ' ');
	str_append(ctx->prev_flags, flags);
}

static void
imapc_sync_finish_store(struct imapc_sync_context *ctx)
{
	struct hash_iterate_context *iter;
	struct imapc_sync_store *store;
	string_t *cmd = t_str_new(128);

	imapc_sync_store_flush(ctx);

	if (!hash_table_is_created(ctx->stores))
		return;

	iter = hash_table_iterate_init(ctx->stores);
	while (hash_table_iterate(iter, ctx->stores, &store, &store)) {
		str_truncate(cmd, 0);
		str_append(cmd, "UID STORE ");
		imap_write_seq_range(cmd, &store->uids);
		str_printfa(cmd, " %cFLAGS (%s)",
			    store->modify_type == MODIFY_ADD ? '+' : '-',
			    store->flags);
		imapc_sync_cmd_full(ctx, str_c(cmd), TRUE);
	}
	hash_table_iterate_deinit(&iter);
	hash_table_destroy(&ctx->stores);
}

static void
imapc_sync_add_missing_deleted_flags(struct imapc_sync_context *ctx,
				     uint32_t seq1, uint32_t seq2)
{
	const struct mail_index_record *rec;
	uint32_t seq, uid1, uid2;

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

		imapc_sync_store(ctx, MODIFY_ADD, uid1, uid2, "\\Deleted");
	}
}

static void imapc_sync_index_flags(struct imapc_sync_context *ctx,
				   const struct mail_index_sync_rec *sync_rec)
{
	string_t *str = t_str_new(128);

	i_assert(sync_rec->type == MAIL_INDEX_SYNC_TYPE_FLAGS);

	if (sync_rec->add_flags != 0) {
		i_assert((sync_rec->add_flags & MAIL_RECENT) == 0);

		imap_write_flags(str, sync_rec->add_flags, NULL);
		imapc_sync_store(ctx, MODIFY_ADD, sync_rec->uid1,
				 sync_rec->uid2, str_c(str));
	}

	if (sync_rec->remove_flags != 0) {
		i_assert((sync_rec->remove_flags & MAIL_RECENT) == 0);
		str_truncate(str, 0);
		imap_write_flags(str, sync_rec->remove_flags, NULL);
		imapc_sync_store(ctx, MODIFY_REMOVE, sync_rec->uid1,
				 sync_rec->uid2, str_c(str));
	}
}

static void
imapc_sync_index_keyword(struct imapc_sync_context *ctx,
			 const struct mail_index_sync_rec *sync_rec)
{
	const char *const *kw_p;
	enum modify_type modify_type;

	switch (sync_rec->type) {
	case MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD:
		modify_type = MODIFY_ADD;
		break;
	case MAIL_INDEX_SYNC_TYPE_KEYWORD_REMOVE:
		modify_type = MODIFY_REMOVE;
		break;
	default:
		i_unreached();
	}

	kw_p = array_idx(ctx->keywords, sync_rec->keyword_idx);
	imapc_sync_store(ctx, modify_type, sync_rec->uid1,
			 sync_rec->uid2, *kw_p);
}

static void imapc_sync_expunge_finish(struct imapc_sync_context *ctx)
{
	string_t *str;

	if (array_count(&ctx->expunged_uids) == 0)
		return;

	if ((ctx->mbox->capabilities & IMAPC_CAPABILITY_UIDPLUS) == 0) {
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

static void imapc_sync_highestmodseq(struct imapc_sync_context *ctx)
{
	if (imapc_mailbox_has_modseqs(ctx->mbox) &&
	    mail_index_modseq_get_highest(ctx->sync_view) < ctx->mbox->sync_highestmodseq)
		mail_index_update_highest_modseq(ctx->trans, ctx->mbox->sync_highestmodseq);
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
			i_assert(mail_index_is_expunged(view, lseq) ||
				 seq_range_exists(&ctx->mbox->delayed_expunged_uids, luid));
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
			return;
		}
	}
}

static void
imapc_sync_send_commands(struct imapc_sync_context *ctx)
{
	if (ctx->mbox->exists_count == 0) {
		/* empty mailbox - no point in fetching anything */
		return;
	}

	if (IMAPC_BOX_HAS_FEATURE(ctx->mbox, IMAPC_FEATURE_GMAIL_MIGRATION) &&
	    ctx->mbox->storage->set->pop3_deleted_flag[0] != '\0') {
		struct imapc_command *cmd;

		cmd = imapc_sync_cmd(ctx, "SEARCH RETURN (ALL) X-GM-RAW \"in:^pop\"");
		i_free(ctx->mbox->sync_gmail_pop3_search_tag);
		ctx->mbox->sync_gmail_pop3_search_tag =
			i_strdup(imapc_command_get_tag(cmd));
	}
}

static void imapc_sync_index(struct imapc_sync_context *ctx)
{
	struct imapc_mailbox *mbox = ctx->mbox;
	struct mail_index_sync_rec sync_rec;
	uint32_t seq1, seq2;

	i_array_init(&ctx->expunged_uids, 64);
	ctx->keywords = mail_index_get_keywords(mbox->box.index);
	ctx->pool = pool_alloconly_create("imapc sync pool", 1024);

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
	imapc_sync_finish_store(ctx);
	pool_unref(&ctx->pool);

	if (!mbox->initial_sync_done)
		imapc_sync_send_commands(ctx);

	imapc_sync_expunge_finish(ctx);
	while (ctx->sync_command_count > 0)
		imapc_mailbox_run(mbox);
	array_free(&ctx->expunged_uids);

	if (!mbox->state_fetched_success) {
		/* All the sync commands succeeded, but we got disconnected.
		   imapc_initial_sync_check() will crash if we go there. */
		ctx->failed = TRUE;
	}

	/* add uidnext & highestmodseq after all appends */
	imapc_sync_uid_next(ctx);
	imapc_sync_highestmodseq(ctx);

	if (mbox->box.v.sync_notify != NULL)
		mbox->box.v.sync_notify(&mbox->box, 0, 0);

	if (!ctx->failed) {
		/* reset only after a successful sync */
		mbox->sync_fetch_first_uid = 0;
	}
	if (!mbox->initial_sync_done && !ctx->failed) {
		imapc_initial_sync_check(ctx, FALSE);
		mbox->initial_sync_done = TRUE;
	}
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

	i_assert(mbox->sync_view == NULL);
	i_assert(mbox->delayed_sync_trans == NULL);
	mbox->sync_view = ctx->sync_view;
	mbox->delayed_sync_view =
		mail_index_transaction_open_updated_view(ctx->trans);
	mbox->delayed_sync_trans = ctx->trans;
	mbox->delayed_sync_cache_view =
		mail_cache_view_open(mbox->box.cache, mbox->delayed_sync_view);
	mbox->delayed_sync_cache_trans =
		mail_cache_get_transaction(mbox->delayed_sync_cache_view,
					   mbox->delayed_sync_trans);
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
	/* Commit the transaction even if we failed. This is important, because
	   during the sync delayed_sync_trans points to the sync transaction.
	   Even if the syncing doesn't fully succeed, we don't want to lose
	   changes in delayed_sync_trans. */
	if (mail_index_sync_commit(&ctx->index_sync_ctx) < 0) {
		mailbox_set_index_error(&ctx->mbox->box);
		ret = -1;
	}
	if (ctx->mbox->sync_gmail_pop3_search_tag != NULL) {
		mailbox_set_critical(&ctx->mbox->box,
			"gmail-pop3 search not successful");
		i_free_and_null(ctx->mbox->sync_gmail_pop3_search_tag);
		ret = -1;
	}
	mail_cache_view_close(&ctx->mbox->delayed_sync_cache_view);
	ctx->mbox->delayed_sync_cache_trans = NULL;

	ctx->mbox->syncing = FALSE;
	ctx->mbox->sync_ctx = NULL;

	/* this is done simply to commit delayed expunges if there are any
	   (has to be done after sync is committed) */
	if (imapc_mailbox_commit_delayed_trans(ctx->mbox, FALSE, &changes) < 0)
		ctx->failed = TRUE;

	i_free(ctx);
	return ret;
}

static int imapc_sync(struct imapc_mailbox *mbox)
{
	struct imapc_sync_context *sync_ctx;
	bool force = mbox->sync_fetch_first_uid != 0;

	if ((mbox->box.flags & MAILBOX_FLAG_SAVEONLY) != 0) {
		/* we're only saving mails here - no syncing actually wanted */
		return 0;
	}

	if (imapc_sync_begin(mbox, &sync_ctx, force) < 0)
		return -1;
	if (sync_ctx == NULL)
		return 0;
	if (imapc_sync_finish(&sync_ctx) < 0)
		return -1;
	return 0;
}

static void
imapc_noop_if_needed(struct imapc_mailbox *mbox, enum mailbox_sync_flags flags)
{
	if (!mbox->initial_sync_done) {
		/* we just SELECTed/EXAMINEd the mailbox, don't do another
		   NOOP. */
	} else if ((flags & MAILBOX_SYNC_FLAG_FAST) == 0 &&
		   ((mbox->capabilities & IMAPC_CAPABILITY_IDLE) == 0 ||
		    (flags & MAILBOX_SYNC_FLAG_FULL_READ) != 0)) {
		/* do NOOP to make sure we have the latest changes before
		   starting sync. this is necessary either because se don't
		   support IDLE at all, or because we want to be sure that we
		   have the latest changes (IDLE is started with a small delay,
		   so we might not actually even be in IDLE right not) */
		imapc_mailbox_noop(mbox);
	}
}

struct mailbox_sync_context *
imapc_mailbox_sync_init(struct mailbox *box, enum mailbox_sync_flags flags)
{
	struct imapc_mailbox *mbox = IMAPC_MAILBOX(box);
	struct imapc_mailbox_list *list = mbox->storage->client->_list;
	bool changes;
	int ret = 0;

	if (list != NULL) {
		if (!list->refreshed_mailboxes &&
		    list->last_refreshed_mailboxes < ioloop_time)
			list->refreshed_mailboxes_recently = FALSE;
	}

	imapc_noop_if_needed(mbox, flags);

	if (imapc_storage_client_handle_auth_failure(mbox->storage->client))
		ret = -1;
	else if (!mbox->state_fetched_success && !mbox->state_fetching_uid1 &&
		 !mbox->box.deleting) {
		/* initial FETCH failed already */
		ret = -1;
	}
	if (imapc_mailbox_commit_delayed_trans(mbox, FALSE, &changes) < 0)
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
	struct imapc_mailbox *mbox = IMAPC_MAILBOX(ctx->box);
	int ret;

	ret = index_mailbox_sync_deinit(ctx, status_r);
	ctx = NULL;

	if (mbox->client_box == NULL)
		return ret;

	imapc_client_mailbox_idle(mbox->client_box);
	return ret;
}
