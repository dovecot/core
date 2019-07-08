/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-index-view-private.h"
#include "mail-index-sync-private.h"
#include "mail-index-transaction-private.h"
#include "mail-transaction-log-private.h"
#include "mail-cache-private.h"

#include <stdio.h>

struct mail_index_sync_ctx {
	struct mail_index *index;
	struct mail_index_view *view;
	struct mail_index_transaction *sync_trans, *ext_trans;
	struct mail_index_transaction_commit_result *sync_commit_result;
	enum mail_index_sync_flags flags;
	char *reason;

	const struct mail_transaction_header *hdr;
	const void *data;

	ARRAY(struct mail_index_sync_list) sync_list;
	uint32_t next_uid;

	bool no_warning:1;
	bool seen_external_expunges:1;
	bool seen_nonexternal_transactions:1;
	bool fully_synced:1;
};

static void mail_index_sync_add_expunge(struct mail_index_sync_ctx *ctx)
{
	const struct mail_transaction_expunge *e = ctx->data;
	size_t i, size = ctx->hdr->size / sizeof(*e);
	uint32_t uid;

	for (i = 0; i < size; i++) {
		for (uid = e[i].uid1; uid <= e[i].uid2; uid++)
			mail_index_expunge(ctx->sync_trans, uid);
	}
}

static void mail_index_sync_add_expunge_guid(struct mail_index_sync_ctx *ctx)
{
	const struct mail_transaction_expunge_guid *e = ctx->data;
	size_t i, size = ctx->hdr->size / sizeof(*e);

	for (i = 0; i < size; i++) {
		mail_index_expunge_guid(ctx->sync_trans, e[i].uid,
					e[i].guid_128);
	}
}

static void mail_index_sync_add_flag_update(struct mail_index_sync_ctx *ctx)
{
	const struct mail_transaction_flag_update *u = ctx->data;
	size_t i, size = ctx->hdr->size / sizeof(*u);

	for (i = 0; i < size; i++) {
		if (u[i].add_flags != 0) {
			mail_index_update_flags_range(ctx->sync_trans,
						      u[i].uid1, u[i].uid2,
						      MODIFY_ADD,
						      u[i].add_flags);
		}
		if (u[i].remove_flags != 0) {
			mail_index_update_flags_range(ctx->sync_trans,
						      u[i].uid1, u[i].uid2,
						      MODIFY_REMOVE,
						      u[i].remove_flags);
		}
	}
}

static void mail_index_sync_add_keyword_update(struct mail_index_sync_ctx *ctx)
{
	const struct mail_transaction_keyword_update *u = ctx->data;
	const char *keyword_names[2];
	struct mail_keywords *keywords;
	const uint32_t *uids;
	uint32_t uid;
	size_t uidset_offset, i, size;

	i_assert(u->name_size > 0);

	uidset_offset = sizeof(*u) + u->name_size;
	if ((uidset_offset % 4) != 0)
		uidset_offset += 4 - (uidset_offset % 4);
	uids = CONST_PTR_OFFSET(u, uidset_offset);

	keyword_names[0] = t_strndup(u + 1, u->name_size);
	keyword_names[1] = NULL;
	keywords = mail_index_keywords_create(ctx->index, keyword_names);

	size = (ctx->hdr->size - uidset_offset) / sizeof(uint32_t);
	for (i = 0; i < size; i += 2) {
		/* FIXME: mail_index_update_keywords_range() */
		for (uid = uids[i]; uid <= uids[i+1]; uid++) {
			mail_index_update_keywords(ctx->sync_trans, uid,
						   u->modify_type, keywords);
		}
	}

	mail_index_keywords_unref(&keywords);
}

static void mail_index_sync_add_keyword_reset(struct mail_index_sync_ctx *ctx)
{
	const struct mail_transaction_keyword_reset *u = ctx->data;
	size_t i, size = ctx->hdr->size / sizeof(*u);
	struct mail_keywords *keywords;
	uint32_t uid;

	keywords = mail_index_keywords_create(ctx->index, NULL);
	for (i = 0; i < size; i++) {
		for (uid = u[i].uid1; uid <= u[i].uid2; uid++) {
			mail_index_update_keywords(ctx->sync_trans, uid,
						   MODIFY_REPLACE, keywords);
		}
	}
	mail_index_keywords_unref(&keywords);
}

static bool mail_index_sync_add_transaction(struct mail_index_sync_ctx *ctx)
{
	switch (ctx->hdr->type & MAIL_TRANSACTION_TYPE_MASK) {
	case MAIL_TRANSACTION_EXPUNGE:
		mail_index_sync_add_expunge(ctx);
		break;
	case MAIL_TRANSACTION_EXPUNGE_GUID:
		mail_index_sync_add_expunge_guid(ctx);
		break;
	case MAIL_TRANSACTION_FLAG_UPDATE:
                mail_index_sync_add_flag_update(ctx);
		break;
	case MAIL_TRANSACTION_KEYWORD_UPDATE:
                mail_index_sync_add_keyword_update(ctx);
		break;
	case MAIL_TRANSACTION_KEYWORD_RESET:
                mail_index_sync_add_keyword_reset(ctx);
		break;
	default:
		return FALSE;
	}
	return TRUE;
}

static void mail_index_sync_add_dirty_updates(struct mail_index_sync_ctx *ctx)
{
	struct mail_transaction_flag_update update;
	const struct mail_index_record *rec;
	uint32_t seq, messages_count;

	i_zero(&update);

	messages_count = mail_index_view_get_messages_count(ctx->view);
	for (seq = 1; seq <= messages_count; seq++) {
		rec = mail_index_lookup(ctx->view, seq);
		if ((rec->flags & MAIL_INDEX_MAIL_FLAG_DIRTY) == 0)
			continue;

		mail_index_update_flags(ctx->sync_trans, rec->uid,
					MODIFY_REPLACE, rec->flags);
	}
}

static int
mail_index_sync_read_and_sort(struct mail_index_sync_ctx *ctx)
{
	struct mail_index_transaction *sync_trans = ctx->sync_trans;
	struct mail_index_sync_list *synclist;
        const struct mail_index_transaction_keyword_update *keyword_updates;
	unsigned int i, keyword_count;
	int ret;

	if ((ctx->view->map->hdr.flags & MAIL_INDEX_HDR_FLAG_HAVE_DIRTY) != 0 &&
	    (ctx->flags & MAIL_INDEX_SYNC_FLAG_FLUSH_DIRTY) != 0 &&
	    (ctx->view->index->flags & MAIL_INDEX_OPEN_FLAG_NO_DIRTY) == 0) {
		/* show dirty flags as flag updates */
		mail_index_sync_add_dirty_updates(ctx);
	}

	/* read all transactions from log into a transaction in memory.
	   skip the external ones, they're already synced to mailbox and
	   included in our view */
	while ((ret = mail_transaction_log_view_next(ctx->view->log_view,
						     &ctx->hdr,
						     &ctx->data)) > 0) {
		if ((ctx->hdr->type & MAIL_TRANSACTION_EXTERNAL) != 0) {
			if ((ctx->hdr->type & (MAIL_TRANSACTION_EXPUNGE |
					       MAIL_TRANSACTION_EXPUNGE_GUID)) != 0)
				ctx->seen_external_expunges = TRUE;
			continue;
		}

		T_BEGIN {
			if (mail_index_sync_add_transaction(ctx)) {
				/* update tail_offset if needed */
				ctx->seen_nonexternal_transactions = TRUE;
			} else {
				/* this is an internal change. we don't
				   necessarily need to update tail_offset, so
				   avoid the extra write caused by it. */
			}
		} T_END;
	}

	/* create an array containing all expunge, flag and keyword update
	   arrays so we can easily go through all of the changes. */
	keyword_count = !array_is_created(&sync_trans->keyword_updates) ? 0 :
		array_count(&sync_trans->keyword_updates);
	i_array_init(&ctx->sync_list, keyword_count + 2);

	if (array_is_created(&sync_trans->expunges)) {
		mail_index_transaction_sort_expunges(sync_trans);
		synclist = array_append_space(&ctx->sync_list);
		synclist->array = (void *)&sync_trans->expunges;
	}

	if (array_is_created(&sync_trans->updates)) {
		synclist = array_append_space(&ctx->sync_list);
		synclist->array = (void *)&sync_trans->updates;
	}

	keyword_updates = keyword_count == 0 ? NULL :
		array_front(&sync_trans->keyword_updates);
	for (i = 0; i < keyword_count; i++) {
		if (array_is_created(&keyword_updates[i].add_seq)) {
			synclist = array_append_space(&ctx->sync_list);
			synclist->array =
				(const void *)&keyword_updates[i].add_seq;
			synclist->keyword_idx = i;
		}
		if (array_is_created(&keyword_updates[i].remove_seq)) {
			synclist = array_append_space(&ctx->sync_list);
			synclist->array =
				(const void *)&keyword_updates[i].remove_seq;
			synclist->keyword_idx = i;
			synclist->keyword_remove = TRUE;
		}
	}

	return ret;
}

static bool
mail_index_need_sync(struct mail_index *index, enum mail_index_sync_flags flags,
		     uint32_t log_file_seq, uoff_t log_file_offset)
{
	const struct mail_index_header *hdr = &index->map->hdr;
	if ((flags & MAIL_INDEX_SYNC_FLAG_REQUIRE_CHANGES) == 0)
		return TRUE;

	/* sync only if there's something to do */
	if (hdr->first_recent_uid < hdr->next_uid &&
	    (flags & MAIL_INDEX_SYNC_FLAG_DROP_RECENT) != 0)
		return TRUE;

	if ((hdr->flags & MAIL_INDEX_HDR_FLAG_HAVE_DIRTY) != 0 &&
	    (flags & MAIL_INDEX_SYNC_FLAG_FLUSH_DIRTY) != 0 &&
	    (index->flags & MAIL_INDEX_OPEN_FLAG_NO_DIRTY) == 0)
		return TRUE;

	if (log_file_seq == (uint32_t)-1) {
		/* we want to sync up to transaction log's head */
		mail_transaction_log_get_head(index->log,
					      &log_file_seq, &log_file_offset);
	}
	if ((hdr->log_file_tail_offset < log_file_offset &&
	     hdr->log_file_seq == log_file_seq) ||
	    hdr->log_file_seq < log_file_seq)
		return TRUE;

	if (index->need_recreate)
		return TRUE;

	/* already synced */
	return mail_cache_need_compress(index->cache);
}

static int
mail_index_sync_set_log_view(struct mail_index_view *view,
			     uint32_t start_file_seq, uoff_t start_file_offset)
{
	uint32_t log_seq;
	uoff_t log_offset;
	const char *reason;
	bool reset;
	int ret;

	mail_transaction_log_get_head(view->index->log, &log_seq, &log_offset);

	ret = mail_transaction_log_view_set(view->log_view,
                                            start_file_seq, start_file_offset,
					    log_seq, log_offset, &reset, &reason);
	if (ret < 0)
		return -1;
	if (ret == 0) {
		/* either corrupted or the file was deleted for
		   some reason. either way, we can't go forward */
		mail_index_set_error(view->index,
			"Unexpected transaction log desync with index %s: %s",
			view->index->filepath, reason);
		return 0;
	}
	return 1;
}

int mail_index_sync_begin(struct mail_index *index,
			  struct mail_index_sync_ctx **ctx_r,
			  struct mail_index_view **view_r,
			  struct mail_index_transaction **trans_r,
			  enum mail_index_sync_flags flags)
{
	int ret;

	ret = mail_index_sync_begin_to(index, ctx_r, view_r, trans_r,
				       (uint32_t)-1, (uoff_t)-1, flags);
	i_assert(ret != 0 ||
		 (flags & MAIL_INDEX_SYNC_FLAG_REQUIRE_CHANGES) != 0);
	return ret;
}

static int
mail_index_sync_begin_init(struct mail_index *index,
			   enum mail_index_sync_flags flags,
			   uint32_t log_file_seq, uoff_t log_file_offset)
{
	const struct mail_index_header *hdr;
	uint32_t seq;
	uoff_t offset;
	bool locked = FALSE;
	int ret;

	/* if we require changes, don't lock transaction log yet. first check
	   if there's anything to sync. */
	if ((flags & MAIL_INDEX_SYNC_FLAG_REQUIRE_CHANGES) == 0) {
		if (mail_transaction_log_sync_lock(index->log, "syncing",
						   &seq, &offset) < 0)
			return -1;
		locked = TRUE;
	}

	/* The view must contain what we expect the mailbox to look like
	   currently. That allows the backend to update external flag
	   changes (etc.) if the view doesn't match the mailbox.

	   We'll update the view to contain everything that exist in the
	   transaction log except for expunges. They're synced in
	   mail_index_sync_commit(). */
	if ((ret = mail_index_map(index, MAIL_INDEX_SYNC_HANDLER_HEAD)) <= 0) {
		if (ret == 0) {
			if (locked)
				mail_transaction_log_sync_unlock(index->log, "sync init failure");
			return -1;
		}

		/* let's try again */
		if (mail_index_map(index, MAIL_INDEX_SYNC_HANDLER_HEAD) <= 0) {
			if (locked)
				mail_transaction_log_sync_unlock(index->log, "sync init failure");
			return -1;
		}
	}

	if (!mail_index_need_sync(index, flags, log_file_seq, log_file_offset) &&
	    !index->index_deleted && !index->need_recreate) {
		if (locked)
			mail_transaction_log_sync_unlock(index->log, "syncing determined unnecessary");
		return 0;
	}

	if (!locked) {
		/* it looks like we have something to sync. lock the file and
		   check again. */
		flags &= ~MAIL_INDEX_SYNC_FLAG_REQUIRE_CHANGES;
		return mail_index_sync_begin_init(index, flags, log_file_seq,
						  log_file_offset);
	}

	if (index->index_deleted &&
	    (flags & MAIL_INDEX_SYNC_FLAG_DELETING_INDEX) == 0) {
		/* index is already deleted. we can't sync. */
		if (locked)
			mail_transaction_log_sync_unlock(index->log, "syncing detected deleted index");
		return -1;
	}

	hdr = &index->map->hdr;
	if (hdr->log_file_tail_offset > hdr->log_file_head_offset ||
	    hdr->log_file_seq > seq ||
	    (hdr->log_file_seq == seq && hdr->log_file_tail_offset > offset)) {
		/* broken sync positions. fix them. */
		mail_index_set_error(index,
			"broken sync positions in index file %s",
			index->filepath);
		mail_index_fsck_locked(index);
	}
	return 1;
}

static int
mail_index_sync_begin_to2(struct mail_index *index,
			  struct mail_index_sync_ctx **ctx_r,
			  struct mail_index_view **view_r,
			  struct mail_index_transaction **trans_r,
			  uint32_t log_file_seq, uoff_t log_file_offset,
			  enum mail_index_sync_flags flags, bool *retry_r)
{
	const struct mail_index_header *hdr;
	struct mail_index_sync_ctx *ctx;
	struct mail_index_view *sync_view;
	enum mail_index_transaction_flags trans_flags;
	int ret;

	i_assert(!index->syncing);

	*retry_r = FALSE;

	if (index->map != NULL &&
	    (index->map->hdr.flags & MAIL_INDEX_HDR_FLAG_CORRUPTED) != 0) {
		/* index is corrupted and need to be reopened */
		return -1;
	}

	if (log_file_seq != (uint32_t)-1)
		flags |= MAIL_INDEX_SYNC_FLAG_REQUIRE_CHANGES;

	ret = mail_index_sync_begin_init(index, flags, log_file_seq,
					 log_file_offset);
	if (ret <= 0)
		return ret;

	hdr = &index->map->hdr;

	ctx = i_new(struct mail_index_sync_ctx, 1);
	ctx->index = index;
	ctx->flags = flags;

	ctx->view = mail_index_view_open(index);

	sync_view = mail_index_dummy_view_open(index);
	ctx->sync_trans = mail_index_transaction_begin(sync_view,
					MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	mail_index_view_close(&sync_view);

	/* set before any rollbacks are called */
	index->syncing = TRUE;

	/* we wish to see all the changes from last mailbox sync position to
	   the end of the transaction log */
	ret = mail_index_sync_set_log_view(ctx->view, hdr->log_file_seq,
					   hdr->log_file_tail_offset);
	if (ret < 0) {
                mail_index_sync_rollback(&ctx);
		return -1;
	}
	if (ret == 0) {
		/* if a log file is missing, there's nothing we can do except
		   to skip over it. fix the problem with fsck and try again. */
		mail_index_fsck_locked(index);
		mail_index_sync_rollback(&ctx);
		*retry_r = TRUE;
		return 0;
	}

	/* we need to have all the transactions sorted to optimize
	   caller's mailbox access patterns */
	if (mail_index_sync_read_and_sort(ctx) < 0) {
                mail_index_sync_rollback(&ctx);
		return -1;
	}

	ctx->view->index_sync_view = TRUE;

	/* create the transaction after the view has been updated with
	   external transactions and marked as sync view */
	trans_flags = MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL;
	if ((ctx->flags & MAIL_INDEX_SYNC_FLAG_AVOID_FLAG_UPDATES) != 0)
		trans_flags |= MAIL_INDEX_TRANSACTION_FLAG_AVOID_FLAG_UPDATES;
	if ((ctx->flags & MAIL_INDEX_SYNC_FLAG_FSYNC) != 0)
		trans_flags |= MAIL_INDEX_TRANSACTION_FLAG_FSYNC;
	ctx->ext_trans = mail_index_transaction_begin(ctx->view, trans_flags);
	ctx->ext_trans->sync_transaction = TRUE;
	ctx->ext_trans->commit_deleted_index =
		(flags & (MAIL_INDEX_SYNC_FLAG_DELETING_INDEX |
			  MAIL_INDEX_SYNC_FLAG_TRY_DELETING_INDEX)) != 0;

	*ctx_r = ctx;
	*view_r = ctx->view;
	*trans_r = ctx->ext_trans;
	return 1;
}

int mail_index_sync_begin_to(struct mail_index *index,
			     struct mail_index_sync_ctx **ctx_r,
			     struct mail_index_view **view_r,
			     struct mail_index_transaction **trans_r,
			     uint32_t log_file_seq, uoff_t log_file_offset,
			     enum mail_index_sync_flags flags)
{
	bool retry;
	int ret;

	i_assert(index->open_count > 0);

	ret = mail_index_sync_begin_to2(index, ctx_r, view_r, trans_r,
					log_file_seq, log_file_offset,
					flags, &retry);
	if (retry) {
		ret = mail_index_sync_begin_to2(index, ctx_r, view_r, trans_r,
						log_file_seq, log_file_offset,
						flags, &retry);
	}
	return ret;
}

bool mail_index_sync_has_expunges(struct mail_index_sync_ctx *ctx)
{
	return array_is_created(&ctx->sync_trans->expunges) &&
		array_count(&ctx->sync_trans->expunges) > 0;
}

static bool mail_index_sync_view_have_any(struct mail_index_view *view,
					  enum mail_index_sync_flags flags,
					  bool expunges_only)
{
	const struct mail_transaction_header *hdr;
	const void *data;
	uint32_t log_seq;
	uoff_t log_offset;
	const char *reason;
	bool reset;
	int ret;

	if (view->map->hdr.first_recent_uid < view->map->hdr.next_uid &&
	    (flags & MAIL_INDEX_SYNC_FLAG_DROP_RECENT) != 0)
		return TRUE;

	if ((view->map->hdr.flags & MAIL_INDEX_HDR_FLAG_HAVE_DIRTY) != 0 &&
	    (flags & MAIL_INDEX_SYNC_FLAG_FLUSH_DIRTY) != 0 &&
	    (view->index->flags & MAIL_INDEX_OPEN_FLAG_NO_DIRTY) == 0)
		return TRUE;

	mail_transaction_log_get_head(view->index->log, &log_seq, &log_offset);
	if (mail_transaction_log_view_set(view->log_view,
					  view->map->hdr.log_file_seq,
					  view->map->hdr.log_file_tail_offset,
					  log_seq, log_offset,
					  &reset, &reason) <= 0) {
		/* let the actual syncing handle the error */
		return TRUE;
	}

	while ((ret = mail_transaction_log_view_next(view->log_view,
						     &hdr, &data)) > 0) {
		if ((hdr->type & MAIL_TRANSACTION_EXTERNAL) != 0)
			continue;

		switch (hdr->type & MAIL_TRANSACTION_TYPE_MASK) {
		case MAIL_TRANSACTION_EXPUNGE:
		case MAIL_TRANSACTION_EXPUNGE_GUID:
			return TRUE;
		case MAIL_TRANSACTION_EXT_REC_UPDATE:
		case MAIL_TRANSACTION_EXT_ATOMIC_INC:
			/* extension record updates aren't exactly needed
			   to be synced, but cache syncing relies on tail
			   offsets being updated. */
		case MAIL_TRANSACTION_FLAG_UPDATE:
		case MAIL_TRANSACTION_KEYWORD_UPDATE:
		case MAIL_TRANSACTION_KEYWORD_RESET:
		case MAIL_TRANSACTION_INDEX_DELETED:
		case MAIL_TRANSACTION_INDEX_UNDELETED:
			if (!expunges_only)
				return TRUE;
			break;
		default:
			break;
		}
	}
	return ret < 0;
}

bool mail_index_sync_have_any(struct mail_index *index,
			      enum mail_index_sync_flags flags)
{
	struct mail_index_view *view;
	bool ret;

	view = mail_index_view_open(index);
	ret = mail_index_sync_view_have_any(view, flags, FALSE);
	mail_index_view_close(&view);
	return ret;
}

bool mail_index_sync_have_any_expunges(struct mail_index *index)
{
	struct mail_index_view *view;
	bool ret;

	view = mail_index_view_open(index);
	ret = mail_index_sync_view_have_any(view, 0, TRUE);
	mail_index_view_close(&view);
	return ret;
}

void mail_index_sync_get_offsets(struct mail_index_sync_ctx *ctx,
				 uint32_t *seq1_r, uoff_t *offset1_r,
				 uint32_t *seq2_r, uoff_t *offset2_r)
{
	*seq1_r = ctx->view->map->hdr.log_file_seq;
	*offset1_r = ctx->view->map->hdr.log_file_tail_offset != 0 ?
		ctx->view->map->hdr.log_file_tail_offset :
		ctx->view->index->log->head->hdr.hdr_size;
	mail_transaction_log_get_head(ctx->view->index->log, seq2_r, offset2_r);
}

static void
mail_index_sync_get_expunge(struct mail_index_sync_rec *rec,
			    const struct mail_transaction_expunge_guid *exp)
{
	rec->type = MAIL_INDEX_SYNC_TYPE_EXPUNGE;
	rec->uid1 = exp->uid;
	rec->uid2 = exp->uid;
	memcpy(rec->guid_128, exp->guid_128, sizeof(rec->guid_128));
}

static void
mail_index_sync_get_update(struct mail_index_sync_rec *rec,
			   const struct mail_index_flag_update *update)
{
	rec->type = MAIL_INDEX_SYNC_TYPE_FLAGS;
	rec->uid1 = update->uid1;
	rec->uid2 = update->uid2;

	rec->add_flags = update->add_flags;
	rec->remove_flags = update->remove_flags;
}

static void
mail_index_sync_get_keyword_update(struct mail_index_sync_rec *rec,
				   const struct uid_range *range,
				   struct mail_index_sync_list *sync_list)
{
	rec->type = !sync_list->keyword_remove ?
		MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD :
		MAIL_INDEX_SYNC_TYPE_KEYWORD_REMOVE;
	rec->uid1 = range->uid1;
	rec->uid2 = range->uid2;
	rec->keyword_idx = sync_list->keyword_idx;
}

bool mail_index_sync_next(struct mail_index_sync_ctx *ctx,
			  struct mail_index_sync_rec *sync_rec)
{
	struct mail_index_transaction *sync_trans = ctx->sync_trans;
	struct mail_index_sync_list *sync_list;
	const struct uid_range *uid_range = NULL;
	unsigned int i, count, next_i;
	uint32_t next_found_uid;

	next_i = UINT_MAX;
	next_found_uid = (uint32_t)-1;

	/* FIXME: replace with a priority queue so we don't have to go
	   through the whole list constantly. and remember to make sure that
	   keyword resets are sent before adds! */
	/* FIXME: pretty ugly to do this for expunges, which isn't even a
	   seq_range. */
	sync_list = array_get_modifiable(&ctx->sync_list, &count);
	for (i = 0; i < count; i++) {
		if (!array_is_created(sync_list[i].array) ||
		    sync_list[i].idx == array_count(sync_list[i].array))
			continue;

		uid_range = array_idx(sync_list[i].array, sync_list[i].idx);
		if (uid_range->uid1 == ctx->next_uid) {
			/* use this one. */
			break;
		}
		if (uid_range->uid1 < next_found_uid) {
			next_i = i;
                        next_found_uid = uid_range->uid1;
		}
	}

	if (i == count) {
		if (next_i == UINT_MAX) {
			/* nothing left in sync_list */
			ctx->fully_synced = TRUE;
			return FALSE;
		}
                ctx->next_uid = next_found_uid;
		i = next_i;
		uid_range = array_idx(sync_list[i].array, sync_list[i].idx);
	}

	if (sync_list[i].array == (void *)&sync_trans->expunges) {
		mail_index_sync_get_expunge(sync_rec,
			(const struct mail_transaction_expunge_guid *)uid_range);
	} else if (sync_list[i].array == (void *)&sync_trans->updates) {
		mail_index_sync_get_update(sync_rec,
			(const struct mail_index_flag_update *)uid_range);
	} else {
		mail_index_sync_get_keyword_update(sync_rec, uid_range,
						   &sync_list[i]);
	}
	sync_list[i].idx++;
	return TRUE;
}

bool mail_index_sync_have_more(struct mail_index_sync_ctx *ctx)
{
	const struct mail_index_sync_list *sync_list;

	array_foreach(&ctx->sync_list, sync_list) {
		if (array_is_created(sync_list->array) &&
		    sync_list->idx != array_count(sync_list->array))
			return TRUE;
	}
	return FALSE;
}

void mail_index_sync_set_commit_result(struct mail_index_sync_ctx *ctx,
				       struct mail_index_transaction_commit_result *result)
{
	ctx->sync_commit_result = result;
}

void mail_index_sync_reset(struct mail_index_sync_ctx *ctx)
{
	struct mail_index_sync_list *sync_list;

	ctx->next_uid = 0;
	array_foreach_modifiable(&ctx->sync_list, sync_list)
		sync_list->idx = 0;
}

void mail_index_sync_no_warning(struct mail_index_sync_ctx *ctx)
{
	ctx->no_warning = TRUE;
}

void mail_index_sync_set_reason(struct mail_index_sync_ctx *ctx,
				const char *reason)
{
	i_free(ctx->reason);
	ctx->reason = i_strdup(reason);
}

static void mail_index_sync_end(struct mail_index_sync_ctx **_ctx)
{
        struct mail_index_sync_ctx *ctx = *_ctx;
	const char *lock_reason;

	i_assert(ctx->index->syncing);

	*_ctx = NULL;

	ctx->index->syncing = FALSE;
	if (ctx->no_warning)
		lock_reason = NULL;
	else if (ctx->reason != NULL)
		lock_reason = ctx->reason;
	else
		lock_reason = "Mailbox was synchronized";
	mail_transaction_log_sync_unlock(ctx->index->log, lock_reason);

	mail_index_view_close(&ctx->view);
	mail_index_transaction_rollback(&ctx->sync_trans);
	if (array_is_created(&ctx->sync_list))
		array_free(&ctx->sync_list);
	i_free(ctx->reason);
	i_free(ctx);
}

static void
mail_index_sync_update_mailbox_offset(struct mail_index_sync_ctx *ctx)
{
	const struct mail_index_header *hdr = &ctx->index->map->hdr;
	uint32_t seq;
	uoff_t offset;

	if (!ctx->fully_synced) {
		/* Everything wasn't synced. This usually means that syncing
		   was used for locking and nothing was synced. Don't update
		   tail offset. */
		return;
	}
	/* All changes were synced. During the syncing other transactions may
	   have been created and committed as well. They're expected to be
	   external transactions. These could be at least:
	    - mdbox finishing expunges
	    - mdbox writing to dovecot.map.index (requires tail offset updates)
	    - sdbox appending messages

	   If any expunges were committed, tail_offset must not be updated
	   before mail_index_map(MAIL_INDEX_SYNC_HANDLER_FILE) is called.
	   Otherwise expunge handlers won't be called for them.

	   We'll require MAIL_INDEX_SYNC_FLAG_UPDATE_TAIL_OFFSET flag for the
	   few places that actually require tail_offset to include the
	   externally committed transactions. Otherwise tail_offset is updated
	   only up to what was just synced. */
	if ((ctx->flags & MAIL_INDEX_SYNC_FLAG_UPDATE_TAIL_OFFSET) != 0)
		mail_transaction_log_get_head(ctx->index->log, &seq, &offset);
	else {
		mail_transaction_log_view_get_prev_pos(ctx->view->log_view,
						       &seq, &offset);
	}
	mail_transaction_log_set_mailbox_sync_pos(ctx->index->log, seq, offset);

	/* If tail offset has changed, make sure it gets written to
	   transaction log. do this only if we're required to make changes.

	   avoid writing a new tail offset if all the transactions were
	   external, because that wouldn't change effective the tail offset.
	   except e.g. mdbox map requires this to happen, so do it
	   optionally. Also update the tail if we've been calling any expunge
	   handlers, so they won't be called multiple times. That could cause
	   at least cache file's [deleted_]record_count to shrink too much. */
	if ((hdr->log_file_seq != seq || hdr->log_file_tail_offset < offset) &&
	    (ctx->seen_external_expunges ||
	     ctx->seen_nonexternal_transactions ||
	     (ctx->flags & MAIL_INDEX_SYNC_FLAG_UPDATE_TAIL_OFFSET) != 0)) {
		ctx->ext_trans->log_updates = TRUE;
		ctx->ext_trans->tail_offset_changed = TRUE;
	}
}

static bool mail_index_sync_want_index_write(struct mail_index *index)
{
	uint32_t log_diff;

	if (index->last_read_log_file_seq != 0 &&
	    index->last_read_log_file_seq != index->map->hdr.log_file_seq) {
		/* dovecot.index points to an old .log file. we were supposed
		   to rewrite the dovecot.index when rotating the log, so
		   we shouldn't usually get here. */
		return TRUE;
	}

	log_diff = index->map->hdr.log_file_tail_offset -
		index->last_read_log_file_tail_offset;
	if (log_diff > index->optimization_set.index.rewrite_max_log_bytes ||
	    (index->index_min_write &&
	     log_diff > index->optimization_set.index.rewrite_min_log_bytes))
		return TRUE;

	if (index->need_recreate)
		return TRUE;
	return FALSE;
}

int mail_index_sync_commit(struct mail_index_sync_ctx **_ctx)
{
        struct mail_index_sync_ctx *ctx = *_ctx;
	struct mail_index *index = ctx->index;
	struct mail_cache_compress_lock *cache_lock = NULL;
	uint32_t next_uid;
	bool want_rotate, index_undeleted, delete_index;
	int ret = 0, ret2;

	index_undeleted = ctx->ext_trans->index_undeleted;
	delete_index = index->index_delete_requested && !index_undeleted &&
		(ctx->flags & (MAIL_INDEX_SYNC_FLAG_DELETING_INDEX |
			       MAIL_INDEX_SYNC_FLAG_TRY_DELETING_INDEX)) != 0;
	if (delete_index) {
		/* finish this sync by marking the index deleted */
		mail_index_set_deleted(ctx->ext_trans);
	} else if (index->index_deleted && !index_undeleted &&
		   (ctx->flags & MAIL_INDEX_SYNC_FLAG_TRY_DELETING_INDEX) == 0) {
		/* another process just marked the index deleted.
		   finish the sync, but return error. */
		mail_index_set_error_nolog(index, "Index is marked deleted");
		ret = -1;
	}

	mail_index_sync_update_mailbox_offset(ctx);

	if ((ctx->flags & MAIL_INDEX_SYNC_FLAG_DROP_RECENT) != 0) {
		next_uid = mail_index_transaction_get_next_uid(ctx->ext_trans);
		if (index->map->hdr.first_recent_uid < next_uid) {
			mail_index_update_header(ctx->ext_trans,
				offsetof(struct mail_index_header,
					 first_recent_uid),
				&next_uid, sizeof(next_uid), FALSE);
		}
	}
	if (index->pending_log2_rotate_time != 0) {
		uint32_t log2_rotate_time = index->pending_log2_rotate_time;

		mail_index_update_header(ctx->ext_trans,
			offsetof(struct mail_index_header, log2_rotate_time),
			&log2_rotate_time, sizeof(log2_rotate_time), TRUE);
		index->pending_log2_rotate_time = 0;
	}

	ret2 = mail_index_transaction_commit(&ctx->ext_trans);
	if (ret2 < 0) {
		mail_index_sync_end(&ctx);
		return -1;
	}

	if (delete_index)
		index->index_deleted = TRUE;
	else if (index_undeleted) {
		index->index_deleted = FALSE;
		index->index_delete_requested = FALSE;
	}

	/* refresh the mapping with newly committed external transactions
	   and the synced expunges. sync using file handler here so that the
	   expunge handlers get called. */
	index->sync_commit_result = ctx->sync_commit_result;
	if (mail_index_map(ctx->index, MAIL_INDEX_SYNC_HANDLER_FILE) <= 0)
		ret = -1;
	index->sync_commit_result = NULL;

	/* The previously called expunged handlers will update cache's
	   record_count and deleted_record_count. That also has a side effect
	   of updating whether cache needs to be compressed. */
	if (ret == 0 && mail_cache_need_compress(index->cache)) {
		struct mail_index_transaction *cache_trans;
		enum mail_index_transaction_flags trans_flags;

		trans_flags = MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL;
		if ((ctx->flags & MAIL_INDEX_SYNC_FLAG_FSYNC) != 0)
			trans_flags |= MAIL_INDEX_TRANSACTION_FLAG_FSYNC;
		cache_trans = mail_index_transaction_begin(ctx->view, trans_flags);
		if (mail_cache_compress(index->cache, cache_trans,
					&cache_lock) < 0)
			mail_index_transaction_rollback(&cache_trans);
		else {
			/* can't really do anything if index commit fails */
			(void)mail_index_transaction_commit(&cache_trans);
			mail_cache_compress_unlock(&cache_lock);
			/* Make sure the newly committed cache record offsets
			   are updated to the current index. This is important
			   if the dovecot.index gets recreated below, because
			   rotation of dovecot.index.log also re-maps the index
			   to make sure everything is up-to-date. But if it
			   wasn't, mail_index_write() will just assert-crash
			   because log_file_head_offset changed. */
			if (mail_index_map(ctx->index, MAIL_INDEX_SYNC_HANDLER_FILE) <= 0)
				ret = -1;
		}
	}

	want_rotate = mail_transaction_log_want_rotate(index->log);
	if (ret == 0 &&
	    (want_rotate || mail_index_sync_want_index_write(index))) {
		index->need_recreate = FALSE;
		index->index_min_write = FALSE;
		mail_index_write(index, want_rotate);
	}
	mail_index_sync_end(_ctx);
	return ret;
}

void mail_index_sync_rollback(struct mail_index_sync_ctx **ctx)
{
	if ((*ctx)->ext_trans != NULL)
		mail_index_transaction_rollback(&(*ctx)->ext_trans);
	mail_index_sync_end(ctx);
}

void mail_index_sync_flags_apply(const struct mail_index_sync_rec *sync_rec,
				 uint8_t *flags)
{
	i_assert(sync_rec->type == MAIL_INDEX_SYNC_TYPE_FLAGS);

	*flags = (*flags & ~sync_rec->remove_flags) | sync_rec->add_flags;
}

bool mail_index_sync_keywords_apply(const struct mail_index_sync_rec *sync_rec,
				    ARRAY_TYPE(keyword_indexes) *keywords)
{
	const unsigned int *keyword_indexes;
	unsigned int idx = sync_rec->keyword_idx;
	unsigned int i, count;

	keyword_indexes = array_get(keywords, &count);
	switch (sync_rec->type) {
	case MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD:
		for (i = 0; i < count; i++) {
			if (keyword_indexes[i] == idx)
				return FALSE;
		}

		array_push_back(keywords, &idx);
		return TRUE;
	case MAIL_INDEX_SYNC_TYPE_KEYWORD_REMOVE:
		for (i = 0; i < count; i++) {
			if (keyword_indexes[i] == idx) {
				array_delete(keywords, i, 1);
				return TRUE;
			}
		}
		return FALSE;
	default:
		i_unreached();
		return FALSE;
	}
}

void mail_index_sync_set_corrupted(struct mail_index_sync_map_ctx *ctx,
				   const char *fmt, ...)
{
	va_list va;
	uint32_t seq;
	uoff_t offset;

	ctx->errors = TRUE;
	/* make sure we don't get to this same error again by updating the
	   dovecot.index */
	ctx->view->index->need_recreate = TRUE;

	mail_transaction_log_view_get_prev_pos(ctx->view->log_view,
					       &seq, &offset);

	if (seq < ctx->view->index->fsck_log_head_file_seq ||
	    (seq == ctx->view->index->fsck_log_head_file_seq &&
	     offset < ctx->view->index->fsck_log_head_file_offset)) {
		/* be silent */
		return;
	}

	va_start(va, fmt);
	T_BEGIN {
		mail_index_set_error(ctx->view->index,
				     "Log synchronization error at "
				     "seq=%u,offset=%"PRIuUOFF_T" for %s: %s",
				     seq, offset, ctx->view->index->filepath,
				     t_strdup_vprintf(fmt, va));
	} T_END;
	va_end(va);
}
