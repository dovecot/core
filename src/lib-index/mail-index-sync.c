/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "mail-index-view-private.h"
#include "mail-index-sync-private.h"
#include "mail-index-transaction-private.h"
#include "mail-transaction-log-private.h"
#include "mail-transaction-util.h"
#include "mail-cache.h"

#include <stdlib.h>

static void mail_index_sync_add_expunge(struct mail_index_sync_ctx *ctx)
{
	const struct mail_transaction_expunge *e = ctx->data;
	size_t i, size = ctx->hdr->size / sizeof(*e);
	uint32_t uid;

	for (i = 0; i < size; i++) {
		for (uid = e[i].uid1; uid <= e[i].uid2; uid++)
			mail_index_expunge(ctx->trans, uid);
	}
}

static void mail_index_sync_add_flag_update(struct mail_index_sync_ctx *ctx)
{
	const struct mail_transaction_flag_update *u = ctx->data;
	size_t i, size = ctx->hdr->size / sizeof(*u);

	for (i = 0; i < size; i++) {
		if (u[i].add_flags != 0) {
			mail_index_update_flags_range(ctx->trans,
						      u[i].uid1, u[i].uid2,
						      MODIFY_ADD,
						      u[i].add_flags);
		}
		if (u[i].remove_flags != 0) {
			mail_index_update_flags_range(ctx->trans,
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

	uidset_offset = sizeof(*u) + u->name_size;
	if ((uidset_offset % 4) != 0)
		uidset_offset += 4 - (uidset_offset % 4);
	uids = CONST_PTR_OFFSET(u, uidset_offset);

	t_push();
	keyword_names[0] = t_strndup(u + 1, u->name_size);
	keyword_names[1] = NULL;
	keywords = mail_index_keywords_create(ctx->trans, keyword_names);

	size = (ctx->hdr->size - uidset_offset) / sizeof(uint32_t);
	for (i = 0; i < size; i += 2) {
		/* FIXME: mail_index_update_keywords_range() */
		for (uid = uids[i]; uid <= uids[i+1]; uid++) {
			mail_index_update_keywords(ctx->trans, uid,
						   u->modify_type, keywords);
		}
	}

	mail_index_keywords_free(keywords);
	t_pop();
}

static void mail_index_sync_add_keyword_reset(struct mail_index_sync_ctx *ctx)
{
	const struct mail_transaction_keyword_reset *u = ctx->data;
	size_t i, size = ctx->hdr->size / sizeof(*u);
	uint32_t uid;

	for (i = 0; i < size; i++) {
		for (uid = u[i].uid1; uid <= u[i].uid2; uid++) {
			mail_index_update_keywords(ctx->trans, uid,
						   MODIFY_REPLACE, NULL);
		}
	}
}

static void mail_index_sync_add_append(struct mail_index_sync_ctx *ctx)
{
	const struct mail_index_record *rec = ctx->data;

	if (ctx->append_uid_first == 0 || rec->uid < ctx->append_uid_first)
		ctx->append_uid_first = rec->uid;

	rec = CONST_PTR_OFFSET(ctx->data, ctx->hdr->size - sizeof(*rec));
	if (rec->uid > ctx->append_uid_last)
		ctx->append_uid_last = rec->uid;

	ctx->sync_appends = TRUE;
}

static void mail_index_sync_add_transaction(struct mail_index_sync_ctx *ctx)
{
	switch (ctx->hdr->type & MAIL_TRANSACTION_TYPE_MASK) {
	case MAIL_TRANSACTION_EXPUNGE:
		mail_index_sync_add_expunge(ctx);
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
	case MAIL_TRANSACTION_APPEND:
		mail_index_sync_add_append(ctx);
		break;
	}
}

static int mail_index_sync_add_dirty_updates(struct mail_index_sync_ctx *ctx)
{
	struct mail_transaction_flag_update update;
	const struct mail_index_record *rec;
	uint32_t seq, messages_count;

	memset(&update, 0, sizeof(update));

	messages_count = mail_index_view_get_messages_count(ctx->view);
	for (seq = 1; seq <= messages_count; seq++) {
		if (mail_index_lookup(ctx->view, seq, &rec) < 0)
			return -1;

		if ((rec->flags & MAIL_INDEX_MAIL_FLAG_DIRTY) == 0)
			continue;

		mail_index_update_flags(ctx->trans, rec->uid,
					MODIFY_REPLACE, rec->flags);
	}
	return 0;
}

static int mail_index_sync_add_recent_updates(struct mail_index_sync_ctx *ctx)
{
	const struct mail_index_record *rec;
	uint32_t seq, messages_count;
	int seen_recent = FALSE;

	messages_count = mail_index_view_get_messages_count(ctx->view);
	for (seq = 1; seq <= messages_count; seq++) {
		if (mail_index_lookup(ctx->view, seq, &rec) < 0)
			return -1;

		if ((rec->flags & MAIL_RECENT) != 0) {
			seen_recent = TRUE;
			mail_index_update_flags(ctx->trans, rec->uid,
						MODIFY_REMOVE, MAIL_RECENT);
		}
	}

	if (!seen_recent) {
		/* no recent messages, drop the sync_recent flag so we
		   don't scan through the message again */
		ctx->sync_recent = FALSE;
	}

	return 0;
}

static int
mail_index_sync_read_and_sort(struct mail_index_sync_ctx *ctx,
			      int *seen_external_r)
{
	size_t size;
	int ret;

	*seen_external_r = FALSE;

	if ((ctx->view->map->hdr.flags & MAIL_INDEX_HDR_FLAG_HAVE_DIRTY) &&
	    ctx->sync_dirty) {
		/* show dirty flags as flag updates */
		if (mail_index_sync_add_dirty_updates(ctx) < 0)
			return -1;
	}

	if (ctx->sync_recent) {
		if (mail_index_sync_add_recent_updates(ctx) < 0)
			return -1;
	}

	while ((ret = mail_transaction_log_view_next(ctx->view->log_view,
						     &ctx->hdr,
						     &ctx->data, NULL)) > 0) {
		if ((ctx->hdr->type & MAIL_TRANSACTION_EXTERNAL) != 0)
			*seen_external_r = TRUE;
		 else
			mail_index_sync_add_transaction(ctx);
	}

	if (ctx->trans->expunges == NULL)
		ctx->expunges_count = 0;
	else {
		ctx->expunges = buffer_get_data(ctx->trans->expunges, &size);
		ctx->expunges_count = size / sizeof(*ctx->expunges);
	}
	if (ctx->trans->updates == NULL)
		ctx->updates_count = 0;
	else {
		ctx->updates = buffer_get_data(ctx->trans->updates, &size);
		ctx->updates_count = size / sizeof(*ctx->updates);
	}
	return ret;
}

static int mail_index_need_lock(struct mail_index *index, int sync_recent,
				uint32_t log_file_seq, uoff_t log_file_offset)
{
	if (sync_recent && index->hdr->recent_messages_count > 0)
		return 1;

	if (index->hdr->log_file_seq > log_file_seq ||
	     (index->hdr->log_file_seq == log_file_seq &&
	      index->hdr->log_file_int_offset >= log_file_offset &&
	      index->hdr->log_file_ext_offset >= log_file_offset)) {
		/* already synced */
		return mail_cache_need_compress(index->cache);
	}

	return 1;
}

static int mail_index_sync_commit_external(struct mail_index_sync_ctx *ctx,
					   uint32_t seq, uoff_t offset)
{
	int ret;

	while ((ret = mail_transaction_log_view_next(ctx->view->log_view,
						     &ctx->hdr, &ctx->data,
						     NULL)) > 0) {
		if ((ctx->hdr->type & MAIL_TRANSACTION_EXTERNAL) != 0)
			break;
	}
	if (ret < 0)
		return -1;

	if (ret > 0) {
		if (mail_transaction_log_view_set(ctx->view->log_view,
				ctx->index->hdr->log_file_seq,
				ctx->index->hdr->log_file_ext_offset,
				seq, offset, MAIL_TRANSACTION_TYPE_MASK) < 0)
			return -1;
		if (mail_index_sync_update_index(ctx, TRUE) < 0)
			return -1;
	}
	return 0;
}

#define MAIL_INDEX_IS_SYNCS_SAME(index) \
	((index)->sync_log_file_seq == (index)->hdr->log_file_seq && \
	 (index)->sync_log_file_offset == (index)->hdr->log_file_ext_offset)

int mail_index_sync_begin(struct mail_index *index,
                          struct mail_index_sync_ctx **ctx_r,
			  struct mail_index_view **view_r,
			  uint32_t log_file_seq, uoff_t log_file_offset,
			  int sync_recent, int sync_dirty)
{
	struct mail_index_sync_ctx *ctx;
	struct mail_index_view *dummy_view;
	uint32_t seq;
	uoff_t offset;
	unsigned int lock_id = 0;
	int seen_external;

	if (mail_transaction_log_sync_lock(index->log, &seq, &offset) < 0)
		return -1;

	if (!index->mmap_disable || !MAIL_INDEX_IS_SYNCS_SAME(index) ||
	    index->sync_log_file_seq != seq ||
	    index->sync_log_file_offset != offset) {
		/* make sure we have the latest file mapped */
		if (mail_index_lock_shared(index, TRUE, &lock_id) < 0) {
			mail_transaction_log_sync_unlock(index->log);
			return -1;
		}

		/* with mmap_disable the force parameter has somewhat special
		   meaning, it syncs exactly to the log seq/offset in index
		   file's header. */
		if (mail_index_map(index, index->mmap_disable) <= 0) {
			mail_transaction_log_sync_unlock(index->log);
			mail_index_unlock(index, lock_id);
			return -1;
		}
	}

	if (!mail_index_need_lock(index, sync_recent,
				  log_file_seq, log_file_offset)) {
		mail_index_unlock(index, lock_id);
		mail_transaction_log_sync_unlock(index->log);
		return 0;
	}

	ctx = i_new(struct mail_index_sync_ctx, 1);
	ctx->index = index;
	ctx->lock_id = lock_id;
	ctx->sync_recent = sync_recent;
	ctx->sync_dirty = sync_dirty;

	ctx->view = mail_index_view_open(index);

	dummy_view = mail_index_dummy_view_open(index);
	ctx->trans = mail_index_transaction_begin(dummy_view, FALSE, TRUE);
	mail_index_view_close(dummy_view);

	if (index->hdr->log_file_seq == seq &&
	    index->hdr->log_file_int_offset > offset) {
		/* synced offset is greater than what we have available.
		   the log sequences have gotten messed up. */
		mail_transaction_log_file_set_corrupted(index->log->head,
			"log_file_int_offset (%u) > log size (%"PRIuUOFF_T")",
			seq, index->hdr->log_file_int_offset, offset);
                mail_index_sync_rollback(ctx);
		return -1;
	}

	if (mail_transaction_log_view_set(ctx->view->log_view,
					  index->hdr->log_file_seq,
					  index->hdr->log_file_int_offset,
					  seq, offset,
					  MAIL_TRANSACTION_TYPE_MASK) < 0) {
                mail_index_sync_rollback(ctx);
		return -1;
	}

	/* See if there are some external transactions which were
	   written to transaction log, but weren't yet committed to
	   index. commit them first to avoid conflicts with another
	   external sync.

	   This is mostly needed to make sure there won't be multiple
	   appends with same UIDs, because those would cause
	   transaction log to be marked corrupted.

	   Note that any internal transactions must not be committed
	   yet. They need to be synced with the real mailbox first. */
	if (seq != index->hdr->log_file_seq ||
	    offset != index->hdr->log_file_ext_offset) {
		if (mail_index_sync_commit_external(ctx, seq, offset) < 0) {
			mail_index_sync_rollback(ctx);
			return -1;
		}

		mail_index_view_close(ctx->view);
		ctx->view = mail_index_view_open(index);

		if (mail_transaction_log_view_set(ctx->view->log_view,
					index->hdr->log_file_seq,
					index->hdr->log_file_int_offset,
					seq, offset,
					MAIL_TRANSACTION_TYPE_MASK) < 0) {
			mail_index_sync_rollback(ctx);
			return -1;
		}
	}

	/* we need to have all the transactions sorted to optimize
	   caller's mailbox access patterns */
	if (mail_index_sync_read_and_sort(ctx, &seen_external) < 0) {
                mail_index_sync_rollback(ctx);
		return -1;
	}

	*ctx_r = ctx;
	*view_r = ctx->view;
	return 1;
}

void
mail_index_sync_get_expunge(struct mail_index_sync_rec *rec,
			    const struct mail_transaction_expunge *exp)
{
	rec->type = MAIL_INDEX_SYNC_TYPE_EXPUNGE;
	rec->uid1 = exp->uid1;
	rec->uid2 = exp->uid2;
}

void
mail_index_sync_get_update(struct mail_index_sync_rec *rec,
			   const struct mail_transaction_flag_update *update)
{
	rec->type = MAIL_INDEX_SYNC_TYPE_FLAGS;
	rec->uid1 = update->uid1;
	rec->uid2 = update->uid2;

	rec->add_flags = update->add_flags;
	rec->remove_flags = update->remove_flags;
}

static int mail_index_sync_rec_check(struct mail_index_view *view,
				     struct mail_index_sync_rec *rec)
{
	switch (rec->type) {
	case MAIL_INDEX_SYNC_TYPE_EXPUNGE:
	case MAIL_INDEX_SYNC_TYPE_FLAGS:
	case MAIL_INDEX_SYNC_TYPE_KEYWORDS:
		if (rec->uid1 > rec->uid2 || rec->uid1 == 0) {
			mail_transaction_log_view_set_corrupted(view->log_view,
				"Broken UID range: %u..%u (type 0x%x)",
				rec->uid1, rec->uid2, rec->type);
			return FALSE;
		}
		break;
	case MAIL_INDEX_SYNC_TYPE_APPEND:
		break;
	}
	return TRUE;
}

int mail_index_sync_next(struct mail_index_sync_ctx *ctx,
			 struct mail_index_sync_rec *sync_rec)
{
	const struct mail_transaction_expunge *next_exp;
	const struct mail_transaction_flag_update *next_update;

	next_exp = ctx->expunge_idx == ctx->expunges_count ? NULL :
		&ctx->expunges[ctx->expunge_idx];
	next_update = ctx->update_idx == ctx->updates_count ? NULL :
		&ctx->updates[ctx->update_idx];

	if (next_update != NULL &&
	    (next_exp == NULL || next_update->uid1 < next_exp->uid1)) {
		mail_index_sync_get_update(sync_rec, next_update);
		if (next_exp != NULL && next_exp->uid1 <= next_update->uid2) {
			/* it's overlapping with next expunge */
			sync_rec->uid2 = next_exp->uid1-1;
		}

		if (sync_rec->uid1 < ctx->next_uid) {
			/* overlapping with previous expunge */
			if (ctx->next_uid > sync_rec->uid2) {
				/* hide this update completely */
				ctx->update_idx++;
                                return mail_index_sync_next(ctx, sync_rec);
			}
			sync_rec->uid1 = ctx->next_uid;
		}

		i_assert(sync_rec->uid1 <= sync_rec->uid2);
		ctx->update_idx++;
		return mail_index_sync_rec_check(ctx->view, sync_rec);
	}

	if (next_exp != NULL) {
		mail_index_sync_get_expunge(sync_rec, next_exp);
		if (mail_index_sync_rec_check(ctx->view, sync_rec) < 0)
			return -1;

		ctx->expunge_idx++;
		ctx->next_uid = next_exp->uid2+1;
		return 1;
	}

	if (ctx->sync_appends) {
		ctx->sync_appends = FALSE;
		sync_rec->type = MAIL_INDEX_SYNC_TYPE_APPEND;
		sync_rec->uid1 = ctx->append_uid_first;
		sync_rec->uid2 = ctx->append_uid_last;
		return 1;
	}

	return 0;
}

int mail_index_sync_have_more(struct mail_index_sync_ctx *ctx)
{
	return (ctx->update_idx != ctx->updates_count) ||
		(ctx->expunge_idx != ctx->expunges_count) ||
		ctx->sync_appends;
}

static void mail_index_sync_end(struct mail_index_sync_ctx *ctx)
{
	mail_index_unlock(ctx->index, ctx->lock_id);

	i_assert(!ctx->index->map->write_to_disk);
	mail_transaction_log_sync_unlock(ctx->index->log);

	mail_index_view_close(ctx->view);
	mail_index_transaction_rollback(ctx->trans);
	i_free(ctx);
}

int mail_index_sync_commit(struct mail_index_sync_ctx *ctx)
{
	struct mail_index *index = ctx->index;
	const struct mail_index_header *hdr;
	uint32_t seq, seq2;
	uoff_t offset, offset2;
	int ret = 0;

	if (mail_transaction_log_view_is_corrupted(ctx->view->log_view))
		ret = -1;

	/* we have had the transaction log locked since the beginning of sync,
	   so only external changes could have been committed. write them to
	   the index here as well. */
	mail_transaction_log_get_head(index->log, &seq, &offset);

	hdr = index->hdr;
	if (ret == 0 && (hdr->log_file_seq != seq ||
			 hdr->log_file_int_offset != offset ||
			 hdr->log_file_ext_offset != offset)) {
		if (mail_transaction_log_view_set(ctx->view->log_view,
				hdr->log_file_seq, hdr->log_file_int_offset,
				seq, offset, MAIL_TRANSACTION_TYPE_MASK) < 0)
			ret = -1;
		else if (mail_index_sync_update_index(ctx, FALSE) < 0)
			ret = -1;
	}

	if (ret == 0 && mail_cache_need_compress(index->cache)) {
		if (mail_cache_compress(index->cache, ctx->view) < 0)
			ret = -1;
		else {
			/* cache_offsets have changed, sync them */
			mail_transaction_log_get_head(index->log,
						      &seq2, &offset2);
			if (mail_transaction_log_view_set(ctx->view->log_view,
					seq, offset, seq2, offset2,
					MAIL_TRANSACTION_TYPE_MASK) < 0)
				ret = -1;
			else if (mail_index_sync_update_index(ctx, FALSE) < 0)
				ret = -1;
		}
	}

	index->sync_log_file_seq = index->map->hdr.log_file_seq;
	index->sync_log_file_offset = index->map->hdr.log_file_int_offset;

	mail_index_sync_end(ctx);
	return ret;
}

void mail_index_sync_rollback(struct mail_index_sync_ctx *ctx)
{
	mail_index_sync_end(ctx);
}

void mail_index_sync_flags_apply(const struct mail_index_sync_rec *sync_rec,
				 uint8_t *flags)
{
	i_assert(sync_rec->type == MAIL_INDEX_SYNC_TYPE_FLAGS);

	*flags = (*flags & ~sync_rec->remove_flags) | sync_rec->add_flags;
}
