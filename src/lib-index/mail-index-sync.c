/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "mail-index-view-private.h"
#include "mail-index-sync-private.h"
#include "mail-transaction-log.h"
#include "mail-transaction-util.h"
#include "mail-cache.h"

#include <stdlib.h>

static void
mail_index_sync_sort_flags(buffer_t *dest_buf,
			   const struct mail_transaction_flag_update *src,
			   size_t src_size)
{
	const struct mail_transaction_flag_update *src_end;
	struct mail_transaction_flag_update *dest;
	struct mail_transaction_flag_update new_update, tmp_update;
	size_t i, dest_count;
	int j;

	dest = buffer_get_modifyable_data(dest_buf, &dest_count);
	dest_count /= sizeof(*dest);

	if (dest_count == 0) {
		buffer_append(dest_buf, src, src_size);
		return;
	}

	src_end = PTR_OFFSET(src, src_size);
	for (i = 0; src != src_end; src++) {
		new_update = *src;

		/* insert it into buffer, split and merge it with existing
		   updates if needed. */
		for (; i < dest_count; i++) {
			if (new_update.uid1 > dest[i].uid2)
				continue;

			if (new_update.uid2 < dest[i].uid1)
				break;

			/* at least partially overlapping */

			if (new_update.uid1 < dest[i].uid1) {
				/* { 5..6 } + { 1..5 } -> { 1..4 } + { 5..6 } */
				tmp_update = new_update;
				tmp_update.uid2 = dest[i].uid1-1;
				new_update.uid1 = dest[i].uid1;
				buffer_insert(dest_buf, i * sizeof(tmp_update),
					      &tmp_update, sizeof(tmp_update));
				dest = buffer_get_modifyable_data(dest_buf,
								  NULL);
				dest_count++; i++;
			} else if (new_update.uid1 > dest[i].uid1) {
				/* { 5..7 } + { 6..6 } ->
				   split old to { 5..5 } + { 6..7 } */
				tmp_update = dest[i];
				tmp_update.uid2 = new_update.uid1-1;
				dest[i].uid1 = new_update.uid1;
				buffer_insert(dest_buf, i * sizeof(tmp_update),
					      &tmp_update, sizeof(tmp_update));
				dest = buffer_get_modifyable_data(dest_buf,
								  NULL);
				dest_count++; i++;
			}
			i_assert(new_update.uid1 == dest[i].uid1);

			if (new_update.uid2 < dest[i].uid2) {
				/* { 5..7 } + { 5..6 } -> { 5..6 } + { 7..7 } */
				tmp_update = dest[i];
				tmp_update.uid1 = new_update.uid2+1;
				dest[i].uid2 = new_update.uid2;
				buffer_insert(dest_buf,
					      (i+1) * sizeof(tmp_update),
					      &tmp_update, sizeof(tmp_update));
				dest = buffer_get_modifyable_data(dest_buf,
								  NULL);
				dest_count++;
				new_update.uid2 = 0;
			} else {
				/* full match, or continues. */
				new_update.uid1 = dest[i].uid2+1;
			}

			/* dest[i] now contains the overlapping area.
			   merge them - new_update overrides old changes. */
			dest[i].add_flags |= new_update.add_flags;
			dest[i].add_flags &= ~new_update.remove_flags;
			dest[i].remove_flags |= new_update.remove_flags;
			dest[i].remove_flags &= ~new_update.add_flags;

			for (j = 0; j < INDEX_KEYWORDS_BYTE_COUNT; j++) {
				dest[i].add_keywords[j] |=
					new_update.add_keywords[j];
				dest[i].add_keywords[j] &=
					~new_update.remove_keywords[j];
				dest[i].remove_keywords[j] |=
					new_update.remove_keywords[j];
				dest[i].remove_keywords[j] &=
					~new_update.add_keywords[j];
			}
		}

		if (new_update.uid1 <= new_update.uid2) {
			buffer_insert(dest_buf, i * sizeof(new_update),
				      &new_update, sizeof(new_update));
			dest = buffer_get_modifyable_data(dest_buf, NULL);
			dest_count++;
		}
	}
}

static void mail_index_sync_sort_transaction(struct mail_index_sync_ctx *ctx)
{
	switch (ctx->hdr->type & MAIL_TRANSACTION_TYPE_MASK) {
	case MAIL_TRANSACTION_EXPUNGE:
		mail_transaction_log_sort_expunges(ctx->expunges_buf,
						   ctx->data, ctx->hdr->size);
		break;
	case MAIL_TRANSACTION_FLAG_UPDATE:
		mail_index_sync_sort_flags(ctx->updates_buf, ctx->data,
					   ctx->hdr->size);
		break;
	case MAIL_TRANSACTION_APPEND: {
		const struct mail_index_record *rec = ctx->data;

		if (ctx->append_uid_first == 0 ||
		    rec->uid < ctx->append_uid_first)
			ctx->append_uid_first = rec->uid;

		rec = CONST_PTR_OFFSET(ctx->data,
				       ctx->hdr->size - sizeof(*rec));
		if (rec->uid > ctx->append_uid_last)
			ctx->append_uid_last = rec->uid;

                ctx->sync_appends = TRUE;
		break;
	}
	}
}

static int mail_index_sync_add_dirty_updates(struct mail_index_sync_ctx *ctx)
{
	struct mail_transaction_flag_update update;
	const struct mail_index_record *rec;
	uint32_t seq, messages_count;
	int i;

	memset(&update, 0, sizeof(update));

	messages_count = mail_index_view_get_message_count(ctx->view);
	for (seq = 1; seq <= messages_count; seq++) {
		if (mail_index_lookup(ctx->view, seq, &rec) < 0)
			return -1;

		if ((rec->flags & MAIL_INDEX_MAIL_FLAG_DIRTY) == 0)
			continue;

		update.uid1 = update.uid2 = rec->uid;
		update.add_flags = rec->flags;
		update.remove_flags = ~update.add_flags;
		memcpy(update.add_keywords, rec->keywords,
		       INDEX_KEYWORDS_BYTE_COUNT);
		for (i = 0; i < INDEX_KEYWORDS_BYTE_COUNT; i++)
			update.remove_keywords[i] = ~update.add_keywords[i];

		mail_index_sync_sort_flags(ctx->updates_buf,
					   &update, sizeof(update));
	}
	return 0;
}

static int mail_index_sync_add_recent_updates(struct mail_index_sync_ctx *ctx)
{
	struct mail_transaction_flag_update update;
	const struct mail_index_record *rec;
	uint32_t seq, messages_count;

	memset(&update, 0, sizeof(update));

	messages_count = mail_index_view_get_message_count(ctx->view);
	for (seq = 1; seq <= messages_count; seq++) {
		if (mail_index_lookup(ctx->view, seq, &rec) < 0)
			return -1;

		if ((rec->flags & MAIL_RECENT) == 0)
			continue;

		update.uid1 = update.uid2 = rec->uid;
		mail_index_sync_sort_flags(ctx->updates_buf,
					   &update, sizeof(update));
	}
	return 0;
}

static int
mail_index_sync_read_and_sort(struct mail_index_sync_ctx *ctx, int sync_recent)
{
	size_t size;
	int ret;

	if (ctx->view->map->hdr->flags & MAIL_INDEX_HDR_FLAG_HAVE_DIRTY) {
		/* show dirty flags as flag updates */
		if (mail_index_sync_add_dirty_updates(ctx) < 0)
			return -1;
	}

	if (sync_recent) {
		if (mail_index_sync_add_recent_updates(ctx) < 0)
			return -1;
	}

	while ((ret = mail_transaction_log_view_next(ctx->view->log_view,
						     &ctx->hdr,
						     &ctx->data, NULL)) > 0) {
		if ((ctx->hdr->type & MAIL_TRANSACTION_EXTERNAL) == 0)
			mail_index_sync_sort_transaction(ctx);
	}

	ctx->expunges = buffer_get_data(ctx->expunges_buf, &size);
	ctx->expunges_count = size / sizeof(*ctx->expunges);
	ctx->updates = buffer_get_data(ctx->updates_buf, &size);
	ctx->updates_count = size / sizeof(*ctx->updates);

	return ret;
}

static int mail_index_need_lock(struct mail_index *index, int sync_recent,
				uint32_t log_file_seq, uoff_t log_file_offset)
{
	if (sync_recent && index->hdr->recent_messages_count > 0)
		return 1;

	if (index->hdr->log_file_seq > log_file_seq ||
	     (index->hdr->log_file_seq == log_file_seq &&
	      index->hdr->log_file_offset >= log_file_offset)) {
		/* already synced */
		return mail_cache_need_compress(index->cache);
	}

	return 1;
}

int mail_index_sync_begin(struct mail_index *index,
                          struct mail_index_sync_ctx **ctx_r,
			  struct mail_index_view **view_r,
			  uint32_t log_file_seq, uoff_t log_file_offset,
			  int sync_recent)
{
	struct mail_index_sync_ctx *ctx;
	uint32_t seq;
	uoff_t offset;
	unsigned int lock_id;

	if (mail_transaction_log_sync_lock(index->log, &seq, &offset) < 0)
		return -1;

	if (mail_index_lock_shared(index, TRUE, &lock_id) < 0) {
		mail_transaction_log_sync_unlock(index->log);
		return -1;
	}

	if (mail_index_map(index, FALSE) <= 0) {
		mail_transaction_log_sync_unlock(index->log);
		mail_index_unlock(index, lock_id);
		return -1;
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

	ctx->view = mail_index_view_open(index);
	ctx->view->external = TRUE;

	if (mail_transaction_log_view_set(ctx->view->log_view,
					  index->hdr->log_file_seq,
					  index->hdr->log_file_offset,
					  seq, offset,
					  MAIL_TRANSACTION_TYPE_MASK) < 0) {
                mail_index_sync_rollback(ctx);
		return -1;
	}

	/* we need to have all the transactions sorted to optimize
	   caller's mailbox access patterns */
	ctx->expunges_buf = buffer_create_dynamic(default_pool,
						  1024, (size_t)-1);
	ctx->updates_buf = buffer_create_dynamic(default_pool,
						 1024, (size_t)-1);
	if (mail_index_sync_read_and_sort(ctx, sync_recent) < 0) {
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
	memcpy(rec->add_keywords, update->add_keywords,
	       sizeof(rec->add_keywords));
	rec->remove_flags = update->remove_flags;
	memcpy(rec->remove_keywords, update->remove_keywords,
	       sizeof(rec->remove_keywords));
}

static int mail_index_sync_rec_check(struct mail_index_view *view,
				     struct mail_index_sync_rec *rec)
{
	switch (rec->type) {
	case MAIL_INDEX_SYNC_TYPE_EXPUNGE:
	case MAIL_INDEX_SYNC_TYPE_FLAGS:
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

	if (ctx->expunges_buf != NULL)
		buffer_free(ctx->expunges_buf);
	if (ctx->updates_buf != NULL)
		buffer_free(ctx->updates_buf);
	i_free(ctx);
}

int mail_index_sync_commit(struct mail_index_sync_ctx *ctx)
{
	const struct mail_index_header *hdr;
	uint32_t seq, seq2;
	uoff_t offset, offset2;
	int ret = 0;

	if (mail_transaction_log_view_is_corrupted(ctx->view->log_view))
		ret = -1;

	mail_transaction_log_get_head(ctx->index->log, &seq, &offset);

	if (ret == 0) {
		hdr = ctx->index->hdr;

		if (mail_transaction_log_view_set(ctx->view->log_view,
				hdr->log_file_seq, hdr->log_file_offset,
				seq, offset, MAIL_TRANSACTION_TYPE_MASK) < 0)
			ret = -1;
		else if (mail_index_sync_update_index(ctx) < 0)
			ret = -1;
	}

	if (ret == 0 && mail_cache_need_compress(ctx->index->cache)) {
		if (mail_cache_compress(ctx->index->cache, ctx->view) < 0)
			ret = -1;
		else {
			/* cache_offsets have changed, sync them */
			mail_transaction_log_get_head(ctx->index->log,
						      &seq2, &offset2);
			if (mail_transaction_log_view_set(ctx->view->log_view,
					seq, offset, seq2, offset2,
					MAIL_TRANSACTION_TYPE_MASK) < 0)
				ret = -1;
			else if (mail_index_sync_update_index(ctx) < 0)
				ret = -1;
		}
	}

	mail_index_sync_end(ctx);
	return ret;
}

void mail_index_sync_rollback(struct mail_index_sync_ctx *ctx)
{
	mail_index_sync_end(ctx);
}

void mail_index_sync_flags_apply(const struct mail_index_sync_rec *sync_rec,
				 uint8_t *flags, keywords_mask_t keywords)
{
	int i;

	i_assert(sync_rec->type == MAIL_INDEX_SYNC_TYPE_FLAGS);

	*flags = (*flags & ~sync_rec->remove_flags) | sync_rec->add_flags;
	for (i = 0; i < INDEX_KEYWORDS_BYTE_COUNT; i++) {
		keywords[i] = (keywords[i] & ~sync_rec->remove_keywords[i]) |
			sync_rec->add_keywords[i];
	}
}
