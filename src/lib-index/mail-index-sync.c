/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "mail-index-view-private.h"
#include "mail-index-sync-private.h"
#include "mail-transaction-log.h"
#include "mail-transaction-util.h"
#include "mail-cache.h"

#include <stdlib.h>

static void mail_index_sync_sort_flags(struct mail_index_sync_ctx *ctx)
{
	const struct mail_transaction_flag_update *src, *src_end;
	const struct mail_transaction_flag_update *dest;
	struct mail_transaction_flag_update new_update;
	uint32_t last;
	size_t i, dest_count;

	src = ctx->data;
	src_end = PTR_OFFSET(src, ctx->hdr->size);
	if (src == src_end)
		return;

	dest = buffer_get_data(ctx->updates_buf, &dest_count);
	dest_count /= sizeof(*dest);

	for (i = 0; src != src_end; src++) {
		new_update = *src;

		/* insert it into buffer, split it in multiple parts if needed
		   to make sure the ordering stays the same */
		for (; i < dest_count; i++) {
			if (dest[i].uid1 <= new_update.uid1)
				continue;

			if (dest[i].uid1 > new_update.uid2)
				break;

			/* partial */
			last = new_update.uid2;
			new_update.uid2 = dest[i].uid1-1;

			buffer_insert(ctx->updates_buf, i * sizeof(new_update),
				      &new_update, sizeof(new_update));
			dest = buffer_get_data(ctx->updates_buf, NULL);
			dest_count++;

			new_update.uid1 = new_update.uid2+1;
			new_update.uid2 = last;
		}

		buffer_insert(ctx->updates_buf, i * sizeof(new_update),
			      &new_update, sizeof(new_update));
		dest = buffer_get_data(ctx->updates_buf, NULL);
		dest_count++;
	}
}

static void mail_index_sync_sort_transaction(struct mail_index_sync_ctx *ctx)
{
	switch (ctx->hdr->type & MAIL_TRANSACTION_TYPE_MASK) {
	case MAIL_TRANSACTION_EXPUNGE:
		if (buffer_get_used_size(ctx->expunges_buf) == 0) {
			buffer_append(ctx->expunges_buf, ctx->data,
				      ctx->hdr->size);
		} else {
			mail_transaction_log_sort_expunges(ctx->expunges_buf,
							   ctx->data,
							   ctx->hdr->size);
		}
		break;
	case MAIL_TRANSACTION_FLAG_UPDATE:
		if (buffer_get_used_size(ctx->expunges_buf) == 0 &&
		    buffer_get_used_size(ctx->updates_buf) == 0) {
			buffer_append(ctx->updates_buf, ctx->data,
				      ctx->hdr->size);
		} else {
			mail_index_sync_sort_flags(ctx);
		}
		break;
	case MAIL_TRANSACTION_APPEND: {
		const struct mail_transaction_append_header *hdr = ctx->data;
		const struct mail_index_record *rec = ctx->data;

		if (ctx->append_uid_first == 0 ||
		    rec->uid < ctx->append_uid_first)
			ctx->append_uid_first = rec->uid;

		rec = CONST_PTR_OFFSET(ctx->data,
				       ctx->hdr->size - hdr->record_size);
		if (rec->uid > ctx->append_uid_last)
			ctx->append_uid_last = rec->uid;

                ctx->sync_appends = TRUE;
		break;
	}
	}
}

static int mail_index_sync_read_and_sort(struct mail_index_sync_ctx *ctx)
{
	size_t size;
	int ret;

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

static int mail_index_need_lock(struct mail_index *index,
				uint32_t log_file_seq, uoff_t log_file_offset)
{
	if (index->hdr->log_file_seq > log_file_seq ||
	     (index->hdr->log_file_seq == log_file_seq &&
	      index->hdr->log_file_offset >= log_file_offset)) {
		/* already synced */
		return 0;
	}

	return 1;
}

int mail_index_sync_begin(struct mail_index *index,
                          struct mail_index_sync_ctx **ctx_r,
			  struct mail_index_view **view_r,
			  uint32_t log_file_seq, uoff_t log_file_offset)
{
	struct mail_index_sync_ctx *ctx;
	uint32_t seq, new_file_seq;
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

	if (!mail_index_need_lock(index, log_file_seq, log_file_offset)) {
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
                mail_index_sync_end(ctx);
		return -1;
	}

	/* we need to have all the transactions sorted to optimize
	   caller's mailbox access patterns */
	ctx->expunges_buf = buffer_create_dynamic(default_pool,
						  1024, (size_t)-1);
	ctx->updates_buf = buffer_create_dynamic(default_pool,
						 1024, (size_t)-1);
	if (mail_index_sync_read_and_sort(ctx) < 0) {
                mail_index_sync_end(ctx);
		return -1;
	}

	/* check here if cache file's sequence has changed unexpectedly */
	if (mail_cache_need_reset(index->cache, &new_file_seq)) {
		uint32_t seq;
		uoff_t offset;
		struct mail_index_transaction *t;

		t = mail_index_transaction_begin(ctx->view, FALSE);
		mail_index_reset_cache(t, new_file_seq);
                mail_index_transaction_commit(t, &seq, &offset);
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

	// FIXME: return dirty flagged records as flag updates

	/* the ugliness here is to avoid returning overlapping expunge
	   and update areas. For example:

	   updates[] = A { 1, 7 }, B { 1, 3 }
	   expunges[] = { 5, 6 }

	   will make us return

	   update A: 1, 4
	   update B: 1, 3
	   expunge : 5, 6
	   update A: 7, 7
	*/
	while (next_update != NULL &&
	       (next_exp == NULL || next_update->uid1 < next_exp->uid1)) {
		if (next_update->uid2 >= ctx->next_uid) {
			mail_index_sync_get_update(sync_rec, next_update);
			if (next_exp != NULL &&
			    next_exp->uid1 <= next_update->uid2) {
				/* it's overlapping.. */
				sync_rec->uid2 = next_exp->uid1-1;
			}

			if (sync_rec->uid1 < ctx->next_uid)
				sync_rec->uid1 = ctx->next_uid;

			i_assert(sync_rec->uid1 <= sync_rec->uid2);
			ctx->update_idx++;
			return mail_index_sync_rec_check(ctx->view, sync_rec);
		}

		if (++ctx->update_idx == ctx->updates_count)
			break;
		next_update++;
	}

	if (next_exp != NULL) {
		mail_index_sync_get_expunge(sync_rec, next_exp);
		if (mail_index_sync_rec_check(ctx->view, sync_rec) < 0)
			return -1;

		ctx->expunge_idx++;

		/* scan updates again from the beginning */
		ctx->update_idx = 0;
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

int mail_index_sync_end(struct mail_index_sync_ctx *ctx)
{
	const struct mail_index_header *hdr;
	uint32_t seq;
	uoff_t offset;
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
		if (mail_index_sync_update_index(ctx) < 0)
			ret = -1;
	}

	mail_index_unlock(ctx->index, ctx->lock_id);
        i_assert(!ctx->index->map->write_to_disk);
	mail_transaction_log_sync_unlock(ctx->index->log);
	mail_index_view_close(ctx->view);

	if (ctx->expunges_buf != NULL)
		buffer_free(ctx->expunges_buf);
	if (ctx->updates_buf != NULL)
		buffer_free(ctx->updates_buf);
	i_free(ctx);
	return ret;
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
