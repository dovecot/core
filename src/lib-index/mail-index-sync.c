/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "mail-index-view-private.h"
#include "mail-index-sync-private.h"
#include "mail-transaction-log.h"
#include "mail-transaction-util.h"

#include <stdlib.h>

static void mail_index_sync_sort_flags(struct mail_index_sync_ctx *ctx)
{
	const struct mail_transaction_flag_update *src, *src_end;
	const struct mail_transaction_flag_update *dest;
	struct mail_transaction_flag_update new_update;
	struct mail_transaction_expunge_traverse_ctx *exp_ctx;
	uint32_t last;
	size_t i, dest_count;

	src = ctx->data;
	src_end = PTR_OFFSET(src, ctx->hdr->size);

	dest = buffer_get_data(ctx->updates_buf, &dest_count);
	dest_count /= sizeof(*dest);

	exp_ctx = mail_transaction_expunge_traverse_init(ctx->expunges_buf);

	for (i = 0; src != src_end; src++) {
		new_update = *src;

		/* find seq1 */
		new_update.seq1 +=
			mail_transaction_expunge_traverse_to(exp_ctx,
							     src->seq1);

		/* find seq2 */
		new_update.seq2 +=
			mail_transaction_expunge_traverse_to(exp_ctx,
							     src->seq2);

		/* insert it into buffer, split it in multiple parts if needed
		   to make sure the ordering stays the same */
		for (; i < dest_count; i++) {
			if (dest[i].seq1 <= new_update.seq1)
				continue;

			if (dest[i].seq1 > new_update.seq2)
				break;

			/* partial */
			last = new_update.seq2;
			new_update.seq2 = dest[i].seq1-1;

			buffer_insert(ctx->updates_buf, i * sizeof(new_update),
				      &new_update, sizeof(new_update));
			dest = buffer_get_data(ctx->updates_buf, NULL);
			dest_count++;

			new_update.seq1 = new_update.seq2+1;
			new_update.seq2 = last;
		}

		buffer_insert(ctx->updates_buf, i * sizeof(new_update),
			      &new_update, sizeof(new_update));
		dest = buffer_get_data(ctx->updates_buf, NULL);
		dest_count++;
	}
	mail_transaction_expunge_traverse_deinit(exp_ctx);
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
	case MAIL_TRANSACTION_APPEND:
		buffer_append(ctx->appends_buf, ctx->data, ctx->hdr->size);
                ctx->sync_appends = TRUE;
		break;
	}
}

static int mail_index_sync_read_and_sort(struct mail_index_sync_ctx *ctx,
					 int external)
{
        enum mail_transaction_type flag;
	size_t size;
	int ret;

	flag = external ? MAIL_TRANSACTION_EXTERNAL : 0;
	while ((ret = mail_transaction_log_view_next(ctx->view->log_view,
						     &ctx->hdr,
						     &ctx->data, NULL)) > 0) {
		if ((ctx->hdr->type & MAIL_TRANSACTION_EXTERNAL) == flag)
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
                mail_index_sync_end(ctx, 0, 0);
		return -1;
	}

	/* we need to have all the transactions sorted to optimize
	   caller's mailbox access patterns */
	ctx->expunges_buf = buffer_create_dynamic(default_pool,
						  1024, (size_t)-1);
	ctx->updates_buf = buffer_create_dynamic(default_pool,
						 1024, (size_t)-1);
	ctx->appends_buf = buffer_create_dynamic(default_pool,
						 1024, (size_t)-1);
	if (mail_index_sync_read_and_sort(ctx, FALSE) < 0) {
                mail_index_sync_end(ctx, 0, 0);
		return -1;
	}

	*ctx_r = ctx;
	*view_r = ctx->view;
	return 1;
}

static void
mail_index_sync_get_expunge(struct mail_index_sync_rec *rec,
			    const struct mail_transaction_expunge *exp)
{
	rec->type = MAIL_INDEX_SYNC_TYPE_EXPUNGE;
	rec->seq1 = exp->seq1;
	rec->seq2 = exp->seq2;
}

static void
mail_index_sync_get_update(struct mail_index_sync_rec *rec,
			   const struct mail_transaction_flag_update *update)
{
	rec->type = MAIL_INDEX_SYNC_TYPE_FLAGS;
	rec->seq1 = update->seq1;
	rec->seq2 = update->seq2;

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
	uint32_t message_count;

	switch (rec->type) {
	case MAIL_INDEX_SYNC_TYPE_EXPUNGE:
	case MAIL_INDEX_SYNC_TYPE_FLAGS:
		if (rec->seq1 > rec->seq2 || rec->seq1 == 0) {
			mail_transaction_log_view_set_corrupted(view->log_view,
				"Broken sequence: %u..%u (type 0x%x)",
				rec->seq1, rec->seq2, rec->type);
			return FALSE;
		}

		message_count = mail_index_view_get_message_count(view);
		if (rec->seq2 > message_count) {
			mail_transaction_log_view_set_corrupted(view->log_view,
				"Sequence out of range: %u > %u (type 0x%x)",
				rec->seq2, message_count, rec->type);
			return FALSE;
		}
		break;
	case MAIL_INDEX_SYNC_TYPE_APPEND:
		break;
	}
	return TRUE;
}

int mail_index_sync_get_rec(struct mail_index_view *view,
			    struct mail_index_sync_rec *rec,
			    const struct mail_transaction_header *hdr,
			    const void *data, size_t *data_offset)
{
	switch (hdr->type & MAIL_TRANSACTION_TYPE_MASK) {
	case MAIL_TRANSACTION_APPEND: {
		rec->type = MAIL_INDEX_SYNC_TYPE_APPEND;
		rec->seq1 = view->index->map->records_count + 1;
		rec->seq2 = rec->seq1 + hdr->size /
			sizeof(struct mail_index_record) - 1;
		rec->appends = NULL;

		*data_offset += hdr->size;
		break;
	}
	case MAIL_TRANSACTION_EXPUNGE: {
		const struct mail_transaction_expunge *exp =
			CONST_PTR_OFFSET(data, *data_offset);

		*data_offset += sizeof(*exp);
                mail_index_sync_get_expunge(rec, exp);
		break;
	}
	case MAIL_TRANSACTION_FLAG_UPDATE: {
		const struct mail_transaction_flag_update *update =
			CONST_PTR_OFFSET(data, *data_offset);

		*data_offset += sizeof(*update);
                mail_index_sync_get_update(rec, update);
		break;
	}
	default:
		i_unreached();
	}

	return mail_index_sync_rec_check(view, rec);
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
	       (next_exp == NULL || next_update->seq1 < next_exp->seq1)) {
		if (next_update->seq2 >= ctx->next_seq) {
			mail_index_sync_get_update(sync_rec, next_update);
			if (next_exp != NULL &&
			    next_exp->seq1 <= next_update->seq2) {
				/* it's overlapping.. */
				sync_rec->seq2 = next_exp->seq1-1;
			}

			if (sync_rec->seq1 < ctx->next_seq)
				sync_rec->seq1 = ctx->next_seq;

			i_assert(sync_rec->seq1 <= sync_rec->seq2);
			ctx->update_idx++;
			return mail_index_sync_rec_check(ctx->view, sync_rec);
		}

		if (++ctx->update_idx == ctx->updates_count)
			break;
		next_update++;
	}

	if (next_exp != NULL) {
		/* a few sanity checks here, we really don't ever want to
		   accidentally expunge a message. If sequence and UID matches,
		   it's quite unlikely this expunge was caused by some bug. */
		uint32_t uid1, uid2;

		if (next_exp->seq1 > ctx->view->map->records_count ||
		    next_exp->seq2 > ctx->view->map->records_count) {
			mail_transaction_log_view_set_corrupted(
				ctx->view->log_view, "Expunge range %u..%u "
				"larger than message count %u",
				next_exp->seq1, next_exp->seq2,
				ctx->view->map->records_count);
			return -1;
		}

		if (mail_index_lookup_uid(ctx->view, next_exp->seq1, &uid1) < 0)
			return -1;
		if (mail_index_lookup_uid(ctx->view, next_exp->seq2, &uid2) < 0)
			return -1;
		if (next_exp->uid1 != uid1 || next_exp->uid2 != uid2) {
			mail_transaction_log_view_set_corrupted(
				ctx->view->log_view, "Expunge range %u..%u: "
				"UIDs %u..%u doesn't match real UIDs %u..%u",
				next_exp->seq1, next_exp->seq2,
				next_exp->uid1, next_exp->uid2, uid1, uid2);
			return -1;
		}

		mail_index_sync_get_expunge(sync_rec, next_exp);
		ctx->expunge_idx++;

		/* scan updates again from the beginning */
		ctx->update_idx = 0;
		ctx->next_seq = next_exp->seq2;          
		return mail_index_sync_rec_check(ctx->view, sync_rec);
	}

	if (ctx->sync_appends) {
		ctx->sync_appends = FALSE;
		sync_rec->type = MAIL_INDEX_SYNC_TYPE_APPEND;
		sync_rec->seq1 = ctx->index->map->records_count+1;
		sync_rec->seq2 = sync_rec->seq1-1 +
			buffer_get_used_size(ctx->appends_buf) /
			sizeof(struct mail_index_record);
		sync_rec->appends = buffer_get_data(ctx->appends_buf, NULL);
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

int mail_index_sync_set_dirty(struct mail_index_sync_ctx *ctx, uint32_t seq)
{
	if (ctx->dirty_lock_id == 0) {
		if (mail_index_lock_exclusive(ctx->index,
					      &ctx->dirty_lock_id) < 0)
			return -1;
	}

	i_assert(seq <= ctx->view->map->records_count);
	ctx->view->map->records[seq-1].flags |= MAIL_INDEX_MAIL_FLAG_DIRTY;
	ctx->have_dirty = TRUE;
	return 0;
}

int mail_index_sync_end(struct mail_index_sync_ctx *ctx,
			uint32_t sync_stamp, uint64_t sync_size)
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
		mail_transaction_log_view_unset(ctx->view->log_view);
		if (mail_transaction_log_view_set(ctx->view->log_view,
				hdr->log_file_seq, hdr->log_file_offset,
				seq, offset, MAIL_TRANSACTION_TYPE_MASK) < 0)
			ret = -1;
	}

	if (ret == 0) {
		mail_index_sync_read_and_sort(ctx, TRUE);

		if (mail_index_sync_update_index(ctx, sync_stamp,
						 sync_size) < 0)
			ret = -1;
	}

	if (ctx->dirty_lock_id == 0) 
		mail_index_unlock(ctx->index, ctx->dirty_lock_id);

	mail_index_unlock(ctx->index, ctx->lock_id);
	mail_transaction_log_sync_unlock(ctx->index->log);
	mail_index_view_close(ctx->view);

	if (ctx->expunges_buf != NULL)
		buffer_free(ctx->expunges_buf);
	if (ctx->updates_buf != NULL)
		buffer_free(ctx->updates_buf);
	if (ctx->appends_buf != NULL)
		buffer_free(ctx->appends_buf);
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
