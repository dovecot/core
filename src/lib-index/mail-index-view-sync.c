/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "mail-index-view-private.h"
#include "mail-index-sync-private.h"
#include "mail-transaction-log.h"
#include "mail-transaction-util.h"

struct mail_index_view_sync_ctx {
	struct mail_index_view *view;
	enum mail_index_sync_type sync_mask;
	struct mail_index_map *sync_map;
	buffer_t *expunges;
	uint32_t messages_count;

	const struct mail_transaction_header *hdr;
	const void *data;

	size_t data_offset;
	unsigned int skipped:1;
	unsigned int last_read:1;
};

static int
view_sync_get_expunges(struct mail_index_view *view, buffer_t **expunges_r)
{
	const struct mail_transaction_expunge *exp, *end;
	buffer_t *expunges;
	size_t size;

	/* with mask 0 we don't get anything, we'll just read the expunges
	   while seeking to end */
	if (mail_transaction_log_view_set(view->log_view,
					  view->log_file_seq,
					  view->log_file_offset,
					  view->index->hdr->log_file_seq,
					  view->index->hdr->log_file_offset,
					  0) < 0)
		return -1;
	if (mail_transaction_log_view_next(view->log_view,
					   NULL, NULL, NULL) < 0)
		return -1;

	expunges = mail_transaction_log_view_get_expunges(view->log_view);
	exp = buffer_get_data(expunges, &size);
	end = CONST_PTR_OFFSET(exp, size);

	*expunges_r = buffer_create_dynamic(default_pool, size, (size_t)-1);
	for (; exp != end; exp++) {
		buffer_append(*expunges_r, &exp->seq1, sizeof(exp->seq1));
		buffer_append(*expunges_r, &exp->seq2, sizeof(exp->seq2));
	}
        mail_transaction_log_view_unset(view->log_view);
	return 0;
}

int mail_index_view_sync_begin(struct mail_index_view *view,
                               enum mail_index_sync_type sync_mask,
			       struct mail_index_view_sync_ctx **ctx_r)
{
	const struct mail_index_header *hdr;
	struct mail_index_view_sync_ctx *ctx;
	struct mail_index_map *map;
	enum mail_transaction_type mask;
	buffer_t *expunges = NULL;

	/* We must sync flags as long as view is mmap()ed, as the flags may
	   have already changed under us. */
	i_assert((sync_mask & MAIL_INDEX_SYNC_TYPE_FLAGS) != 0);
	i_assert(view->transactions == 0);
	i_assert(!view->syncing);

	if (mail_index_view_lock_head(view, TRUE) < 0)
		return -1;

	hdr = view->index->hdr;
	if ((sync_mask & MAIL_INDEX_SYNC_TYPE_EXPUNGE) != 0) {
		/* get list of all expunges first */
		if (view_sync_get_expunges(view, &expunges) < 0)
			return -1;
	}

	mask = mail_transaction_type_mask_get(sync_mask);
	if (mail_transaction_log_view_set(view->log_view,
					  view->log_file_seq,
					  view->log_file_offset,
					  hdr->log_file_seq,
					  hdr->log_file_offset, mask) < 0) {
		if (expunges != NULL)
			buffer_free(expunges);
		return -1;
	}

	if (sync_mask == MAIL_INDEX_SYNC_MASK_ALL) {
		map = view->index->map;
		map->refcount++;
	} else {
		map = mail_index_map_to_memory(view->map);
	}
	view->syncing = TRUE;

	ctx = i_new(struct mail_index_view_sync_ctx, 1);
	ctx->view = view;
	ctx->sync_mask = sync_mask;
	ctx->sync_map = map;
	ctx->expunges = expunges;
	ctx->messages_count = mail_index_view_get_message_count(view);

	*ctx_r = ctx;
	return 0;
}

static int view_is_transaction_synced(struct mail_index_view *view,
				      uint32_t seq, uoff_t offset)
{
	const unsigned char *data, *end;
	size_t size;

	if (view->log_syncs == NULL)
		return 0;

	data = buffer_get_data(view->log_syncs, &size);
	end = data + size;

	for (; data < end; ) {
		if (*((const uoff_t *)data) == offset &&
		    *((const uint32_t *)(data + sizeof(uoff_t))) == seq)
			return 1;
		data += sizeof(uoff_t) + sizeof(uint32_t);
	}

	return 0;
}

static int sync_expunge(const struct mail_transaction_expunge *e, void *context)
{
	struct mail_index_map *map = context;
	unsigned int idx, count;

	for (idx = e->seq1-1; idx < e->seq2; idx++) {
		mail_index_header_update_counts(&map->hdr_copy,
						map->records[idx].flags, 0);
	}

	count = e->seq2 - e->seq1 + 1;
	buffer_delete(map->buffer,
		      (e->seq1-1) * sizeof(struct mail_index_record),
		      count * sizeof(struct mail_index_record));
	map->records = buffer_get_modifyable_data(map->buffer, NULL);

	map->records_count -= count;
	map->hdr_copy.messages_count -= count;
	return 1;
}

static int sync_append(const struct mail_index_record *rec, void *context)
{
	struct mail_index_map *map = context;

	buffer_append(map->buffer, rec, sizeof(*rec));
	map->records = buffer_get_modifyable_data(map->buffer, NULL);

	map->records_count++;
	map->hdr_copy.messages_count++;
	map->hdr_copy.next_uid = rec->uid+1;

	mail_index_header_update_counts(&map->hdr_copy, 0, rec->flags);
	mail_index_header_update_lowwaters(&map->hdr_copy, rec);
	return 1;
}

static int sync_flag_update(const struct mail_transaction_flag_update *u,
			    void *context)
{
	struct mail_index_map *map = context;
	struct mail_index_record *rec;
	unsigned int i, idx;
	uint8_t old_flags;

	for (idx = u->seq1-1; idx < u->seq2; idx++) {
		rec = &map->records[idx];

		old_flags = rec->flags;
		rec->flags = (rec->flags & ~u->remove_flags) | u->add_flags;
		for (i = 0; i < INDEX_KEYWORDS_BYTE_COUNT; i++) {
			rec->keywords[i] = u->add_keywords[i] |
				(rec->keywords[i] & ~u->remove_keywords[i]);
		}

		mail_index_header_update_counts(&map->hdr_copy, old_flags,
						rec->flags);
		mail_index_header_update_lowwaters(&map->hdr_copy, rec);
	}
	return 1;
}

static int sync_cache_update(const struct mail_transaction_cache_update *u,
			     void *context)
{
	struct mail_index_map *map = context;

	map->records[u->seq-1].cache_offset = u->cache_offset;
	return 1;
}

static int mail_index_view_sync_map(struct mail_index_view_sync_ctx *ctx)
{
	static struct mail_transaction_map_functions map_funcs = {
		sync_expunge, sync_append, sync_flag_update, sync_cache_update
	};

	return mail_transaction_map(ctx->hdr, ctx->data,
				    &map_funcs, ctx->sync_map);
}

static int mail_index_view_sync_next_trans(struct mail_index_view_sync_ctx *ctx,
					   uint32_t *seq_r, uoff_t *offset_r)
{
        struct mail_transaction_log_view *log_view = ctx->view->log_view;
	struct mail_index_view *view = ctx->view;
	int ret, skipped;

	ret = mail_transaction_log_view_next(log_view, &ctx->hdr, &ctx->data,
					     &skipped);
	if (ret <= 0) {
		if (ret < 0)
			return -1;

		ctx->last_read = TRUE;
		return 1;
	}

	if (skipped)
		ctx->skipped = TRUE;

	mail_transaction_log_view_get_prev_pos(log_view, seq_r, offset_r);

	/* skip flag changes that we committed ourself or have already synced */
	if (view_is_transaction_synced(view, *seq_r, *offset_r))
		return 0;

	if (ctx->sync_mask != MAIL_INDEX_SYNC_MASK_ALL) {
		if (mail_index_view_sync_map(ctx) < 0)
			return -1;
	}

	return 1;
}

static void
mail_index_view_sync_get_rec(struct mail_index_view_sync_ctx *ctx,
			     struct mail_index_sync_rec *rec)
{
	const struct mail_transaction_header *hdr = ctx->hdr;
	const void *data = ctx->data;

	switch (hdr->type & MAIL_TRANSACTION_TYPE_MASK) {
	case MAIL_TRANSACTION_APPEND: {
		rec->type = MAIL_INDEX_SYNC_TYPE_APPEND;
		rec->seq1 = ctx->messages_count + 1;
		ctx->messages_count +=
			hdr->size / sizeof(struct mail_index_record);
		rec->seq2 = ctx->messages_count;
		rec->appends = NULL;

		ctx->data_offset += hdr->size;
		break;
	}
	case MAIL_TRANSACTION_EXPUNGE: {
		const struct mail_transaction_expunge *exp =
			CONST_PTR_OFFSET(data, ctx->data_offset);

		ctx->data_offset += sizeof(*exp);
                mail_index_sync_get_expunge(rec, exp);
		break;
	}
	case MAIL_TRANSACTION_FLAG_UPDATE: {
		const struct mail_transaction_flag_update *update =
			CONST_PTR_OFFSET(data, ctx->data_offset);

		ctx->data_offset += sizeof(*update);
                mail_index_sync_get_update(rec, update);
		break;
	}
	default:
		i_unreached();
	}
}

int mail_index_view_sync_next(struct mail_index_view_sync_ctx *ctx,
			      struct mail_index_sync_rec *sync_rec)
{
	struct mail_index_view *view = ctx->view;
	uint32_t seq;
	uoff_t offset;
	int ret;

	if (ctx->hdr == NULL || ctx->data_offset == ctx->hdr->size) {
		ctx->data_offset = 0;
		do {
			ret = mail_index_view_sync_next_trans(ctx, &seq,
							      &offset);
			if (ret < 0)
				return -1;

			if (ctx->last_read)
				return 0;

			if (!ctx->skipped) {
				view->log_file_seq = seq;
				view->log_file_offset = offset +
					sizeof(*ctx->hdr) + ctx->hdr->size;
			}
		} while (ret == 0);

		if (ctx->skipped) {
			mail_index_view_add_synced_transaction(view, seq,
							       offset);
		}
	}

	mail_index_view_sync_get_rec(ctx, sync_rec);
	return 1;
}

const uint32_t *
mail_index_view_sync_get_expunges(struct mail_index_view_sync_ctx *ctx,
				  size_t *count_r)
{
	const uint32_t *data;
	size_t size;

	data = buffer_get_data(ctx->expunges, &size);
	*count_r = size / (sizeof(uint32_t)*2);
	return data;
}

void mail_index_view_sync_end(struct mail_index_view_sync_ctx *ctx)
{
        struct mail_index_view *view = ctx->view;

	i_assert(view->syncing);

	if (view->log_syncs != NULL && !ctx->skipped)
		buffer_set_used_size(view->log_syncs, 0);

	if (!ctx->last_read && ctx->hdr != NULL &&
	    ctx->data_offset != ctx->hdr->size) {
		/* we didn't sync everything */
		view->inconsistent = TRUE;
	}

	mail_index_unmap(view->index, view->map);
	view->map = ctx->sync_map;

        mail_transaction_log_view_unset(view->log_view);

	if (ctx->expunges != NULL)
		buffer_free(ctx->expunges);

	view->syncing = FALSE;
	i_free(ctx);
}

void mail_index_view_add_synced_transaction(struct mail_index_view *view,
					    uint32_t log_file_seq,
					    uoff_t log_file_offset)
{
	if (view->log_syncs == NULL) {
		view->log_syncs = buffer_create_dynamic(default_pool,
							128, (size_t)-1);
	}
	buffer_append(view->log_syncs, &log_file_offset,
		      sizeof(log_file_offset));
	buffer_append(view->log_syncs, &log_file_seq, sizeof(log_file_seq));
}
