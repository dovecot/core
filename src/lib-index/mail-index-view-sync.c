/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "mail-index-view-private.h"
#include "mail-index-sync-private.h"
#include "mail-transaction-log.h"
#include "mail-transaction-util.h"

struct mail_index_view_sync_ctx {
	struct mail_index_view *view;
	enum mail_transaction_type trans_sync_mask;
	struct mail_index_sync_map_ctx sync_map_ctx;
	buffer_t *expunges;

	const struct mail_transaction_header *hdr;
	const void *data;

	size_t data_offset;
	unsigned int skipped_some:1;
	unsigned int last_read:1;
	unsigned int sync_map_update:1;
};

static int
view_sync_get_expunges(struct mail_index_view *view, buffer_t **expunges_r)
{
	const struct mail_transaction_header *hdr;
	struct mail_transaction_expunge *src, *src_end, *dest;
	const void *data;
	size_t size;
	int ret;

	*expunges_r = buffer_create_dynamic(default_pool, 512);

	/* with mask 0 we don't get anything, we'll just read the expunges
	   while seeking to end */
	if (mail_transaction_log_view_set(view->log_view,
					  view->log_file_seq,
					  view->log_file_offset,
					  view->index->hdr->log_file_seq,
					  view->index->hdr->log_file_int_offset,
					  MAIL_TRANSACTION_EXPUNGE) < 0)
		return -1;
	while ((ret = mail_transaction_log_view_next(view->log_view,
						     &hdr, &data, NULL)) > 0) {
		mail_transaction_log_sort_expunges(*expunges_r,
						   data, hdr->size);
	}

	if (ret == 0) {
		/* convert to sequences */
		src = dest = buffer_get_modifyable_data(*expunges_r, &size);
		src_end = src + size / sizeof(*src);
		for (; src != src_end; src++) {
			ret = mail_index_lookup_uid_range(view, src->uid1,
							  src->uid2,
							  &dest->uid1,
							  &dest->uid2);
			i_assert(ret == 0);

			if (dest->uid1 == 0)
				size -= sizeof(*dest);
			else
				dest++;
		}
		buffer_set_used_size(*expunges_r, size);
	} else {
		buffer_set_used_size(*expunges_r, 0);
	}

	return ret;
}

#define MAIL_INDEX_VIEW_VISIBLE_SYNC_MASK \
	(MAIL_TRANSACTION_EXPUNGE | MAIL_TRANSACTION_APPEND | \
	 MAIL_TRANSACTION_FLAG_UPDATE)

int mail_index_view_sync_begin(struct mail_index_view *view,
                               enum mail_index_sync_type sync_mask,
			       struct mail_index_view_sync_ctx **ctx_r)
{
	const struct mail_index_header *hdr;
	struct mail_index_view_sync_ctx *ctx;
	struct mail_index_map *map;
	enum mail_transaction_type mask, want_mask;
	buffer_t *expunges = NULL;

	/* We must sync flags as long as view is mmap()ed, as the flags may
	   have already changed under us. */
	i_assert((sync_mask & MAIL_INDEX_SYNC_TYPE_FLAGS) != 0);
	i_assert(!view->syncing);

	if (mail_index_view_lock_head(view, TRUE) < 0)
		return -1;

	hdr = view->index->hdr;
	if ((sync_mask & MAIL_INDEX_SYNC_TYPE_EXPUNGE) != 0) {
		/* get list of all expunges first */
		if (view_sync_get_expunges(view, &expunges) < 0)
			return -1;
	}

	/* only flags, appends and expunges can be left to be synced later */
	want_mask = mail_transaction_type_mask_get(sync_mask);
	i_assert((want_mask & ~MAIL_INDEX_VIEW_VISIBLE_SYNC_MASK) == 0);
	mask = want_mask |
		(MAIL_TRANSACTION_TYPE_MASK ^
		 MAIL_INDEX_VIEW_VISIBLE_SYNC_MASK);

	if (mail_transaction_log_view_set(view->log_view,
					  view->log_file_seq,
					  view->log_file_offset,
					  hdr->log_file_seq,
					  hdr->log_file_int_offset, mask) < 0) {
		if (expunges != NULL)
			buffer_free(expunges);
		return -1;
	}

	ctx = i_new(struct mail_index_view_sync_ctx, 1);
	ctx->view = view;
	ctx->trans_sync_mask = want_mask;
	ctx->expunges = expunges;
	mail_index_sync_map_init(&ctx->sync_map_ctx, view,
				 MAIL_INDEX_SYNC_HANDLER_VIEW);

	if ((sync_mask & MAIL_INDEX_SYNC_TYPE_EXPUNGE) != 0 &&
	    (sync_mask & MAIL_INDEX_SYNC_TYPE_APPEND) != 0) {
		view->new_map = view->index->map;
		view->new_map->refcount++;

		/* keep the old mapping without expunges until we're
		   fully synced */
	} else {
		/* we need a private copy of the map if we don't want to
		   sync expunges. we need to sync mapping only if we're not
		   using the latest one. */
		uint32_t old_records_count = view->map->records_count;

		if (view->map != view->index->map) {
			i_assert(view->map->records_count >=
				 view->hdr.messages_count);
                        view->map->records_count = view->hdr.messages_count;
			ctx->sync_map_update = TRUE;
		}

		map = mail_index_map_clone(view->map,
					   view->map->hdr.record_size);
		view->map->records_count = old_records_count;
		mail_index_unmap(view->index, view->map);
		view->map = map;

		if (ctx->sync_map_update) {
			if (map->hdr_base != map->hdr_copy_buf->data) {
				buffer_reset(map->hdr_copy_buf);
				buffer_append(map->hdr_copy_buf, map->hdr_base,
					      map->hdr.header_size);
				map->hdr_base = map->hdr_copy_buf->data;
			}

			/* start from our old view's header. */
			buffer_write(map->hdr_copy_buf, 0,
				     &view->hdr, sizeof(view->hdr));
			map->hdr = view->hdr;
		}

		i_assert(map->records_count == map->hdr.messages_count);
	}

	mail_index_view_unref_maps(view);
	view->syncing = TRUE;

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

	while (data < end) {
		if (*((const uoff_t *)data) == offset &&
		    *((const uint32_t *)(data + sizeof(uoff_t))) == seq)
			return 1;
		data += sizeof(uoff_t) + sizeof(uint32_t);
	}

	return 0;
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

		ctx->hdr = NULL;
		ctx->last_read = TRUE;
		return 1;
	}

	if (skipped)
		ctx->skipped_some = TRUE;

	mail_transaction_log_view_get_prev_pos(log_view, seq_r, offset_r);

	/* skip flag changes that we committed ourself or have already synced */
	if (view_is_transaction_synced(view, *seq_r, *offset_r))
		return 0;

	/* expunges have to be synced afterwards so that caller can still get
	   information of the messages. otherwise caller most likely wants to
	   see only updated information. */
	if (ctx->sync_map_update &&
	    (ctx->hdr->type & MAIL_TRANSACTION_EXPUNGE) == 0) {
		if (mail_index_sync_record(&ctx->sync_map_ctx, ctx->hdr,
					   ctx->data) < 0)
			return -1;
	}

	if ((ctx->hdr->type & ctx->trans_sync_mask) == 0)
		return 0;

	return 1;
}

#define FLAG_UPDATE_IS_INTERNAL(u, empty) \
	((((u)->add_flags | (u)->remove_flags) & \
	  ~(MAIL_INDEX_MAIL_FLAG_DIRTY | MAIL_RECENT)) == 0 && \
	 memcmp((u)->add_keywords, empty, INDEX_KEYWORDS_BYTE_COUNT) == 0 && \
	 memcmp((u)->add_keywords, empty, INDEX_KEYWORDS_BYTE_COUNT) == 0)

static int
mail_index_view_sync_get_rec(struct mail_index_view_sync_ctx *ctx,
			     struct mail_index_sync_rec *rec)
{
	static keywords_mask_t empty_keywords = { 0, };
	const struct mail_transaction_header *hdr = ctx->hdr;
	const void *data = ctx->data;

	switch (hdr->type & MAIL_TRANSACTION_TYPE_MASK) {
	case MAIL_TRANSACTION_APPEND: {
		rec->type = MAIL_INDEX_SYNC_TYPE_APPEND;
		rec->uid1 = rec->uid2 = 0;
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

		for (;;) {
			ctx->data_offset += sizeof(*update);
			if (!FLAG_UPDATE_IS_INTERNAL(update, empty_keywords))
				break;

			if (ctx->data_offset == ctx->hdr->size)
				return 0;
		}
                mail_index_sync_get_update(rec, update);
		break;
	}
	default:
		i_unreached();
	}
	return 1;
}

int mail_index_view_sync_next(struct mail_index_view_sync_ctx *ctx,
			      struct mail_index_sync_rec *sync_rec)
{
	struct mail_index_view *view = ctx->view;
	uint32_t seq;
	uoff_t offset;
	int ret;

	do {
		if (ctx->hdr == NULL || ctx->data_offset == ctx->hdr->size) {
			ctx->data_offset = 0;
			do {
				ret = mail_index_view_sync_next_trans(ctx, &seq,
								      &offset);
				if (ret < 0)
					return -1;

				if (ctx->last_read)
					return 0;

				if (!ctx->skipped_some) {
					view->log_file_seq = seq;
					view->log_file_offset = offset +
						sizeof(*ctx->hdr) +
						ctx->hdr->size;
				}
			} while (ret == 0);

			if (ctx->skipped_some) {
				mail_index_view_add_synced_transaction(view,
								       seq,
								       offset);
			}
		}
	} while (!mail_index_view_sync_get_rec(ctx, sync_rec));

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

	if (ctx->sync_map_update)
		mail_index_sync_map_deinit(&ctx->sync_map_ctx);

	if (view->log_syncs != NULL && !ctx->skipped_some)
		buffer_set_used_size(view->log_syncs, 0);

	if (!ctx->last_read && ctx->hdr != NULL &&
	    ctx->data_offset != ctx->hdr->size) {
		/* we didn't sync everything */
		view->inconsistent = TRUE;
	}

	if (view->new_map != NULL) {
		mail_index_unmap(view->index, view->map);
		view->map = view->new_map;
		view->new_map = NULL;
	}
	view->hdr = view->map->hdr;

	(void)mail_transaction_log_view_set(view->log_view,
					    view->log_file_seq,
					    view->log_file_offset,
					    view->log_file_seq,
					    view->log_file_offset,
					    MAIL_TRANSACTION_TYPE_MASK);

	if (ctx->expunges != NULL)
		buffer_free(ctx->expunges);

	view->syncing = FALSE;
	i_free(ctx);
}

void mail_index_view_add_synced_transaction(struct mail_index_view *view,
					    uint32_t log_file_seq,
					    uoff_t log_file_offset)
{
	if (view->log_syncs == NULL)
		view->log_syncs = buffer_create_dynamic(default_pool, 128);
	buffer_append(view->log_syncs, &log_file_offset,
		      sizeof(log_file_offset));
	buffer_append(view->log_syncs, &log_file_seq, sizeof(log_file_seq));
}
