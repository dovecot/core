/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "buffer.h"
#include "mail-index-view-private.h"
#include "mail-index-sync-private.h"
#include "mail-transaction-log.h"
#include "mail-transaction-util.h"

struct mail_index_view_sync_ctx {
	struct mail_index_view *view;
	enum mail_transaction_type trans_sync_mask;
	struct mail_index_sync_map_ctx sync_map_ctx;
	array_t ARRAY_DEFINE(expunges, struct mail_transaction_expunge);

	const struct mail_transaction_header *hdr;
	const void *data;

	size_t data_offset;
	unsigned int skipped_some:1;
	unsigned int last_read:1;
	unsigned int sync_map_update:1;
};

struct mail_index_view_log_sync_pos {
	uint32_t log_file_seq;
	uoff_t log_file_offset;
};

static void
mail_transaction_log_sort_expunges(array_t *expunges,
				   const struct mail_transaction_expunge *src,
				   size_t src_size)
{
	ARRAY_SET_TYPE(expunges, struct mail_transaction_expunge);
	const struct mail_transaction_expunge *src_end;
	struct mail_transaction_expunge *dest;
	struct mail_transaction_expunge new_exp;
	unsigned int first, i, dest_count;

	i_assert(src_size % sizeof(*src) == 0);

	/* @UNSAFE */
	dest = array_get_modifyable(expunges, &dest_count);
	if (dest_count == 0) {
		array_append(expunges, src, src_size / sizeof(*src));
		return;
	}

	src_end = CONST_PTR_OFFSET(src, src_size);
	for (i = 0; src != src_end; src++) {
		/* src[] must be sorted. */
		i_assert(src+1 == src_end || src->uid2 < src[1].uid1);
		i_assert(src->uid1 <= src->uid2);

		for (; i < dest_count; i++) {
			if (src->uid1 < dest[i].uid1)
				break;
		}

		new_exp = *src;

		first = i;
		while (i < dest_count && src->uid2 >= dest[i].uid1-1) {
			/* we can/must merge with next record */
			if (new_exp.uid2 < dest[i].uid2)
				new_exp.uid2 = dest[i].uid2;
			i++;
		}

		if (first > 0 && new_exp.uid1 <= dest[first-1].uid2+1) {
			/* continue previous record */
			if (dest[first-1].uid2 < new_exp.uid2)
				dest[first-1].uid2 = new_exp.uid2;
		} else if (i == first) {
			array_insert(expunges, i, &new_exp, 1);
			i++; first++;

			dest = array_get_modifyable(expunges, &dest_count);
		} else {
			/* use next record */
			dest[first] = new_exp;
			first++;
		}

		if (i > first) {
			array_delete(expunges, first, i - first);

			dest = array_get_modifyable(expunges, &dest_count);
			i = first;
		}
	}
}

static int
view_sync_get_expunges(struct mail_index_view *view, array_t *expunges_r)
{
	ARRAY_SET_TYPE(expunges_r, struct mail_transaction_expunge);
	const struct mail_transaction_header *hdr;
	struct mail_transaction_expunge *src, *src_end, *dest;
	const void *data;
	unsigned int count;
	int ret;

	if (mail_transaction_log_view_set(view->log_view,
					  view->log_file_seq,
					  view->log_file_offset,
					  view->index->hdr->log_file_seq,
					  view->index->hdr->log_file_int_offset,
					  MAIL_TRANSACTION_EXPUNGE) < 0)
		return -1;

	ARRAY_CREATE(expunges_r, default_pool,
		     struct mail_transaction_expunge, 64);
	while ((ret = mail_transaction_log_view_next(view->log_view,
						     &hdr, &data, NULL)) > 0) {
		i_assert((hdr->type & MAIL_TRANSACTION_EXPUNGE) != 0);
		mail_transaction_log_sort_expunges(expunges_r, data, hdr->size);
	}

	if (ret < 0) {
		array_free(expunges_r);
		return -1;
	}

	/* convert to sequences */
	src = dest = array_get_modifyable(expunges_r, &count);
	src_end = src + count;
	for (; src != src_end; src++) {
		ret = mail_index_lookup_uid_range(view, src->uid1,
						  src->uid2,
						  &dest->uid1,
						  &dest->uid2);
		i_assert(ret == 0);

		if (dest->uid1 == 0)
			count--;
		else
			dest++;
	}
	array_delete(expunges_r, count, array_count(expunges_r) - count);
	return 0;
}

#define MAIL_INDEX_VIEW_VISIBLE_SYNC_MASK \
	(MAIL_TRANSACTION_EXPUNGE | MAIL_TRANSACTION_APPEND | \
	 MAIL_TRANSACTION_FLAG_UPDATE | MAIL_TRANSACTION_KEYWORD_UPDATE | \
	 MAIL_TRANSACTION_KEYWORD_RESET)

int mail_index_view_sync_begin(struct mail_index_view *view,
                               enum mail_index_sync_type sync_mask,
			       struct mail_index_view_sync_ctx **ctx_r)
{
	const struct mail_index_header *hdr;
	struct mail_index_view_sync_ctx *ctx;
	struct mail_index_map *map;
	enum mail_transaction_type mask, want_mask;
	array_t expunges = { 0, 0 };

	/* We must sync flags as long as view is mmap()ed, as the flags may
	   have already changed under us. */
	i_assert((sync_mask & MAIL_INDEX_SYNC_TYPE_FLAGS) != 0);
	/* Currently we're not handling correctly expunges + no-appends case */
	i_assert((sync_mask & MAIL_INDEX_SYNC_TYPE_EXPUNGE) == 0 ||
		 (sync_mask & MAIL_INDEX_SYNC_TYPE_APPEND) != 0);

	i_assert(!view->syncing);
	i_assert(view->transactions == 0);

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
		if (array_is_created(&expunges))
			array_free(&expunges);
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
	const struct mail_index_view_log_sync_pos *pos, *end;
	size_t size;

	if (view->log_syncs == NULL)
		return 0;

	pos = buffer_get_data(view->log_syncs, &size);
	end = CONST_PTR_OFFSET(pos, size);

	for (; pos != end; pos++) {
		if (pos->log_file_offset == offset && pos->log_file_seq == seq)
			return 1;
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

#define FLAG_UPDATE_IS_INTERNAL(u) \
	((((u)->add_flags | (u)->remove_flags) & \
	  ~(MAIL_INDEX_MAIL_FLAG_DIRTY | MAIL_RECENT)) == 0)

static int
mail_index_view_sync_get_rec(struct mail_index_view_sync_ctx *ctx,
			     struct mail_index_sync_rec *rec)
{
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
			if (!FLAG_UPDATE_IS_INTERNAL(update))
				break;

			if (ctx->data_offset == ctx->hdr->size)
				return 0;

			update = CONST_PTR_OFFSET(data, ctx->data_offset);
		}
                mail_index_sync_get_update(rec, update);
		break;
	}
	case MAIL_TRANSACTION_KEYWORD_UPDATE: {
		const struct mail_transaction_keyword_update *update = data;
		const uint32_t *uids;

		if (ctx->data_offset == 0) {
			ctx->data_offset = sizeof(*update) + update->name_size;
			if ((ctx->data_offset % 4) != 0)
				ctx->data_offset += 4 - (ctx->data_offset % 4);
		}

		uids = CONST_PTR_OFFSET(data, ctx->data_offset);
		/* FIXME: this isn't exactly correct.. but no-one cares? */
		rec->type = MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD;
		rec->uid1 = uids[0];
		rec->uid2 = uids[1];
		ctx->data_offset += sizeof(uint32_t) * 2;
		break;
	}
	case MAIL_TRANSACTION_KEYWORD_RESET: {
		const struct mail_transaction_keyword_reset *reset =
			CONST_PTR_OFFSET(data, ctx->data_offset);

		rec->type = MAIL_INDEX_SYNC_TYPE_KEYWORD_RESET;
		rec->uid1 = reset->uid1;
		rec->uid2 = reset->uid2;
		ctx->data_offset += sizeof(*reset);
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
				  unsigned int *count_r)
{
	const struct mail_transaction_expunge *data;

	data = array_get(&ctx->expunges, count_r);
	return (const uint32_t *)data;
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

	if (array_is_created(&ctx->expunges))
		array_free(&ctx->expunges);

	view->syncing = FALSE;
	i_free(ctx);
}

void mail_index_view_add_synced_transaction(struct mail_index_view *view,
					    uint32_t log_file_seq,
					    uoff_t log_file_offset)
{
	struct mail_index_view_log_sync_pos pos;

	memset(&pos, 0, sizeof(pos));
	pos.log_file_seq = log_file_seq;
	pos.log_file_offset = log_file_offset;

	if (view->log_syncs == NULL)
		view->log_syncs = buffer_create_dynamic(default_pool, 128);
	buffer_append(view->log_syncs, &pos, sizeof(pos));
}
