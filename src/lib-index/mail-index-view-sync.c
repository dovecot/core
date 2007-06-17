/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "buffer.h"
#include "mail-index-view-private.h"
#include "mail-index-sync-private.h"
#include "mail-transaction-log.h"

struct mail_index_view_sync_ctx {
	struct mail_index_view *view;
	enum mail_index_view_sync_flags flags;
	struct mail_index_sync_map_ctx sync_map_ctx;
	ARRAY_TYPE(seq_range) expunges;

	const struct mail_transaction_header *hdr;
	const void *data;

	size_t data_offset;
	unsigned int sync_map_update:1;
	unsigned int skipped_expunges:1;
	unsigned int last_read:1;
};

static int
mail_transaction_log_sort_expunges(ARRAY_TYPE(seq_range) *expunges,
				   const struct seq_range *src, size_t src_size)
{
	/* Note that all the sequences are actually still UIDs at this point */
	const struct seq_range *src_end;
	struct seq_range *dest, new_exp;
	unsigned int first, i, dest_count;

	i_assert(src_size % sizeof(*src) == 0);

	/* @UNSAFE */
	dest = array_get_modifiable(expunges, &dest_count);
	if (dest_count == 0) {
		array_append(expunges, src, src_size / sizeof(*src));
		return 0;
	}

	src_end = CONST_PTR_OFFSET(src, src_size);
	for (i = 0; src != src_end; src++) {
		/* src[] must be sorted. */
		if (src->seq1 > src->seq2 ||
		    (src+1 != src_end && src->seq2 >= src[1].seq1))
			return -1;

		for (; i < dest_count; i++) {
			if (src->seq1 < dest[i].seq1)
				break;
		}

		new_exp = *src;

		first = i;
		while (i < dest_count && src->seq2 >= dest[i].seq1-1) {
			/* we can/must merge with next record */
			if (new_exp.seq2 < dest[i].seq2)
				new_exp.seq2 = dest[i].seq2;
			i++;
		}

		if (first > 0 && new_exp.seq1 <= dest[first-1].seq2+1) {
			/* continue previous record */
			if (dest[first-1].seq2 < new_exp.seq2)
				dest[first-1].seq2 = new_exp.seq2;
		} else if (i == first) {
			array_insert(expunges, i, &new_exp, 1);
			i++; first++;

			dest = array_get_modifiable(expunges, &dest_count);
		} else {
			/* use next record */
			dest[first] = new_exp;
			first++;
		}

		if (i > first) {
			array_delete(expunges, first, i - first);

			dest = array_get_modifiable(expunges, &dest_count);
			i = first;
		}
	}
	return 0;
}

static int view_sync_set_log_view_range(struct mail_index_view *view)
{
	const struct mail_index_header *hdr = view->index->hdr;
	int ret;

	/* the view begins from the first non-synced transaction */
	ret = mail_transaction_log_view_set(view->log_view,
					    view->log_file_expunge_seq,
					    view->log_file_expunge_offset,
					    hdr->log_file_seq,
					    hdr->log_file_head_offset);
	if (ret <= 0) {
		if (ret == 0) {
			/* FIXME: use the new index to get needed changes */
			mail_index_set_error(view->index,
				"Transaction log got desynced for index %s",
				view->index->filepath);
			mail_index_set_inconsistent(view->index);
		}
		return -1;
	}
	return 0;
}

static int
view_sync_get_expunges(struct mail_index_view *view,
		       ARRAY_TYPE(seq_range) *expunges_r)
{
	const struct mail_transaction_header *hdr;
	struct seq_range *src, *src_end, *dest;
	const void *data;
	unsigned int count;
	int ret;

	if (view_sync_set_log_view_range(view) < 0)
		return -1;

	/* get a list of expunge transactions. there may be some that we have
	   already synced, but it doesn't matter because they'll get dropped
	   out when converting to sequences */
	i_array_init(expunges_r, 64);
	while ((ret = mail_transaction_log_view_next(view->log_view,
						     &hdr, &data)) > 0) {
		if ((hdr->type & MAIL_TRANSACTION_EXPUNGE) == 0)
			continue;
		if ((hdr->type & MAIL_TRANSACTION_EXTERNAL) == 0) {
			/* this is simply a request for expunge */
			continue;
		}

		if (mail_transaction_log_sort_expunges(expunges_r, data,
						       hdr->size) < 0) {
			mail_transaction_log_view_set_corrupted(view->log_view,
				"Corrupted expunge record");
			ret = -1;
			break;
		}
	}

	if (ret < 0) {
		array_free(expunges_r);
		return -1;
	}

	/* convert UIDs to sequences */
	src = dest = array_get_modifiable(expunges_r, &count);
	src_end = src + count;
	for (; src != src_end; src++) {
		ret = mail_index_lookup_uid_range(view, src->seq1,
						  src->seq2,
						  &dest->seq1,
						  &dest->seq2);
		i_assert(ret == 0);

		if (dest->seq1 == 0)
			count--;
		else
			dest++;
	}
	array_delete(expunges_r, count, array_count(expunges_r) - count);
	return 0;
}

#ifdef DEBUG
static void mail_index_view_check(struct mail_index_view *view)
{
	unsigned int i, del = 0, recent = 0, seen = 0;

	i_assert(view->hdr.messages_count == view->map->records_count);
	i_assert(view->hdr.deleted_messages_count ==
		 view->map->hdr.deleted_messages_count);
	i_assert(view->hdr.recent_messages_count ==
		 view->map->hdr.recent_messages_count);
	i_assert(view->hdr.seen_messages_count ==
		 view->map->hdr.seen_messages_count);

	for (i = 0; i < view->map->records_count; i++) {
		const struct mail_index_record *rec;

		rec = MAIL_INDEX_MAP_IDX(view->map, i);

		if (rec->flags & MAIL_DELETED) {
			i_assert(rec->uid >= view->hdr.first_deleted_uid_lowwater);
			del++;
		}
		if (rec->flags & MAIL_RECENT) {
			i_assert(rec->uid >= view->hdr.first_recent_uid_lowwater);
			recent++;
		}
		if (rec->flags & MAIL_SEEN)
			seen++;
		else
			i_assert(rec->uid >= view->hdr.first_unseen_uid_lowwater);
	}
	i_assert(del == view->hdr.deleted_messages_count);
	i_assert(recent == view->hdr.recent_messages_count);
	i_assert(seen == view->hdr.seen_messages_count);
}
#endif

#define VIEW_IS_SYNCED_TO_SAME(hdr, tail_seq, tail_offset) \
	((hdr)->log_file_seq == (tail_seq) && \
	 (hdr)->log_file_head_offset == (tail_offset))

int mail_index_view_sync_begin(struct mail_index_view *view,
                               enum mail_index_view_sync_flags flags,
			       struct mail_index_view_sync_ctx **ctx_r)
{
	struct mail_index_view_sync_ctx *ctx;
	struct mail_index_map *map;
	ARRAY_TYPE(seq_range) expunges = ARRAY_INIT;

	i_assert(!view->syncing);
	i_assert(view->transactions == 0);

	if (mail_index_view_lock_head(view) < 0)
		return -1;

	if ((flags & MAIL_INDEX_VIEW_SYNC_FLAG_NOEXPUNGES) == 0) {
		/* get list of all expunges first */
		if (view_sync_get_expunges(view, &expunges) < 0)
			return -1;
	}

	if (view_sync_set_log_view_range(view) < 0) {
		if (array_is_created(&expunges))
			array_free(&expunges);
		return -1;
	}

	ctx = i_new(struct mail_index_view_sync_ctx, 1);
	ctx->view = view;
	ctx->flags = flags;
	ctx->expunges = expunges;
	mail_index_sync_map_init(&ctx->sync_map_ctx, view,
				 MAIL_INDEX_SYNC_HANDLER_VIEW);

	if ((flags & MAIL_INDEX_VIEW_SYNC_FLAG_NOEXPUNGES) == 0) {
		view->sync_new_map = view->index->map;
		view->sync_new_map->refcount++;

		/* keep the old mapping without expunges until we're
		   fully synced */
	} else {
		/* We need a private copy of the map if we don't want to
		   sync expunges.

		   If view's map is the head map, it means that it contains
		   already all the latest changes and there's no need for us
		   to apply any changes to it. This can only happen if there
		   hadn't been any expunges. */
		if (view->map != view->index->map) {
			/* Using non-head mapping. We have to apply
			   transactions to it to get latest changes into it. */
			ctx->sync_map_update = TRUE;
		}

		/* Unless map was synced at the exact same position as
		   view, the message flags can't be reliably used to
		   update flag counters. note that map->hdr may contain
		   old information if another process updated the
		   index file since. */
		if (view->map->mmap_base != NULL) {
			// FIXME: locking should do this..?..
			const struct mail_index_header *hdr;

			hdr = view->map->mmap_base;
			view->map->hdr = *hdr;
		}

#ifdef DEBUG
		i_assert(view->map->hdr.messages_count ==
			 view->hdr.messages_count);
		mail_index_view_check(view);
#endif

		if (view->map->refcount > 1) {
			map = mail_index_map_clone(view->map);
			mail_index_unmap(view->index, &view->map);
			view->map = map;
		} else {
			map = view->map;
		}
		view->hdr = map->hdr;
		i_assert(map->records_count == map->hdr.messages_count);
	}

	/* Syncing the view invalidates all previous looked up records.
	   Unreference the mappings this view keeps because of them. */
	mail_index_view_unref_maps(view);
	view->syncing = TRUE;

	*ctx_r = ctx;
	return 0;
}

static bool
view_sync_area_find(struct mail_index_view *view, uint32_t seq, uoff_t offset)
{
	const struct mail_index_view_log_sync_area *syncs;
	unsigned int i, count;

	if (!array_is_created(&view->syncs_hidden))
		return FALSE;

	syncs = array_get(&view->syncs_hidden, &count);
	for (i = 0; i < count; i++) {
		if (syncs[i].log_file_offset <= offset &&
		    offset - syncs[i].log_file_offset < syncs[i].length &&
		    syncs[i].log_file_seq == seq)
			return TRUE;
	}

	return FALSE;
}

static bool
mail_index_view_sync_want(struct mail_index_view_sync_ctx *ctx,
			  const struct mail_transaction_header *hdr)
{
        struct mail_index_view *view = ctx->view;
	uint32_t seq;
	uoff_t offset, next_offset;

	mail_transaction_log_view_get_prev_pos(view->log_view, &seq, &offset);
	next_offset = offset + sizeof(*hdr) + hdr->size;

	if ((hdr->type & MAIL_TRANSACTION_EXPUNGE) != 0 &&
	    (hdr->type & MAIL_TRANSACTION_EXTERNAL) != 0) {
		if ((ctx->flags & MAIL_INDEX_VIEW_SYNC_FLAG_NOEXPUNGES) != 0) {
			i_assert(!LOG_IS_BEFORE(seq, offset,
						view->log_file_expunge_seq,
						view->log_file_expunge_offset));
			if (!ctx->skipped_expunges) {
				view->log_file_expunge_seq = seq;
				view->log_file_expunge_offset = offset;
				ctx->skipped_expunges = TRUE;
			}
			return FALSE;
		}
		if (LOG_IS_BEFORE(seq, offset, view->log_file_expunge_seq,
				  view->log_file_expunge_offset)) {
			/* already synced */
			return FALSE;
		}
	}

	if (LOG_IS_BEFORE(seq, offset, view->log_file_head_seq,
			  view->log_file_head_offset)) {
		/* already synced */
		return FALSE;
	}

	view->log_file_head_seq = seq;
	view->log_file_head_offset = next_offset;
	return TRUE;
}

static int
mail_index_view_sync_get_next_transaction(struct mail_index_view_sync_ctx *ctx)
{
        struct mail_transaction_log_view *log_view = ctx->view->log_view;
	struct mail_index_view *view = ctx->view;
	const struct mail_transaction_header *hdr;
	uint32_t seq;
	uoff_t offset;
	int ret;
	bool synced_to_map;

	for (;;) {
		/* Get the next transaction from log. */
		ret = mail_transaction_log_view_next(log_view, &ctx->hdr,
						     &ctx->data);
		if (ret <= 0) {
			if (ret < 0)
				return -1;

			ctx->hdr = NULL;
			ctx->last_read = TRUE;
			return 0;
		}

		hdr = ctx->hdr;
		if (!mail_index_view_sync_want(ctx, hdr)) {
			/* This is a visible record that we don't want to
			   sync. */
			continue;
		}

		mail_transaction_log_view_get_prev_pos(log_view, &seq, &offset);

		/* If we started from a map that we didn't create ourself,
		   some of the transactions may already be synced. at the end
		   of this view sync we'll update file_seq=0 so that this check
		   always becomes FALSE for subsequent syncs. */
		synced_to_map = view->map->hdr.log_file_seq != 0 &&
			!LOG_IS_BEFORE(seq, offset,
				       view->map->hdr.log_file_seq,
				       view->map->hdr.log_file_head_offset);

		/* Apply transaction to view's mapping if needed (meaning we
		   didn't just re-map the view to head mapping). */
		if (ctx->sync_map_update && !synced_to_map) {
			i_assert((hdr->type & MAIL_TRANSACTION_EXPUNGE) == 0 ||
				 (hdr->type & MAIL_TRANSACTION_EXTERNAL) == 0);

			if (mail_index_sync_record(&ctx->sync_map_ctx,
						   hdr, ctx->data) < 0)
				return -1;
		}

		/* skip changes committed by hidden transactions (eg. in IMAP
		   store +flags.silent command) */
		if (view_sync_area_find(view, seq, offset))
			continue;
		break;
	}
	return 1;
}

#define FLAG_UPDATE_IS_INTERNAL(u) \
	((((u)->add_flags | (u)->remove_flags) & \
	  ~(MAIL_INDEX_MAIL_FLAG_DIRTY | MAIL_RECENT)) == 0)

static bool
mail_index_view_sync_get_rec(struct mail_index_view_sync_ctx *ctx,
			     struct mail_index_view_sync_rec *rec)
{
	const struct mail_transaction_header *hdr = ctx->hdr;
	const void *data = ctx->data;

	switch (hdr->type & MAIL_TRANSACTION_TYPE_MASK) {
	case MAIL_TRANSACTION_APPEND: {
		/* data contains the appended records, but we don't care */
		rec->type = MAIL_INDEX_SYNC_TYPE_APPEND;
		rec->uid1 = rec->uid2 = 0;
		ctx->data_offset += hdr->size;
		break;
	}
	case MAIL_TRANSACTION_EXPUNGE: {
		const struct mail_transaction_expunge *exp =
			CONST_PTR_OFFSET(data, ctx->data_offset);

		if ((hdr->type & MAIL_TRANSACTION_EXTERNAL) == 0) {
			/* this is simply a request for expunge */
			ctx->data_offset = ctx->hdr->size;
			return 0;
		}

		/* data contains mail_transaction_expunge[] */
		rec->type = MAIL_INDEX_SYNC_TYPE_EXPUNGE;
		rec->uid1 = exp->uid1;
		rec->uid2 = exp->uid2;

		ctx->data_offset += sizeof(*exp);
		break;
	}
	case MAIL_TRANSACTION_FLAG_UPDATE: {
		const struct mail_transaction_flag_update *update =
			CONST_PTR_OFFSET(data, ctx->data_offset);

		/* data contains mail_transaction_flag_update[] */
		for (;;) {
			ctx->data_offset += sizeof(*update);
			if (!FLAG_UPDATE_IS_INTERNAL(update))
				break;

			/* skip internal flag changes */
			if (ctx->data_offset == ctx->hdr->size)
				return 0;

			update = CONST_PTR_OFFSET(data, ctx->data_offset);
		}

		rec->type = MAIL_INDEX_SYNC_TYPE_FLAGS;
		rec->uid1 = update->uid1;
		rec->uid2 = update->uid2;
		break;
	}
	case MAIL_TRANSACTION_KEYWORD_UPDATE: {
		const struct mail_transaction_keyword_update *update = data;
		const uint32_t *uids;

		/* data contains mail_transaction_keyword_update header,
		   the keyword name and an array of { uint32_t uid1, uid2; } */

		if (ctx->data_offset == 0) {
			/* skip over the header and name */
			ctx->data_offset = sizeof(*update) + update->name_size;
			if ((ctx->data_offset % 4) != 0)
				ctx->data_offset += 4 - (ctx->data_offset % 4);
		}

		uids = CONST_PTR_OFFSET(data, ctx->data_offset);
		rec->type = MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD;
		rec->uid1 = uids[0];
		rec->uid2 = uids[1];

		ctx->data_offset += sizeof(uint32_t) * 2;
		break;
	}
	case MAIL_TRANSACTION_KEYWORD_RESET: {
		const struct mail_transaction_keyword_reset *reset =
			CONST_PTR_OFFSET(data, ctx->data_offset);

		/* data contains mail_transaction_keyword_reset[] */
		rec->type = MAIL_INDEX_SYNC_TYPE_KEYWORD_RESET;
		rec->uid1 = reset->uid1;
		rec->uid2 = reset->uid2;
		ctx->data_offset += sizeof(*reset);
		break;
	}
	default:
		ctx->hdr = NULL;
		return FALSE;
	}
	return TRUE;
}

int mail_index_view_sync_next(struct mail_index_view_sync_ctx *ctx,
			      struct mail_index_view_sync_rec *sync_rec)
{
	int ret;

	do {
		if (ctx->hdr == NULL || ctx->data_offset == ctx->hdr->size) {
			ret = mail_index_view_sync_get_next_transaction(ctx);
			if (ret <= 0)
				return ret;

			ctx->data_offset = 0;
		}
	} while (!mail_index_view_sync_get_rec(ctx, sync_rec));

	return 1;
}

void mail_index_view_sync_get_expunges(struct mail_index_view_sync_ctx *ctx,
				       const ARRAY_TYPE(seq_range) **expunges_r)
{
	*expunges_r = &ctx->expunges;
}

static void
mail_index_view_sync_clean_log_syncs(struct mail_index_view *view)
{
	const struct mail_index_view_log_sync_area *syncs;
	unsigned int i, count;

	if (!array_is_created(&view->syncs_hidden))
		return;

	/* Clean up to view's tail */
	syncs = array_get(&view->syncs_hidden, &count);
	for (i = 0; i < count; i++) {
		if ((syncs[i].log_file_offset +
		     syncs[i].length > view->log_file_expunge_offset &&
                     syncs[i].log_file_seq == view->log_file_expunge_seq) ||
		    syncs[i].log_file_seq > view->log_file_expunge_seq)
			break;
	}
	if (i > 0)
		array_delete(&view->syncs_hidden, 0, i);
}

void mail_index_view_sync_end(struct mail_index_view_sync_ctx **_ctx)
{
        struct mail_index_view_sync_ctx *ctx = *_ctx;
        struct mail_index_view *view = ctx->view;

	i_assert(view->syncing);

	*_ctx = NULL;

	if (!ctx->last_read) {
		/* we didn't sync everything */
		view->inconsistent = TRUE;
	}

	if (view->sync_new_map != NULL) {
		mail_index_unmap(view->index, &view->map);
		view->map = view->sync_new_map;
		view->sync_new_map = NULL;
	}

	if (!ctx->skipped_expunges) {
		view->log_file_expunge_seq = view->log_file_head_seq;
		view->log_file_expunge_offset = view->log_file_head_offset;
	}

	if (ctx->sync_map_update) {
		/* log offsets have no meaning in views. make sure they're not
		   tried to be used wrong by setting them to zero. */
		view->map->hdr.log_file_seq = 0;
		view->map->hdr.log_file_head_offset = 0;
		view->map->hdr.log_file_tail_offset = 0;
	}
	view->hdr = view->map->hdr;

	mail_index_sync_map_deinit(&ctx->sync_map_ctx);
	mail_index_view_sync_clean_log_syncs(ctx->view);

#ifdef DEBUG
	mail_index_view_check(view);
#endif

	/* set log view to empty range so unneeded memory gets freed */
	(void)mail_transaction_log_view_set(view->log_view,
					    view->log_file_head_seq,
					    view->log_file_head_offset,
					    view->log_file_head_seq,
					    view->log_file_head_offset);

	if (array_is_created(&ctx->expunges))
		array_free(&ctx->expunges);

	view->syncing = FALSE;
	i_free(ctx);
}

void mail_index_view_add_hidden_transaction(struct mail_index_view *view,
					    uint32_t log_file_seq,
					    uoff_t log_file_offset,
					    unsigned int length)
{
	struct mail_index_view_log_sync_area *area;

	if (!array_is_created(&view->syncs_hidden))
		i_array_init(&view->syncs_hidden, 32);

	area = array_append_space(&view->syncs_hidden);
	area->log_file_seq = log_file_seq;
	area->log_file_offset = log_file_offset;
	area->length = length;
}
