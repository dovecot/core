/* Copyright (C) 2004 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "buffer.h"
#include "file-set-size.h"
#include "mmap-util.h"
#include "mail-index-view-private.h"
#include "mail-index-sync-private.h"
#include "mail-transaction-log.h"
#include "mail-transaction-util.h"
#include "mail-cache-private.h"

#include <time.h>

static void
mail_index_header_update_counts(struct mail_index_header *hdr,
				uint8_t old_flags, uint8_t new_flags)
{
	if (((old_flags ^ new_flags) & MAIL_RECENT) != 0) {
		/* different recent-flag */
		if ((old_flags & MAIL_RECENT) == 0)
			hdr->recent_messages_count++;
		else if (--hdr->recent_messages_count == 0)
			hdr->first_recent_uid_lowwater = hdr->next_uid;
	}

	if (((old_flags ^ new_flags) & MAIL_SEEN) != 0) {
		/* different seen-flag */
		if ((old_flags & MAIL_SEEN) != 0)
			hdr->seen_messages_count--;
		else if (++hdr->seen_messages_count == hdr->messages_count)
			hdr->first_unseen_uid_lowwater = hdr->next_uid;
	}

	if (((old_flags ^ new_flags) & MAIL_DELETED) != 0) {
		/* different deleted-flag */
		if ((old_flags & MAIL_DELETED) == 0)
			hdr->deleted_messages_count++;
		else if (--hdr->deleted_messages_count == 0)
			hdr->first_deleted_uid_lowwater = hdr->next_uid;
	}
}

static void
mail_index_header_update_lowwaters(struct mail_index_header *hdr,
				   const struct mail_index_record *rec)
{
	if ((rec->flags & MAIL_RECENT) != 0 &&
	    rec->uid < hdr->first_recent_uid_lowwater)
		hdr->first_recent_uid_lowwater = rec->uid;
	if ((rec->flags & MAIL_SEEN) == 0 &&
	    rec->uid < hdr->first_unseen_uid_lowwater)
		hdr->first_unseen_uid_lowwater = rec->uid;
	if ((rec->flags & MAIL_DELETED) != 0 &&
	    rec->uid < hdr->first_deleted_uid_lowwater)
		hdr->first_deleted_uid_lowwater = rec->uid;
}

static void mail_index_sync_cache_expunge(struct mail_index_sync_map_ctx *ctx,
					  uoff_t cache_offset)
{
	if (!ctx->update_cache)
		return;

	if (!ctx->cache_locked) {
		if (mail_cache_lock(ctx->view->index->cache) <= 0)
			return;
		ctx->cache_locked = TRUE;
	}

	(void)mail_cache_delete(ctx->view->index->cache, cache_offset);
}

static int sync_expunge(const struct mail_transaction_expunge *e, void *context)
{
        struct mail_index_sync_map_ctx *ctx = context;
	struct mail_index_view *view = ctx->view;
	struct mail_index_map *map = view->map;
	struct mail_index_header *hdr = &map->hdr_copy;
	struct mail_index_record *rec;
	uint32_t count, seq, seq1, seq2;

	i_assert(MAIL_INDEX_MAP_IS_IN_MEMORY(map));

	if (mail_index_lookup_uid_range(view, e->uid1, e->uid2,
					&seq1, &seq2) < 0)
		return -1;

	if (seq1 == 0)
		return 1;

	for (seq = seq1; seq <= seq2; seq++) {
                rec = MAIL_INDEX_MAP_IDX(map, seq-1);
		mail_index_header_update_counts(hdr, rec->flags, 0);
		
		if (rec->cache_offset != 0)
			mail_index_sync_cache_expunge(ctx, rec->cache_offset);
	}

	/* @UNSAFE */
	count = seq2 - seq1 + 1;
	memmove(MAIL_INDEX_MAP_IDX(map, seq1-1), MAIL_INDEX_MAP_IDX(map, seq2),
		(map->records_count - seq2) * map->hdr->record_size);

	map->records_count -= count;
	hdr->messages_count -= count;
	view->messages_count -= count;

	if (map->buffer != NULL) {
		buffer_set_used_size(map->buffer, map->records_count *
				     map->hdr->record_size);
		map->records = buffer_get_modifyable_data(map->buffer, NULL);
	}
	return 1;
}

static int sync_append(const struct mail_transaction_append_header *hdr,
		       const struct mail_index_record *rec, void *context)
{
        struct mail_index_sync_map_ctx *ctx = context;
	struct mail_index_view *view = ctx->view;
	struct mail_index_map *map = view->map;
	void *dest;

	i_assert(hdr->record_size <= map->hdr->record_size);

	if (rec->uid < map->hdr_copy.next_uid) {
		mail_transaction_log_view_set_corrupted(view->log_view,
			"Append with UID %u, but next_uid = %u",
			rec->uid, map->hdr_copy.next_uid);
		return -1;
	}

	if (MAIL_INDEX_MAP_IS_IN_MEMORY(map)) {
		i_assert(map->records_count * map->hdr->record_size ==
			 buffer_get_used_size(map->buffer));
		dest = buffer_append_space_unsafe(map->buffer,
						  map->hdr->record_size);
		map->records = buffer_get_modifyable_data(map->buffer, NULL);
	} else {
		i_assert((map->records_count+1) * map->hdr->record_size <=
			 map->mmap_size);
		dest = MAIL_INDEX_MAP_IDX(map, map->records_count);
	}
	memcpy(dest, rec, hdr->record_size);
	memset(PTR_OFFSET(dest, hdr->record_size), 0,
	       map->hdr->record_size - hdr->record_size);

	map->hdr_copy.messages_count++;
	map->hdr_copy.next_uid = rec->uid+1;
	view->messages_count++;
	map->records_count++;

	mail_index_header_update_counts(&map->hdr_copy, 0, rec->flags);
	mail_index_header_update_lowwaters(&map->hdr_copy, rec);
	return 1;
}

static int sync_flag_update(const struct mail_transaction_flag_update *u,
			    void *context)
{
        struct mail_index_sync_map_ctx *ctx = context;
	struct mail_index_view *view = ctx->view;
	struct mail_index_record *rec;
	struct mail_index_header *hdr;
	uint8_t flag_mask, old_flags;
	keywords_mask_t keyword_mask;
	uint32_t i, idx, seq1, seq2;
	int update_keywords;

	if (mail_index_lookup_uid_range(view, u->uid1, u->uid2,
					&seq1, &seq2) < 0)
		return -1;

	if (seq1 == 0)
		return 1;

	hdr = &view->map->hdr_copy;

	if ((u->add_flags & MAIL_INDEX_MAIL_FLAG_DIRTY) != 0)
		hdr->flags |= MAIL_INDEX_HDR_FLAG_HAVE_DIRTY;

	update_keywords = FALSE;
	for (i = 0; i < INDEX_KEYWORDS_BYTE_COUNT; i++) {
		if (u->add_keywords[i] != 0 ||
		    u->remove_keywords[i] != 0)
			update_keywords = TRUE;
		keyword_mask[i] = ~u->remove_keywords[i];
	}
        flag_mask = ~u->remove_flags;

	for (idx = seq1-1; idx < seq2; idx++) {
                rec = MAIL_INDEX_MAP_IDX(view->map, idx);

		old_flags = rec->flags;
		rec->flags = (rec->flags & flag_mask) | u->add_flags;
		if (update_keywords) {
			for (i = 0; i < INDEX_KEYWORDS_BYTE_COUNT; i++) {
				rec->keywords[i] = u->add_keywords[i] |
					(rec->keywords[i] & keyword_mask[i]);
			}
		}

		mail_index_header_update_counts(hdr, old_flags, rec->flags);
                mail_index_header_update_lowwaters(hdr, rec);
	}
	return 1;
}

static int sync_cache_reset(const struct mail_transaction_cache_reset *u,
			    void *context)
{
        struct mail_index_sync_map_ctx *ctx = context;
	struct mail_index_view *view = ctx->view;
	uint32_t i;

	view->map->hdr_copy.cache_file_seq = u->new_file_seq;

	for (i = 0; i < view->messages_count; i++)
		MAIL_INDEX_MAP_IDX(view->map, i)->cache_offset = 0;
	return 1;
}

static int sync_cache_update(const struct mail_transaction_cache_update *u,
			     void *context)
{
        struct mail_index_sync_map_ctx *ctx = context;
	struct mail_index_view *view = ctx->view;
	struct mail_index_record *rec;
	uint32_t seq;
	int ret;

	if (mail_index_lookup_uid_range(view, u->uid, u->uid, &seq, &seq) < 0)
		return -1;

	if (seq == 0) {
		/* already expunged */
		return 1;
	}

	rec = MAIL_INDEX_MAP_IDX(view->map, seq-1);
	if (rec->cache_offset != 0 && ctx->update_cache) {
		/* we'll need to link the old and new cache records */
		if (!ctx->cache_locked) {
			if ((ret = mail_cache_lock(view->index->cache)) <= 0)
				return ret < 0 ? -1 : 1;
			ctx->cache_locked = TRUE;
		}

		if (mail_cache_link(view->index->cache,
				    rec->cache_offset, u->cache_offset) < 0)
			return -1;
	}
	rec->cache_offset = u->cache_offset;
	return 1;
}

static int sync_header_update(const struct mail_transaction_header_update *u,
			      void *context)
{
        struct mail_index_sync_map_ctx *ctx = context;
	void *data;

	data = PTR_OFFSET(&ctx->view->map->hdr_copy, u->offset);
	memcpy(data, u + 1, u->size);
	return 1;
}

static int
sync_extra_rec_update(const struct mail_transaction_extra_rec_header *hdr,
		      const struct mail_transaction_extra_rec_update *u,
		      void *context)
{
        struct mail_index_sync_map_ctx *ctx = context;
	struct mail_index_view *view = ctx->view;
	struct mail_index_record *rec;
	uint32_t seq;
	uint16_t offset, size;

	/* FIXME: do data_id mapping conversion */

	if (mail_index_lookup_uid_range(view, u->uid, u->uid, &seq, &seq) < 0)
		return -1;

	if (seq != 0) {
		offset = view->index->extra_records[hdr->data_id].offset;
		size = view->index->extra_records[hdr->data_id].size;

		rec = MAIL_INDEX_MAP_IDX(view->map, seq-1);
		memcpy(PTR_OFFSET(rec, offset), u + 1, size);
	}
	return 1;
}

static int mail_index_grow(struct mail_index *index, struct mail_index_map *map,
			   unsigned int count)
{
	struct mail_index_header hdr;
	size_t size;

	if (MAIL_INDEX_MAP_IS_IN_MEMORY(map))
		return 0;

	i_assert(map == index->map);

	size = map->hdr->header_size +
		(map->records_count + count) * map->hdr->record_size;
	if (size <= map->mmap_size)
		return 0;

	/* when we grow fast, do it exponentially */
	if (count < index->last_grow_count)
		count = index->last_grow_count;
	if (count < MAIL_INDEX_MAX_POWER_GROW)
		count = nearest_power(count);
	index->last_grow_count = count;

	size = map->hdr->header_size +
		(map->records_count + count) * map->hdr->record_size;
	if (file_set_size(index->fd, (off_t)size) < 0)
		return mail_index_set_syscall_error(index, "file_set_size()");

	/* we only wish to grow the file, but mail_index_map() updates the
	   headers as well and may break our modified hdr_copy. so, take
	   a backup of it and put it back afterwards */
	hdr = map->hdr_copy;

	if (mail_index_map(index, TRUE) <= 0)
		return -1;

	map = index->map;
	map->hdr_copy = hdr;
	map->hdr = &map->hdr_copy;
	map->records_count = map->hdr->messages_count;

	i_assert(map->mmap_size >= size);
	return 0;
}

static void mail_index_sync_replace_map(struct mail_index_view *view,
					struct mail_index_map *map)
{
	mail_index_unmap(view->index, view->map);
	view->map = map;
	view->map->refcount++;
	mail_index_unmap(view->index, view->index->map);
	view->index->map = map;
	view->index->hdr = map->hdr;
	map->write_to_disk = TRUE;
}

static void
mail_index_update_day_headers(struct mail_index_header *hdr, uint32_t uid)
{
	const int max_days =
		sizeof(hdr->day_first_uid) / sizeof(hdr->day_first_uid[0]);
	struct tm tm;
	time_t stamp;
	int i, days;

	/* get beginning of today */
	tm = *localtime(&ioloop_time);
	tm.tm_hour = 0;
	tm.tm_min = 0;
	tm.tm_sec = 0;
	stamp = mktime(&tm);
	if (stamp == (time_t)-1)
		i_panic("mktime(today) failed");

	if ((time_t)hdr->day_stamp >= stamp)
		return;

	/* get number of days since last message */
	days = (stamp - hdr->day_stamp) / (3600*24);
	if (days > max_days)
		days = max_days;

	/* @UNSAFE: move days forward and fill the missing days with old
	   day_first_uid[0]. */
	memcpy(hdr->day_first_uid + days,
	       hdr->day_first_uid, max_days - days);
	for (i = 1; i < days; i++)
		hdr->day_first_uid[i] = hdr->day_first_uid[0];

	hdr->day_stamp = stamp;
	hdr->day_first_uid[0] = uid;
}

int mail_index_sync_update_index(struct mail_index_sync_ctx *sync_ctx)
{
	struct mail_index *index = sync_ctx->index;
	struct mail_index_view *view = sync_ctx->view;
	struct mail_index_map *map;
        struct mail_index_sync_map_ctx sync_map_ctx;
	const struct mail_transaction_header *hdr;
	const void *data;
	unsigned int count, old_lock_id;
	uint32_t seq, i, first_append_uid;
	uoff_t offset;
	int ret, had_dirty, skipped;

	memset(&sync_map_ctx, 0, sizeof(sync_map_ctx));
	sync_map_ctx.view = view;
        sync_map_ctx.update_cache = TRUE;

	/* we'll have to update view->lock_id to avoid mail_index_view_lock()
	   trying to update the file later. */
	old_lock_id = view->lock_id;
	if (mail_index_lock_exclusive(index, &view->lock_id) < 0)
		return -1;
	mail_index_unlock(index, old_lock_id);

	/* NOTE: locking may change index->map so make sure assignment
	   after locking */
	map = index->map;
	if (MAIL_INDEX_MAP_IS_IN_MEMORY(map))
		map->write_to_disk = TRUE;

	map->hdr_copy = *map->hdr;
	map->hdr = &map->hdr_copy;

	mail_index_unmap(index, view->map);
	view->map = map;
	view->map->refcount++;

        first_append_uid = 0;
	had_dirty = (map->hdr_copy.flags & MAIL_INDEX_HDR_FLAG_HAVE_DIRTY) != 0;
	if (had_dirty)
		map->hdr_copy.flags &= ~MAIL_INDEX_HDR_FLAG_HAVE_DIRTY;

	while ((ret = mail_transaction_log_view_next(view->log_view, &hdr,
						     &data, &skipped)) > 0) {
		if ((hdr->type & MAIL_TRANSACTION_EXPUNGE) != 0 &&
		    !map->write_to_disk) {
			/* expunges have to be atomic. so we'll have to copy
			   the mapping, do the changes there and then finally
			   replace the whole index file. to avoid extra disk
			   I/O we copy the index into memory rather than to
			   temporary file */
			map = mail_index_map_to_memory(map,
						       map->hdr->record_size);
			mail_index_sync_replace_map(view, map);
		}

		if ((hdr->type & MAIL_TRANSACTION_APPEND) != 0) {
                        const struct mail_transaction_append_header *append_hdr;
			const struct mail_index_record *rec;

			rec = CONST_PTR_OFFSET(data, sizeof(*append_hdr));
			if (first_append_uid == 0)
				first_append_uid = rec->uid;

			append_hdr = data;
			if (append_hdr->record_size > map->hdr->record_size) {
				/* we have to grow our record size */
				map = mail_index_map_to_memory(map,
					append_hdr->record_size);
				mail_index_sync_replace_map(view, map);
			}
			count = (hdr->size - sizeof(*append_hdr)) /
				append_hdr->record_size;
			if (mail_index_grow(index, map, count) < 0) {
				ret = -1;
				break;
			}
			map = index->map;
		}

		if (mail_transaction_map(index, hdr, data,
					 &mail_index_map_sync_funcs,
					 &sync_map_ctx) < 0) {
			ret = -1;
			break;
		}
	}

	if (sync_map_ctx.cache_locked) {
		mail_cache_unlock(index->cache);
		sync_map_ctx.cache_locked = FALSE;
	}

	if (ret < 0) {
		mail_index_view_unlock(view);
		return -1;
	}

	i_assert(map->records_count == map->hdr->messages_count);
	i_assert(view->messages_count == map->hdr->messages_count);

	mail_transaction_log_get_head(index->log, &seq, &offset);

	map->hdr_copy.log_file_seq = seq;
	map->hdr_copy.log_file_offset = offset;

	if (first_append_uid != 0)
		mail_index_update_day_headers(&map->hdr_copy, first_append_uid);

	if ((map->hdr_copy.flags & MAIL_INDEX_HDR_FLAG_HAVE_DIRTY) == 0 &&
	    had_dirty) {
		/* do we have dirty flags anymore? */
		const struct mail_index_record *rec;

		for (i = 0; i < map->records_count; i++) {
			rec = MAIL_INDEX_MAP_IDX(map, i);
			if ((rec->flags & MAIL_INDEX_MAIL_FLAG_DIRTY) != 0) {
				map->hdr_copy.flags |=
					MAIL_INDEX_HDR_FLAG_HAVE_DIRTY;
				break;
			}
		}
	}

	if (!MAIL_INDEX_MAP_IS_IN_MEMORY(map)) {
		map->mmap_used_size = index->hdr->header_size +
			map->records_count * map->hdr->record_size;

		memcpy(map->mmap_base, &map->hdr_copy, sizeof(map->hdr_copy));
		if (msync(map->mmap_base, map->mmap_used_size, MS_SYNC) < 0) {
			mail_index_set_syscall_error(index, "msync()");
			ret = -1;
		}
		map->hdr = map->mmap_base;
	}

        mail_index_view_unlock(view);
	return ret;
}

struct mail_transaction_map_functions mail_index_map_sync_funcs = {
	sync_expunge, sync_append, sync_flag_update,
	sync_cache_reset, sync_cache_update, sync_header_update,
	sync_extra_rec_update
};
