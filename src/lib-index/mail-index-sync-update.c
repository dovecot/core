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

	if (!MAIL_CACHE_IS_UNUSABLE(ctx->view->index->cache) &&
	    ctx->view->map->hdr->cache_file_seq !=
	    ctx->view->index->cache->hdr->file_seq)
		(void)mail_cache_delete(ctx->view->index->cache, cache_offset);
}

static int sync_expunge(const struct mail_transaction_expunge *e, void *context)
{
        struct mail_index_sync_map_ctx *ctx = context;
	struct mail_index_view *view = ctx->view;
	struct mail_index_map *map = view->map;
	struct mail_index_header *hdr;
	struct mail_index_record *rec;
	uint32_t count, seq, seq1, seq2;

	i_assert(MAIL_INDEX_MAP_IS_IN_MEMORY(map));

	if (mail_index_lookup_uid_range(view, e->uid1, e->uid2,
					&seq1, &seq2) < 0)
		return -1;

	if (seq1 == 0)
		return 1;

	hdr = buffer_get_modifyable_data(map->hdr_copy_buf, NULL);
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

static int sync_append(const struct mail_index_record *rec, void *context)
{
        struct mail_index_sync_map_ctx *ctx = context;
	struct mail_index_view *view = ctx->view;
	struct mail_index_map *map = view->map;
	struct mail_index_header *hdr;
	void *dest;

	hdr = buffer_get_modifyable_data(map->hdr_copy_buf, NULL);
	if (rec->uid < hdr->next_uid) {
		mail_transaction_log_view_set_corrupted(view->log_view,
			"Append with UID %u, but next_uid = %u",
			rec->uid, hdr->next_uid);
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
	memcpy(dest, rec, sizeof(*rec));
	memset(PTR_OFFSET(dest, sizeof(*rec)), 0,
	       map->hdr->record_size - sizeof(*rec));

	hdr->messages_count++;
	hdr->next_uid = rec->uid+1;
	view->messages_count++;
	map->records_count++;

	mail_index_header_update_counts(hdr, 0, rec->flags);
	mail_index_header_update_lowwaters(hdr, rec);
	return 1;
}

static int sync_flag_update(const struct mail_transaction_flag_update *u,
			    void *context)
{
        struct mail_index_sync_map_ctx *ctx = context;
	struct mail_index_view *view = ctx->view;
	struct mail_index_header *hdr;
	struct mail_index_record *rec;
	uint8_t flag_mask, old_flags;
	keywords_mask_t keyword_mask;
	uint32_t i, idx, seq1, seq2;
	int update_keywords;

	if (mail_index_lookup_uid_range(view, u->uid1, u->uid2,
					&seq1, &seq2) < 0)
		return -1;

	if (seq1 == 0)
		return 1;

	hdr = buffer_get_modifyable_data(view->map->hdr_copy_buf, NULL);

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
	struct mail_index_header *hdr;
	uint32_t i;

	hdr = buffer_get_modifyable_data(view->map->hdr_copy_buf, NULL);
	hdr->cache_file_seq = u->new_file_seq;

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

		if (view->map->hdr->cache_file_seq !=
		    view->index->cache->hdr->file_seq) {
			/* cache has been compressed, don't modify it */
			return 1;
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
	const struct mail_index_header *hdr = ctx->view->map->hdr;

	if (u->offset >= hdr->base_header_size ||
	    u->offset + u->size > hdr->base_header_size) {
		mail_transaction_log_view_set_corrupted(ctx->view->log_view,
			"Header update outside range: %u + %u > %u",
			u->offset, u->size, hdr->base_header_size);
		return -1;
	}

	buffer_write(ctx->view->map->hdr_copy_buf, u->offset, u + 1, u->size);
	ctx->view->map->hdr = ctx->view->map->hdr_copy_buf->data;
	return 1;
}

static int sync_extra_intro(const struct mail_transaction_extra_intro *u,
			    void *context)
{
	struct mail_index_sync_map_ctx *ctx = context;
	struct mail_index_extra_record_info_header einfo_hdr;
	const struct mail_index_extra_record_info *einfo;
	struct mail_index_header *hdr;
	const char *name;
	buffer_t *hdr_buf;
	uint32_t data_id;

	t_push();
	name = t_strndup(u + 1, u->name_size);

	hdr_buf = ctx->view->map->hdr_copy_buf;
	data_id = mail_index_map_register_extra_info(ctx->view->index,
						     ctx->view->map, name,
						     hdr_buf->used, u->hdr_size,
						     u->record_size);

	einfo = ctx->view->index->extra_infos->data;
	einfo += data_id;

	/* name NUL [padding] einfo_hdr [header data] */
	buffer_append(hdr_buf, name, strlen(name)+1);
	if ((hdr_buf->used % 4) != 0)
		buffer_append(hdr_buf, null4, 4 - (hdr_buf->used % 4));

	memset(&einfo_hdr, 0, sizeof(einfo_hdr));
	einfo_hdr.hdr_size = einfo->hdr_size;
	einfo_hdr.record_offset = einfo->record_offset;
	einfo_hdr.record_size = einfo->record_size;
	buffer_append(hdr_buf, &einfo_hdr, sizeof(einfo_hdr));
	buffer_append_zero(hdr_buf, einfo->hdr_size);

	hdr = buffer_get_modifyable_data(hdr_buf, NULL);
	hdr->header_size = hdr_buf->used;

	ctx->view->map->hdr = hdr;

	t_pop();

	if (data_id != u->data_id) {
		mail_transaction_log_view_set_corrupted(ctx->view->log_view,
			"Introduced extra with invalid data id: %u != %u",
			u->data_id, data_id);
		return -1;
	}
	return 1;
}

static int sync_extra_reset(const struct mail_transaction_extra_rec_header *u,
			    void *context)
{
        struct mail_index_sync_map_ctx *ctx = context;
	struct mail_index_view *view = ctx->view;
	struct mail_index_map *map = view->map;
        const struct mail_index_extra_record_info *einfo;
	struct mail_index_record *rec;
	uint32_t i;

	if (map->extra_infos == NULL ||
	    u->data_id >= map->extra_infos->used / sizeof(*einfo)) {
		mail_transaction_log_view_set_corrupted(view->log_view,
			"Extra reset for unknown data id %u",
			u->data_id);
		return -1;
	}

	einfo = map->extra_infos->data;
	einfo += u->data_id;

	memset(buffer_get_space_unsafe(map->hdr_copy_buf,
				       einfo->hdr_offset, einfo->hdr_size),
	       0, einfo->hdr_size);
	map->hdr = map->hdr_copy_buf->data;

	for (i = 0; i < view->messages_count; i++) {
		rec = MAIL_INDEX_MAP_IDX(view->map, i);
		memset(PTR_OFFSET(rec, einfo->record_offset), 0,
		       einfo->record_size);
	}
	return 1;
}

static int
sync_extra_hdr_update(const struct mail_transaction_extra_hdr_update *u,
		      void *context)
{
        struct mail_index_sync_map_ctx *ctx = context;
	struct mail_index_map *map = ctx->view->map;
        const struct mail_index_extra_record_info *einfo;

	if (map->extra_infos == NULL ||
	    u->data_id >= map->extra_infos->used / sizeof(*einfo)) {
		mail_transaction_log_view_set_corrupted(ctx->view->log_view,
			"Extra header update for unknown data id %u",
			u->data_id);
		return -1;
	}

	einfo = map->extra_infos->data;
	einfo += u->data_id;

	buffer_write(map->hdr_copy_buf, einfo->hdr_offset + u->offset,
		     u + 1, u->size);
	map->hdr = map->hdr_copy_buf->data;
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
        const struct mail_index_extra_record_info *einfo;
	uint32_t seq;

	if (view->map->extra_infos == NULL ||
	    hdr->data_id >= view->map->extra_infos->used / sizeof(*einfo)) {
		mail_transaction_log_view_set_corrupted(view->log_view,
			"Extra record update for unknown data id %u",
			hdr->data_id);
		return -1;
	}

	if (mail_index_lookup_uid_range(view, u->uid, u->uid, &seq, &seq) < 0)
		return -1;

	if (seq != 0) {
		einfo = view->map->extra_infos->data;
		einfo += hdr->data_id;

		rec = MAIL_INDEX_MAP_IDX(view->map, seq-1);
		memcpy(PTR_OFFSET(rec, einfo->record_offset),
		       u + 1, einfo->record_size);
	}
	return 1;
}

static int mail_index_grow(struct mail_index *index, struct mail_index_map *map,
			   unsigned int count)
{
	void *hdr_copy;
	size_t size, hdr_copy_size;

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
	t_push();
        hdr_copy_size = map->hdr_copy_buf->used;
	hdr_copy = t_malloc(hdr_copy_size);
	memcpy(hdr_copy, map->hdr_copy_buf->data, hdr_copy_size);

	if (mail_index_map(index, TRUE) <= 0) {
		t_pop();
		return -1;
	}

	map = index->map;
	buffer_reset(map->hdr_copy_buf);
	buffer_append(map->hdr_copy_buf, hdr_copy, hdr_copy_size);
	map->hdr = map->hdr_copy_buf->data;
	map->records_count = map->hdr->messages_count;

	i_assert(map->mmap_size >= size);
	t_pop();
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
	const struct mail_transaction_header *thdr;
	struct mail_index_header *tmphdr;
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

	/* NOTE: locking may change index->map so make sure the assignment is
	   after locking */
	map = index->map;
	if (MAIL_INDEX_MAP_IS_IN_MEMORY(map))
		map->write_to_disk = TRUE;

	if (map->hdr != map->hdr_copy_buf->data) {
		buffer_reset(map->hdr_copy_buf);
		buffer_append(map->hdr_copy_buf, map->hdr,
			      map->hdr->header_size);
		map->hdr = map->hdr_copy_buf->data;
	}

	mail_index_unmap(index, view->map);
	view->map = map;
	view->map->refcount++;

	tmphdr = buffer_get_modifyable_data(map->hdr_copy_buf, NULL);
	had_dirty = (tmphdr->flags & MAIL_INDEX_HDR_FLAG_HAVE_DIRTY) != 0;
	if (had_dirty)
		tmphdr->flags &= ~MAIL_INDEX_HDR_FLAG_HAVE_DIRTY;

        first_append_uid = 0;
	while ((ret = mail_transaction_log_view_next(view->log_view, &thdr,
						     &data, &skipped)) > 0) {
		if ((thdr->type & MAIL_TRANSACTION_EXPUNGE) != 0 &&
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

		if ((thdr->type & MAIL_TRANSACTION_APPEND) != 0) {
			const struct mail_index_record *rec = data;

			if (first_append_uid == 0)
				first_append_uid = rec->uid;

			count = thdr->size / sizeof(*rec);
			if (mail_index_grow(index, map, count) < 0) {
				ret = -1;
				break;
			}
			if (map != index->map) {
				map = index->map;
				mail_index_unmap(view->index, view->map);
				view->map = map;
				view->map->refcount++;
			}
		}

		if (mail_transaction_map(view->map, thdr, data,
					 &mail_index_map_sync_funcs,
					 &sync_map_ctx) < 0) {
			ret = -1;
			break;
		}
		if ((thdr->type & MAIL_TRANSACTION_EXTRA_INTRO) != 0) {
			const struct mail_index_extra_record_info *einfo;
			size_t size;

			einfo = buffer_get_data(map->extra_infos, &size);
			einfo += (size / sizeof(*einfo)) - 1;

			map = mail_index_map_to_memory(map,
						       einfo->record_offset +
						       einfo->record_size);
			mail_index_sync_replace_map(view, map);
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

	/* hdr pointer may have changed, update it */
	tmphdr = buffer_get_modifyable_data(map->hdr_copy_buf, NULL);
	tmphdr->log_file_seq = seq;
	tmphdr->log_file_offset = offset;

	if (first_append_uid != 0)
		mail_index_update_day_headers(tmphdr, first_append_uid);

	if ((tmphdr->flags & MAIL_INDEX_HDR_FLAG_HAVE_DIRTY) == 0 &&
	    had_dirty) {
		/* do we have dirty flags anymore? */
		const struct mail_index_record *rec;

		for (i = 0; i < map->records_count; i++) {
			rec = MAIL_INDEX_MAP_IDX(map, i);
			if ((rec->flags & MAIL_INDEX_MAIL_FLAG_DIRTY) != 0) {
				tmphdr->flags |= MAIL_INDEX_HDR_FLAG_HAVE_DIRTY;
				break;
			}
		}
	}

	if (!MAIL_INDEX_MAP_IS_IN_MEMORY(map)) {
		map->mmap_used_size = index->hdr->header_size +
			map->records_count * map->hdr->record_size;

		memcpy(map->mmap_base, tmphdr, tmphdr->header_size);
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
	sync_extra_intro, sync_extra_reset,
	sync_extra_hdr_update, sync_extra_rec_update
};
