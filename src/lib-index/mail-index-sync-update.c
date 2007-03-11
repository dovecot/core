/* Copyright (C) 2004 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "buffer.h"
#include "file-set-size.h"
#include "mmap-util.h"
#include "mail-index-view-private.h"
#include "mail-index-sync-private.h"
#include "mail-transaction-log.h"
#include "mail-transaction-log-private.h"
#include "mail-transaction-util.h"

static void
mail_index_sync_update_log_offset(struct mail_index_sync_map_ctx *ctx,
				  struct mail_index_map *map, bool eol)
{
	uint32_t prev_seq;
	uoff_t prev_offset;

	mail_transaction_log_view_get_prev_pos(ctx->view->log_view,
					       &prev_seq, &prev_offset);

	if (prev_offset == ctx->ext_intro_offset + ctx->ext_intro_size &&
	    prev_seq == ctx->ext_intro_seq && !eol) {
		/* previous transaction was an extension introduction.
		   we probably came here from mail_index_sync_ext_reset().
		   if there are any more views which want to continue syncing
		   it needs the intro. so back up a bit more.

		   don't do this in case the last transaction in the log is
		   the extension intro, so we don't keep trying to sync it
		   over and over again. */
		prev_offset = ctx->ext_intro_offset;
	}

	if (!ctx->sync_only_external) {
		i_assert(prev_offset >= map->hdr.log_file_int_offset ||
			 prev_seq > map->hdr.log_file_seq);
		map->hdr.log_file_int_offset = prev_offset;
	} else if (map->hdr.log_file_seq != prev_seq) {
		/* log sequence changed. update internal offset to
		   beginning of the new file. */
		i_assert(map->hdr.log_file_int_offset ==
			 ctx->view->index->log->head->hdr.prev_file_offset);
		map->hdr.log_file_int_offset =
			ctx->view->index->log->head->hdr.hdr_size;
	}

	/* we might be in the middle of syncing internal transactions, with
	   some of the following external transactions already synced. */
	i_assert(prev_seq > map->hdr.log_file_seq ||
		 prev_offset >= map->hdr.log_file_ext_offset ||
		 (!eol && !ctx->sync_only_external));
	if (map->hdr.log_file_seq != prev_seq ||
	    prev_offset > map->hdr.log_file_ext_offset) {
		map->hdr.log_file_seq = prev_seq;
		map->hdr.log_file_ext_offset = prev_offset;
	}
}

static int
mail_index_map_msync(struct mail_index *index, struct mail_index_map *map)
{
	unsigned int base_size;

	if (MAIL_INDEX_MAP_IS_IN_MEMORY(map))
		return 0;

	base_size = I_MIN(map->hdr.base_header_size, sizeof(map->hdr));
	map->mmap_used_size = index->hdr->header_size +
		map->records_count * map->hdr.record_size;

	memcpy(map->mmap_base, &map->hdr, base_size);
	memcpy(PTR_OFFSET(map->mmap_base, base_size),
	       CONST_PTR_OFFSET(map->hdr_base, base_size),
	       map->hdr.header_size - base_size);
	if (msync(map->mmap_base, map->mmap_used_size, MS_SYNC) < 0) {
		mail_index_set_syscall_error(index, "msync()");
		return -1;
	}
	return 0;
}

void mail_index_sync_replace_map(struct mail_index_sync_map_ctx *ctx,
				 struct mail_index_map *map)
{
        struct mail_index_view *view = ctx->view;
	struct mail_index_map *old_map = view->map;

	i_assert(view->map != map);

	old_map->refcount++;

	/* if map still exists after this, it's only in views. */
	view->map->write_to_disk = FALSE;
	/* keywords aren't parsed for the new map yet */
	view->map->keywords_read = FALSE;

	mail_index_unmap(view->index, &view->map);
	view->map = map;

	if ((ctx->type & (MAIL_INDEX_SYNC_HANDLER_FILE |
			  MAIL_INDEX_SYNC_HANDLER_HEAD)) != 0 &&
	    view->index->map != map) {
		mail_index_unmap(view->index, &view->index->map);
		view->index->map = map;
		view->index->hdr = &map->hdr;
		map->refcount++;

		if (ctx->type == MAIL_INDEX_SYNC_HANDLER_FILE) {
			map->write_to_disk = TRUE;
			map->write_atomic = TRUE;
		}
	}

	/* some views may still use the same mapping, and since we could have
	   already updated the records, make sure we leave the header in a
	   valid state as well */
	mail_index_sync_update_log_offset(ctx, old_map, FALSE);
	(void)mail_index_map_msync(view->index, old_map);
	mail_index_unmap(view->index, &old_map);

	i_assert(view->hdr.messages_count == map->hdr.messages_count);
}

static int
mail_index_header_update_counts(struct mail_index_header *hdr,
				uint8_t old_flags, uint8_t new_flags,
				const char **error_r)
{
	if (((old_flags ^ new_flags) & MAIL_RECENT) != 0) {
		/* different recent-flag */
		if ((old_flags & MAIL_RECENT) == 0) {
			hdr->recent_messages_count++;
			if (hdr->recent_messages_count > hdr->messages_count) {
				*error_r = "Recent counter wrong";
				return -1;
			}
		} else {
			if (hdr->recent_messages_count == 0 ||
			    hdr->recent_messages_count > hdr->messages_count) {
				*error_r = "Recent counter wrong";
				return -1;
			}

			if (--hdr->recent_messages_count == 0)
				hdr->first_recent_uid_lowwater = hdr->next_uid;
		}
	}

	if (((old_flags ^ new_flags) & MAIL_SEEN) != 0) {
		/* different seen-flag */
		if ((old_flags & MAIL_SEEN) != 0) {
			if (hdr->seen_messages_count == 0) {
				*error_r = "Seen counter wrong";
				return -1;
			}
			hdr->seen_messages_count--;
		} else {
			if (hdr->seen_messages_count >= hdr->messages_count) {
				*error_r = "Seen counter wrong";
				return -1;
			}

			if (++hdr->seen_messages_count == hdr->messages_count)
				hdr->first_unseen_uid_lowwater = hdr->next_uid;
		}
	}

	if (((old_flags ^ new_flags) & MAIL_DELETED) != 0) {
		/* different deleted-flag */
		if ((old_flags & MAIL_DELETED) == 0) {
			hdr->deleted_messages_count++;
			if (hdr->deleted_messages_count > hdr->messages_count) {
				*error_r = "Deleted counter wrong";
				return -1;
			}
		} else {
			if (hdr->deleted_messages_count == 0 ||
			    hdr->deleted_messages_count > hdr->messages_count) {
				*error_r = "Deleted counter wrong";
				return -1;
			}

			if (--hdr->deleted_messages_count == 0)
				hdr->first_deleted_uid_lowwater = hdr->next_uid;
		}
	}
	return 0;
}

void mail_index_view_recalc_counters(struct mail_index_view *view)
{
	struct mail_index_map *map = view->map;
	const struct mail_index_record *rec;
	const char *error;
	unsigned int i;

	map->hdr.recent_messages_count = 0;
	map->hdr.seen_messages_count = 0;
	map->hdr.deleted_messages_count = 0;

	for (i = 0; i < view->hdr.messages_count; i++) {
		rec = MAIL_INDEX_MAP_IDX(map, i);
		if (mail_index_header_update_counts(&map->hdr, 0, rec->flags,
						    &error) < 0)
			i_panic("mail_index_view_recalc_counters(): %s", error);
	}

	view->hdr.recent_messages_count = map->hdr.recent_messages_count;
	view->hdr.seen_messages_count = map->hdr.seen_messages_count;
	view->hdr.deleted_messages_count = map->hdr.deleted_messages_count;

	view->broken_counters = FALSE;
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

static int sync_expunge(const struct mail_transaction_expunge *e,
			struct mail_index_sync_map_ctx *ctx)
{
	struct mail_index_view *view = ctx->view;
	struct mail_index_map *map = view->map;
	struct mail_index_record *rec;
	const char *error;
	uint32_t count, seq, seq1, seq2;
        const struct mail_index_expunge_handler *expunge_handlers, *eh;
	unsigned int i, expunge_handlers_count;

	if (e->uid1 > e->uid2 || e->uid1 == 0) {
		mail_index_sync_set_corrupted(ctx,
				"Invalid UID range in expunge (%u .. %u)",
				e->uid1, e->uid2);
		return -1;
	}

	if (!view->map->write_to_disk || view->map->refcount != 1) {
		/* expunges have to be atomic. so we'll have to copy
		   the mapping, do the changes there and then finally
		   replace the whole index file. to avoid extra disk
		   I/O we copy the index into memory rather than to
		   temporary file */
		map = mail_index_map_clone(map, map->hdr.record_size);
		mail_index_sync_replace_map(ctx, map);
	}
	i_assert(MAIL_INDEX_MAP_IS_IN_MEMORY(map));

	/* we want atomic rename()ing */
	map->write_atomic = TRUE;

	if (mail_index_lookup_uid_range(view, e->uid1, e->uid2,
					&seq1, &seq2) < 0)
		return -1;

	if (seq1 == 0)
		return 1;

	/* call expunge handlers only when syncing index file */
	if (ctx->type == MAIL_INDEX_SYNC_HANDLER_FILE &&
	    !ctx->expunge_handlers_set)
		mail_index_sync_init_expunge_handlers(ctx);

	if (ctx->type == MAIL_INDEX_SYNC_HANDLER_FILE &&
	    array_is_created(&ctx->expunge_handlers)) {
		expunge_handlers = array_get(&ctx->expunge_handlers,
					     &expunge_handlers_count);
	} else {
		expunge_handlers = NULL;
		expunge_handlers_count = 0;
	}

	if (ctx->unreliable_flags || view->broken_counters)
		view->broken_counters = TRUE;
	else {
		for (seq = seq1; seq <= seq2; seq++) {
			rec = MAIL_INDEX_MAP_IDX(map, seq-1);
			if (mail_index_header_update_counts(&map->hdr,
							    rec->flags, 0,
							    &error) < 0) {
				mail_index_sync_set_corrupted(ctx, "%s", error);
				return -1;
			}
		}
	}

	for (i = 0; i < expunge_handlers_count; i++) {
		eh = &expunge_handlers[i];

		for (seq = seq1; seq <= seq2; seq++) {
			rec = MAIL_INDEX_MAP_IDX(map, seq-1);
			if (eh->handler(ctx, seq,
					PTR_OFFSET(rec, eh->record_offset),
					eh->sync_context, eh->context) < 0)
				return -1;
		}
	}

	/* @UNSAFE */
	count = seq2 - seq1 + 1;
	memmove(MAIL_INDEX_MAP_IDX(map, seq1-1), MAIL_INDEX_MAP_IDX(map, seq2),
		(map->records_count - seq2) * map->hdr.record_size);

	map->records_count -= count;
	map->hdr.messages_count -= count;
	view->hdr.messages_count -= count;

	if (map->buffer != NULL) {
		buffer_set_used_size(map->buffer, map->records_count *
				     map->hdr.record_size);
		map->records = buffer_get_modifiable_data(map->buffer, NULL);
	}
	return 1;
}

static void write_seq_update(struct mail_index_map *map,
			     uint32_t seq1, uint32_t seq2)
{
	if (map->write_seq_first == 0 ||
	    map->write_seq_first > seq1)
		map->write_seq_first = seq1;
	if (map->write_seq_last < seq2)
		map->write_seq_last = seq2;
}

static int sync_append(const struct mail_index_record *rec,
		       struct mail_index_sync_map_ctx *ctx)
{
	struct mail_index_view *view = ctx->view;
	struct mail_index_map *map = view->map;
	const char *error;
	void *dest;

	if (rec->uid < map->hdr.next_uid) {
		mail_index_sync_set_corrupted(ctx,
			"Append with UID %u, but next_uid = %u",
			rec->uid, map->hdr.next_uid);
		return -1;
	}

	if (MAIL_INDEX_MAP_IS_IN_MEMORY(map)) {
		i_assert(map->records_count * map->hdr.record_size ==
			 buffer_get_used_size(map->buffer));
		dest = buffer_append_space_unsafe(map->buffer,
						  map->hdr.record_size);
		map->records = buffer_get_modifiable_data(map->buffer, NULL);
	} else {
		i_assert((map->records_count+1) * map->hdr.record_size <=
			 map->mmap_size);
		dest = MAIL_INDEX_MAP_IDX(map, map->records_count);
	}
	memcpy(dest, rec, sizeof(*rec));
	memset(PTR_OFFSET(dest, sizeof(*rec)), 0,
	       map->hdr.record_size - sizeof(*rec));

	map->hdr.messages_count++;
	map->hdr.next_uid = rec->uid+1;
	map->records_count++;
	view->hdr.messages_count++;
	view->hdr.next_uid = rec->uid+1;

	write_seq_update(map, map->hdr.messages_count, map->hdr.messages_count);

	if ((rec->flags & MAIL_INDEX_MAIL_FLAG_DIRTY) != 0)
		map->hdr.flags |= MAIL_INDEX_HDR_FLAG_HAVE_DIRTY;

	mail_index_header_update_lowwaters(&map->hdr, rec);
	if (!view->broken_counters) {
		if (mail_index_header_update_counts(&map->hdr, 0, rec->flags,
						    &error) < 0) {
			mail_index_sync_set_corrupted(ctx, "%s", error);
			return -1;
		}
	}
	return 1;
}

static int sync_flag_update(const struct mail_transaction_flag_update *u,
			    struct mail_index_sync_map_ctx *ctx)
{
	struct mail_index_view *view = ctx->view;
	struct mail_index_header *hdr;
	struct mail_index_record *rec;
	const char *error;
	uint8_t flag_mask, old_flags;
	uint32_t idx, seq1, seq2;

	if (u->uid1 > u->uid2 || u->uid1 == 0) {
		mail_index_sync_set_corrupted(ctx,
				"Invalid UID range in flag update (%u .. %u)",
				u->uid1, u->uid2);
		return -1;
	}

	if (mail_index_lookup_uid_range(view, u->uid1, u->uid2,
					&seq1, &seq2) < 0)
		return -1;

	if (seq1 == 0)
		return 1;

	write_seq_update(view->map, seq1, seq2);

	hdr = &view->map->hdr;
	if ((u->add_flags & MAIL_INDEX_MAIL_FLAG_DIRTY) != 0)
		hdr->flags |= MAIL_INDEX_HDR_FLAG_HAVE_DIRTY;

        flag_mask = ~u->remove_flags;

	if (((u->add_flags | u->remove_flags) &
	     (MAIL_SEEN | MAIL_DELETED | MAIL_RECENT)) == 0) {
		/* we're not modifying any counted/lowwatered flags */
		for (idx = seq1-1; idx < seq2; idx++) {
			rec = MAIL_INDEX_MAP_IDX(view->map, idx);
			rec->flags = (rec->flags & flag_mask) | u->add_flags;
		}
	} else if (view->broken_counters || ctx->unreliable_flags) {
		view->broken_counters = TRUE;
		for (idx = seq1-1; idx < seq2; idx++) {
			rec = MAIL_INDEX_MAP_IDX(view->map, idx);
			rec->flags = (rec->flags & flag_mask) | u->add_flags;

			mail_index_header_update_lowwaters(hdr, rec);
		}
	} else {
		for (idx = seq1-1; idx < seq2; idx++) {
			rec = MAIL_INDEX_MAP_IDX(view->map, idx);

			old_flags = rec->flags;
			rec->flags = (rec->flags & flag_mask) | u->add_flags;

			mail_index_header_update_lowwaters(hdr, rec);
			if (mail_index_header_update_counts(hdr, old_flags,
							    rec->flags,
							    &error) < 0) {
				mail_index_sync_set_corrupted(ctx, "%s", error);
				return -1;
			}
		}
	}
	return 1;
}

static int sync_header_update(const struct mail_transaction_header_update *u,
			      struct mail_index_sync_map_ctx *ctx)
{
	struct mail_index_map *map = ctx->view->map;

	if (u->offset >= map->hdr.base_header_size ||
	    u->offset + u->size > map->hdr.base_header_size) {
		mail_index_sync_set_corrupted(ctx,
			"Header update outside range: %u + %u > %u",
			u->offset, u->size, map->hdr.base_header_size);
		return -1;
	}

	buffer_write(map->hdr_copy_buf, u->offset, u + 1, u->size);
	map->hdr_base = map->hdr_copy_buf->data;

	/* @UNSAFE */
	if ((uint32_t)(u->offset + u->size) <= sizeof(map->hdr)) {
		memcpy(PTR_OFFSET(&map->hdr, u->offset),
		       u + 1, u->size);
	} else if (u->offset < sizeof(map->hdr)) {
		memcpy(PTR_OFFSET(&map->hdr, u->offset),
		       u + 1, sizeof(map->hdr) - u->offset);
	}
	return 1;
}

static int mail_index_grow(struct mail_index *index, struct mail_index_map *map,
			   unsigned int count)
{
	void *hdr_copy;
	size_t size, hdr_copy_size;

	if (MAIL_INDEX_MAP_IS_IN_MEMORY(map))
		return 1;

	i_assert(map == index->map);
	i_assert(!index->mapping); /* mail_index_sync_from_transactions() */

	size = map->hdr.header_size +
		(map->records_count + count) * map->hdr.record_size;
	if (size <= map->mmap_size)
		return 1;

	/* when we grow fast, do it exponentially */
	if (count < index->last_grow_count)
		count = index->last_grow_count;
	if (count < MAIL_INDEX_MAX_POWER_GROW)
		count = nearest_power(count);
	index->last_grow_count = count;

	size = map->hdr.header_size +
		(map->records_count + count) * map->hdr.record_size;
	if (file_set_size(index->fd, (off_t)size) < 0) {
		mail_index_set_syscall_error(index, "file_set_size()");
		return !ENOSPACE(errno) ? -1 :
			mail_index_move_to_memory(index);
	}

	/* we only wish to grow the file, but mail_index_map() updates the
	   headers as well and may break our modified hdr_copy. so, take
	   a backup of it and put it back afterwards */
	t_push();
	i_assert(map->hdr_copy_buf->used == map->hdr.header_size);
        hdr_copy_size = map->hdr_copy_buf->used;
	hdr_copy = t_malloc(hdr_copy_size);
	memcpy(hdr_copy, map->hdr_copy_buf->data, hdr_copy_size);
	memcpy(hdr_copy, &map->hdr, sizeof(map->hdr));

	if (mail_index_map(index, TRUE) <= 0) {
		t_pop();
		return -1;
	}

	map = index->map;
	buffer_reset(map->hdr_copy_buf);
	buffer_append(map->hdr_copy_buf, hdr_copy, hdr_copy_size);

	map->hdr_base = map->hdr_copy_buf->data;
	memcpy(&map->hdr, hdr_copy, sizeof(map->hdr));
	map->records_count = map->hdr.messages_count;

	i_assert(map->mmap_size >= size);

	t_pop();
	return 1;
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

int mail_index_sync_record(struct mail_index_sync_map_ctx *ctx,
			   const struct mail_transaction_header *hdr,
			   const void *data)
{
	int ret = 0;

	t_push();
	switch (hdr->type & MAIL_TRANSACTION_TYPE_MASK) {
	case MAIL_TRANSACTION_APPEND: {
		const struct mail_index_record *rec, *end;

		end = CONST_PTR_OFFSET(data, hdr->size);
		for (rec = data; rec < end; rec++) {
			ret = sync_append(rec, ctx);
			if (ret <= 0)
				break;
		}
		break;
	}
	case MAIL_TRANSACTION_EXPUNGE:
	case MAIL_TRANSACTION_EXPUNGE|MAIL_TRANSACTION_EXPUNGE_PROT: {
		const struct mail_transaction_expunge *rec, *end;

		end = CONST_PTR_OFFSET(data, hdr->size);
		for (rec = data; rec < end; rec++) {
			ret = sync_expunge(rec, ctx);
			if (ret <= 0)
				break;
		}
		break;
	}
	case MAIL_TRANSACTION_FLAG_UPDATE: {
		const struct mail_transaction_flag_update *rec, *end;

		end = CONST_PTR_OFFSET(data, hdr->size);
		for (rec = data; rec < end; rec++) {
			ret = sync_flag_update(rec, ctx);
			if (ret <= 0)
				break;
		}
		break;
	}
	case MAIL_TRANSACTION_HEADER_UPDATE: {
		const struct mail_transaction_header_update *rec;
		unsigned int i;

		for (i = 0; i < hdr->size; ) {
			rec = CONST_PTR_OFFSET(data, i);
			ret = sync_header_update(rec, ctx);
			if (ret <= 0)
				break;

			i += sizeof(*rec) + rec->size;
			if ((i % 4) != 0)
				i += 4 - (i % 4);
		}
		break;
	}
	case MAIL_TRANSACTION_EXT_INTRO: {
		const struct mail_transaction_ext_intro *rec = data;
		unsigned int i;
		uint32_t prev_seq;
		uoff_t prev_offset;

		mail_transaction_log_view_get_prev_pos(ctx->view->log_view,
						       &prev_seq, &prev_offset);
		ctx->ext_intro_seq = prev_seq;
		ctx->ext_intro_offset = prev_offset;
		ctx->ext_intro_size = hdr->size + sizeof(*hdr);

		for (i = 0; i < hdr->size; ) {
			if (i + sizeof(*rec) > hdr->size) {
				/* should be just extra padding */
				break;
			}

			rec = CONST_PTR_OFFSET(data, i);
			ret = mail_index_sync_ext_intro(ctx, rec);
			if (ret <= 0)
				break;

			i += sizeof(*rec) + rec->name_size;
			if ((i % 4) != 0)
				i += 4 - (i % 4);
		}
		break;
	}
	case MAIL_TRANSACTION_EXT_RESET: {
		const struct mail_transaction_ext_reset *rec = data;
		ret = mail_index_sync_ext_reset(ctx, rec);
		break;
	}
	case MAIL_TRANSACTION_EXT_HDR_UPDATE: {
		const struct mail_transaction_ext_hdr_update *rec = data;
		unsigned int i;

		for (i = 0; i < hdr->size; ) {
			rec = CONST_PTR_OFFSET(data, i);
			ret = mail_index_sync_ext_hdr_update(ctx, rec);
			if (ret <= 0)
				break;

			i += sizeof(*rec) + rec->size;
			if ((i % 4) != 0)
				i += 4 - (i % 4);
		}
		break;
	}
	case MAIL_TRANSACTION_EXT_REC_UPDATE: {
		const struct mail_transaction_ext_rec_update *rec, *end;
		const struct mail_index_ext *ext;
		unsigned int record_size;

		if (ctx->cur_ext_id == (uint32_t)-1) {
			mail_index_sync_set_corrupted(ctx,
				"Extension record updated "
				"without intro prefix");
			ret = -1;
			break;
		}

		if (ctx->cur_ext_ignore) {
			ret = 1;
			break;
		}

		ext = array_idx(&ctx->view->map->extensions, ctx->cur_ext_id);
		/* the record is padded to 32bits in the transaction log */
		record_size = (sizeof(*rec) + ext->record_size + 3) & ~3;

		rec = data;
		end = CONST_PTR_OFFSET(data, hdr->size);
		while (rec < end) {
			ret = mail_index_sync_ext_rec_update(ctx, rec);
			if (ret <= 0)
				break;

			rec = CONST_PTR_OFFSET(rec, record_size);
		}
		break;
	}
	case MAIL_TRANSACTION_KEYWORD_UPDATE: {
		const struct mail_transaction_keyword_update *rec = data;

		ret = mail_index_sync_keywords(ctx, hdr, rec);
		break;
	}
	case MAIL_TRANSACTION_KEYWORD_RESET: {
		const struct mail_transaction_keyword_reset *rec = data;

		ret = mail_index_sync_keywords_reset(ctx, hdr, rec);
		break;
	}
	default:
		i_unreached();
	}
	t_pop();

	i_assert(ctx->view->map->records_count ==
		 ctx->view->map->hdr.messages_count);
	i_assert(ctx->view->hdr.messages_count ==
		 ctx->view->map->hdr.messages_count);
	return ret;
}

void mail_index_sync_map_init(struct mail_index_sync_map_ctx *sync_map_ctx,
			      struct mail_index_view *view,
			      enum mail_index_sync_handler_type type)
{
	memset(sync_map_ctx, 0, sizeof(*sync_map_ctx));
	sync_map_ctx->view = view;
	sync_map_ctx->cur_ext_id = (uint32_t)-1;
	sync_map_ctx->type = type;

	/* make sure we re-read it in case it has changed */
	sync_map_ctx->view->map->keywords_read = FALSE;

	mail_index_sync_init_handlers(sync_map_ctx);
}

void mail_index_sync_map_deinit(struct mail_index_sync_map_ctx *sync_map_ctx)
{
	if (sync_map_ctx->expunge_handlers_used)
		mail_index_sync_deinit_expunge_handlers(sync_map_ctx);
	mail_index_sync_deinit_handlers(sync_map_ctx);
}

static void mail_index_sync_remove_recent(struct mail_index_sync_ctx *sync_ctx)
{
	struct mail_index_map *map = sync_ctx->view->map;
	struct mail_index_record *rec;
	unsigned int i;

	for (i = 0; i < map->records_count; i++) {
		rec = MAIL_INDEX_MAP_IDX(map, i);
		if ((rec->flags & MAIL_RECENT) != 0) {
			rec->flags &= ~MAIL_RECENT;

			write_seq_update(map, i + 1, i + 1);
		}
	}

	map->hdr.recent_messages_count = 0;
	map->hdr.first_recent_uid_lowwater = map->hdr.next_uid;
}

static void log_view_seek_back(struct mail_transaction_log_view *log_view)
{
	uint32_t prev_seq;
	uoff_t prev_offset;

	mail_transaction_log_view_get_prev_pos(log_view, &prev_seq,
					       &prev_offset);
	mail_transaction_log_view_seek(log_view, prev_seq, prev_offset);
}

int mail_index_sync_update_index(struct mail_index_sync_ctx *sync_ctx,
				 bool sync_only_external)
{
	struct mail_index *index = sync_ctx->index;
	struct mail_index_view *view = sync_ctx->view;
	struct mail_index_map *map;
        struct mail_index_sync_map_ctx sync_map_ctx;
	const struct mail_transaction_header *thdr;
	const void *data;
	unsigned int count, old_lock_id;
	uint32_t i, first_append_uid;
	int ret;
	bool had_dirty, skipped, check_ext_offsets;

	mail_index_sync_map_init(&sync_map_ctx, view,
				 MAIL_INDEX_SYNC_HANDLER_FILE);
	sync_map_ctx.sync_only_external = sync_only_external;

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

	if (map->hdr_base != map->hdr_copy_buf->data) {
		buffer_reset(map->hdr_copy_buf);
		buffer_append(map->hdr_copy_buf, map->hdr_base,
			      map->hdr.header_size);
		map->hdr_base = map->hdr_copy_buf->data;
	}
	i_assert(map->hdr.base_header_size >= sizeof(map->hdr));

	mail_index_unmap(index, &view->map);
	view->map = map;
	view->map->refcount++;

	i_assert(view->hdr.messages_count == map->hdr.messages_count);

	had_dirty = (map->hdr.flags & MAIL_INDEX_HDR_FLAG_HAVE_DIRTY) != 0;
	if (had_dirty)
		map->hdr.flags &= ~MAIL_INDEX_HDR_FLAG_HAVE_DIRTY;

	if (sync_ctx->sync_recent) {
		/* mark all messages non-recent */
		mail_index_sync_remove_recent(sync_ctx);
	}

	/* make sure we don't go doing fsck while modifying the index */
	index->sync_update = TRUE;

	first_append_uid = 0;
	check_ext_offsets = TRUE;
	while ((ret = mail_transaction_log_view_next(view->log_view, &thdr,
						     &data, &skipped)) > 0) {
		if ((thdr->type & MAIL_TRANSACTION_EXTERNAL) == 0) {
			if (sync_only_external) {
				/* we're syncing only external changes. */
				continue;
			}
		} else if (check_ext_offsets) {
			if (mail_index_is_ext_synced(view->log_view, view->map))
				continue;
			check_ext_offsets = FALSE;
		}

		if ((thdr->type & MAIL_TRANSACTION_APPEND) != 0) {
			const struct mail_index_record *rec = data;

			if (first_append_uid == 0)
				first_append_uid = rec->uid;

			map = view->map;
			count = thdr->size / sizeof(*rec);
			if ((ret = mail_index_grow(index, map, count)) < 0)
				break;

			if (map != index->map) {
				index->map->refcount++;
				mail_index_sync_replace_map(&sync_map_ctx,
							    index->map);
			}

			if (ret == 0) {
				/* moved to memory. data pointer is invalid,
				   seek back and do this append again. */
				log_view_seek_back(view->log_view);
				continue;
			}
		}

		if (mail_index_sync_record(&sync_map_ctx, thdr, data) < 0) {
			ret = -1;
			break;
		}
	}

	if (ret == 0) {
		mail_index_sync_update_log_offset(&sync_map_ctx, view->map,
						  TRUE);
	}
	mail_index_sync_map_deinit(&sync_map_ctx);

	index->sync_update = FALSE;

	if (ret < 0) {
		mail_index_view_unlock(view);
		return -1;
	}

	map = view->map;
	i_assert(map->records_count == map->hdr.messages_count);
	i_assert(map->hdr_copy_buf->used <= map->hdr.header_size);

	if (first_append_uid != 0)
		mail_index_update_day_headers(&map->hdr, first_append_uid);

	if ((map->hdr.flags & MAIL_INDEX_HDR_FLAG_HAVE_DIRTY) == 0 &&
	    had_dirty) {
		/* do we have dirty flags anymore? */
		const struct mail_index_record *rec;

		for (i = 0; i < map->records_count; i++) {
			rec = MAIL_INDEX_MAP_IDX(map, i);
			if ((rec->flags & MAIL_INDEX_MAIL_FLAG_DIRTY) != 0) {
				map->hdr.flags |=
					MAIL_INDEX_HDR_FLAG_HAVE_DIRTY;
				break;
			}
		}
	}

	if (mail_index_map_msync(index, map) < 0)
		ret = -1;
	i_assert(view->map == index->map);
	view->hdr = map->hdr;

        mail_index_view_unlock(view);
	return ret;
}
