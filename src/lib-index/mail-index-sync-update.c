/* Copyright (C) 2004 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "mmap-util.h"
#include "mail-index-view-private.h"
#include "mail-index-sync-private.h"
#include "mail-transaction-log.h"
#include "mail-transaction-log-private.h"

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

	if (!ctx->sync_only_external) { // FIXME: never happens
		i_assert(prev_offset >= map->hdr.log_file_index_int_offset ||
			 prev_seq > map->hdr.log_file_seq);
		map->hdr.log_file_index_int_offset = prev_offset;
	} else if (map->hdr.log_file_seq != prev_seq) {
		/* log sequence changed. update internal offset to
		   beginning of the new file. */
		i_assert(map->hdr.log_file_index_int_offset ==
			 ctx->view->index->log->head->hdr.prev_file_offset);
		map->hdr.log_file_index_int_offset =
			ctx->view->index->log->head->hdr.hdr_size;
	}

	/* we might be in the middle of syncing internal transactions, with
	   some of the following external transactions already synced. */
	i_assert(prev_seq > map->hdr.log_file_seq ||
		 prev_offset >= map->hdr.log_file_index_ext_offset ||
		 (!eol && !ctx->sync_only_external));
	if (map->hdr.log_file_seq != prev_seq ||
	    prev_offset > map->hdr.log_file_index_ext_offset) {
		map->hdr.log_file_seq = prev_seq;
		map->hdr.log_file_index_ext_offset = prev_offset;
	}
}

#if 0 // FIXME: can we / do we want to support this?
static int
mail_index_map_msync(struct mail_index *index, struct mail_index_map *map)
{
	if (MAIL_INDEX_MAP_IS_IN_MEMORY(map)) {
		buffer_write(map->hdr_copy_buf, 0, &map->hdr, sizeof(map->hdr));
		return 0;
	}

	map->mmap_used_size = map->hdr.header_size +
		map->records_count * map->hdr.record_size;

	memcpy(map->mmap_base, &map->hdr,
	       I_MIN(map->hdr.base_header_size, sizeof(map->hdr)));
	memcpy(PTR_OFFSET(map->mmap_base, map->hdr.base_header_size),
	       CONST_PTR_OFFSET(map->hdr_base, map->hdr.base_header_size),
	       map->hdr.header_size - map->hdr.base_header_size);
	if (msync(map->mmap_base, map->mmap_used_size, MS_SYNC) < 0) {
		mail_index_set_syscall_error(index, "msync()");
		return -1;
	}
	return 0;
}
#endif

static void mail_index_sync_replace_map(struct mail_index_sync_map_ctx *ctx,
					struct mail_index_map *map)
{
        struct mail_index_view *view = ctx->view;

	i_assert(view->map != map);

#if 0 // FIXME
	/* we could have already updated some of the records, so make sure
	   that other views (in possibly other processes) will see this map's
	   header in a valid state.  */
	mail_index_sync_update_log_offset(ctx, view->map, FALSE);
	(void)mail_index_map_msync(view->index, view->map);
#endif

	mail_index_unmap(view->index, &view->map);
	view->map = map;

	if (ctx->type != MAIL_INDEX_SYNC_HANDLER_VIEW) {
		view->index->map = map;
		view->index->hdr = &map->hdr;
	}
}

void mail_index_sync_move_to_private(struct mail_index_sync_map_ctx *ctx)
{
	struct mail_index_map *map = ctx->view->map;

	if (map->refcount == 1) {
		if (!MAIL_INDEX_MAP_IS_IN_MEMORY(map))
			mail_index_map_move_to_memory(map);
	} else {
		map = mail_index_map_clone(map);
		mail_index_sync_replace_map(ctx, map);
	}
}

struct mail_index_map *
mail_index_sync_get_atomic_map(struct mail_index_sync_map_ctx *ctx)
{
	mail_index_sync_move_to_private(ctx);
	ctx->view->map->write_atomic = TRUE;
	return ctx->view->map;
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

static void
mail_index_sync_header_update_counts(struct mail_index_sync_map_ctx *ctx,
				     uint8_t old_flags, uint8_t new_flags)
{
	const char *error;

	if (ctx->view->broken_counters)
		return;

	if (mail_index_header_update_counts(&ctx->view->map->hdr,
					    old_flags, new_flags, &error) < 0) {
		mail_index_sync_set_corrupted(ctx, "%s", error);
		ctx->view->broken_counters = TRUE;
	}
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

static int
sync_expunge_call_handlers(struct mail_index_sync_map_ctx *ctx,
			   uint32_t seq1, uint32_t seq2)
{
	const struct mail_index_expunge_handler *eh;
	struct mail_index_record *rec;
	unsigned int i, count;

	/* call expunge handlers only when syncing index file */
	if (ctx->type != MAIL_INDEX_SYNC_HANDLER_FILE)
		return 0;

	if (!ctx->expunge_handlers_set)
		mail_index_sync_init_expunge_handlers(ctx);

	if (!array_is_created(&ctx->expunge_handlers))
		return 0;

	eh = array_get(&ctx->expunge_handlers, &count);
	for (i = 0; i < count; i++, eh++) {
		for (; seq1 <= seq2; seq1++) {
			rec = MAIL_INDEX_MAP_IDX(ctx->view->map, seq1-1);
			if (eh->handler(ctx, seq1,
					PTR_OFFSET(rec, eh->record_offset),
					eh->sync_context, eh->context) < 0)
				return -1;
		}
	}
	return 0;
}

static int
sync_expunge(const struct mail_transaction_expunge *e, unsigned int count,
	     struct mail_index_sync_map_ctx *ctx)
{
	struct mail_index_map *map = ctx->view->map;
	struct mail_index_record *rec;
	uint32_t seq_count, seq, seq1, seq2;
	unsigned int i;

	/* we don't ever want to move around data inside a memory mapped file.
	   it gets corrupted too easily if we crash in the middle. */
	// FIXME: it's necessary for current view code that we get atomic
	// map even if these messages are already expunged, because the
	// view code doesn't check that and our index_int_offset goes wrong
	map = mail_index_sync_get_atomic_map(ctx);

	for (i = 0; i < count; i++, e++) {
		if (mail_index_lookup_uid_range(ctx->view, e->uid1, e->uid2,
						&seq1, &seq2) < 0)
			return -1;
		if (seq1 == 0) {
			/* everything expunged already */
			continue;
		}

		if (ctx->unreliable_flags || ctx->view->broken_counters)
			ctx->view->broken_counters = TRUE;
		else {
			for (seq = seq1; seq <= seq2; seq++) {
				rec = MAIL_INDEX_MAP_IDX(map, seq-1);
				mail_index_sync_header_update_counts(ctx,
								rec->flags, 0);
			}
		}

		if (sync_expunge_call_handlers(ctx, seq1, seq2) < 0)
			return -1;

		/* @UNSAFE */
		memmove(MAIL_INDEX_MAP_IDX(map, seq1-1),
			MAIL_INDEX_MAP_IDX(map, seq2),
			(map->records_count - seq2) * map->hdr.record_size);

		seq_count = seq2 - seq1 + 1;
		map->records_count -= seq_count;
		map->hdr.messages_count -= seq_count;

		/* lookup_uid_range() relies on this */
		ctx->view->hdr.messages_count -= seq_count;
	}
	return 1;
}

void mail_index_sync_write_seq_update(struct mail_index_sync_map_ctx *ctx,
				      uint32_t seq1, uint32_t seq2)
{
	struct mail_index_map *map = ctx->view->map;

	i_assert(MAIL_INDEX_MAP_IS_IN_MEMORY(map));

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
	void *dest;
	size_t append_pos;

	if (rec->uid < map->hdr.next_uid) {
		mail_index_sync_set_corrupted(ctx,
			"Append with UID %u, but next_uid = %u",
			rec->uid, map->hdr.next_uid);
		return -1;
	}

	/* move to memory. the mapping is written when unlocking so we don't
	   waste time re-mmap()ing multiple times or waste space growing index
	   file too large */
	mail_index_sync_move_to_private(ctx);
	map = view->map;

	/* don't rely on buffer->used being at the correct position.
	   at least expunges can move it */
	append_pos = map->records_count * map->hdr.record_size;
	dest = buffer_get_space_unsafe(map->buffer, append_pos,
				       map->hdr.record_size);
	map->records = buffer_get_modifiable_data(map->buffer, NULL);

	memcpy(dest, rec, sizeof(*rec));
	memset(PTR_OFFSET(dest, sizeof(*rec)), 0,
	       map->hdr.record_size - sizeof(*rec));

	map->hdr.messages_count++;
	map->hdr.next_uid = rec->uid+1;
	map->records_count++;

	mail_index_sync_write_seq_update(ctx, map->hdr.messages_count,
					 map->hdr.messages_count);
	map->write_base_header = TRUE;

	if ((rec->flags & MAIL_INDEX_MAIL_FLAG_DIRTY) != 0)
		map->hdr.flags |= MAIL_INDEX_HDR_FLAG_HAVE_DIRTY;

	mail_index_header_update_lowwaters(&map->hdr, rec);
	mail_index_sync_header_update_counts(ctx, 0, rec->flags);
	return 1;
}

static int sync_flag_update(const struct mail_transaction_flag_update *u,
			    struct mail_index_sync_map_ctx *ctx)
{
	struct mail_index_view *view = ctx->view;
	struct mail_index_header *hdr;
	struct mail_index_record *rec;
	uint8_t flag_mask, old_flags;
	uint32_t idx, seq1, seq2;

	if (mail_index_lookup_uid_range(view, u->uid1, u->uid2,
					&seq1, &seq2) < 0)
		return -1;

	if (seq1 == 0)
		return 1;

	mail_index_sync_move_to_private(ctx);
	mail_index_sync_write_seq_update(ctx, seq1, seq2);
	view->map->write_base_header = TRUE;

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
			mail_index_sync_header_update_counts(ctx, old_flags,
							     rec->flags);
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
	map->write_base_header = TRUE;

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

static void
mail_index_update_day_headers(struct mail_index_header *hdr, uint32_t uid)
{
	// FIXME: move as header updates to transaction committing
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
		const struct mail_transaction_expunge *rec = data, *end;

		end = CONST_PTR_OFFSET(data, hdr->size);
		ret = sync_expunge(rec, end - rec, ctx);
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
			if (i + sizeof(*rec) + rec->name_size > hdr->size) {
				mail_index_sync_set_corrupted(ctx,
					"ext intro: name_size too large");
				ret = -1;
				break;
			}

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

		if (hdr->size != sizeof(*rec)) {
			mail_index_sync_set_corrupted(ctx,
				"ext reset: invalid record size");
			ret = -1;
			break;
		}
		ret = mail_index_sync_ext_reset(ctx, rec);
		break;
	}
	case MAIL_TRANSACTION_EXT_HDR_UPDATE: {
		const struct mail_transaction_ext_hdr_update *rec = data;
		unsigned int i;

		for (i = 0; i < hdr->size; ) {
			rec = CONST_PTR_OFFSET(data, i);

			if (i + sizeof(*rec) > hdr->size ||
			    i + sizeof(*rec) + rec->size > hdr->size) {
				mail_index_sync_set_corrupted(ctx,
					"ext hdr update: invalid record size");
				ret = -1;
				break;
			}

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
		const struct mail_transaction_ext_rec_update *rec;
		const struct mail_index_ext *ext;
		unsigned int i, record_size;

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

		for (i = 0; i < hdr->size; i += record_size) {
			rec = CONST_PTR_OFFSET(data, i);

			if (i + record_size > hdr->size) {
				mail_index_sync_set_corrupted(ctx,
					"ext rec update: invalid record size");
				ret = -1;
				break;
			}

			ret = mail_index_sync_ext_rec_update(ctx, rec);
			if (ret <= 0)
				break;
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
	ctx->view->hdr = ctx->view->map->hdr;
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

static void mail_index_sync_remove_recent(struct mail_index_sync_map_ctx *ctx)
{
	struct mail_index_map *map = ctx->view->map;
	struct mail_index_record *rec;
	unsigned int i;

	for (i = 0; i < map->records_count; i++) {
		rec = MAIL_INDEX_MAP_IDX(map, i);
		if ((rec->flags & MAIL_RECENT) != 0) {
			rec->flags &= ~MAIL_RECENT;

			mail_index_sync_write_seq_update(ctx, i + 1, i + 1);
		}
	}

	map->hdr.recent_messages_count = 0;
	map->hdr.first_recent_uid_lowwater = map->hdr.next_uid;
	map->write_base_header = TRUE;
}

static void mail_index_sync_update_hdr_dirty_flag(struct mail_index_map *map)
{
	const struct mail_index_record *rec;
	unsigned int i;

	if ((map->hdr.flags & MAIL_INDEX_HDR_FLAG_HAVE_DIRTY) != 0)
		return;

	/* do we have dirty flags anymore? */
	for (i = 0; i < map->records_count; i++) {
		rec = MAIL_INDEX_MAP_IDX(map, i);
		if ((rec->flags & MAIL_INDEX_MAIL_FLAG_DIRTY) != 0) {
			map->hdr.flags |= MAIL_INDEX_HDR_FLAG_HAVE_DIRTY;
			break;
		}
	}
}

int mail_index_sync_map(struct mail_index *index, struct mail_index_map **_map,
			enum mail_index_sync_handler_type type, bool force)
{
	struct mail_index_map *map = *_map;
	struct mail_index_view *view;
	struct mail_index_sync_map_ctx sync_map_ctx;
	const struct mail_transaction_header *thdr;
	const void *tdata;
	uint32_t prev_seq, mailbox_sync_seq, expunge_seq;
	uoff_t prev_offset, mailbox_sync_offset, expunge_offset;
	int ret;
	bool had_dirty;

	if (!force) {
		/* see if we'd prefer to reopen the index file instead of
		   syncing the current map from the transaction log */
		uoff_t log_size, index_size;

		if (index->log->head == NULL || index->fd == -1)
			return 0;

		index_size = map->hdr.header_size +
			map->records_count * map->hdr.record_size;

		/* this isn't necessary correct currently, but it should be
		   close enough */
		log_size = index->log->head->last_size;
		if (log_size > map->hdr.log_file_index_int_offset &&
		    log_size - map->hdr.log_file_index_int_offset > index_size)
			return 0;
	}

	view = mail_index_view_open_with_map(index, map);
	if (mail_transaction_log_view_set(view->log_view,
					  map->hdr.log_file_seq,
					  map->hdr.log_file_index_int_offset,
					  (uint32_t)-1, (uoff_t)-1,
					  MAIL_TRANSACTION_TYPE_MASK) <= 0) {
		/* can't use it. sync by re-reading index. */
		mail_index_view_close(&view);
		return 0;
	}

	mail_transaction_log_get_mailbox_sync_pos(index->log, &mailbox_sync_seq,
						  &mailbox_sync_offset);

	/* view referenced the map. avoid unnecessary map cloning by
	   unreferencing the map while view exists. */
	map->refcount--;

	had_dirty = (map->hdr.flags & MAIL_INDEX_HDR_FLAG_HAVE_DIRTY) != 0;
	if (had_dirty) {
		map->hdr.flags &= ~MAIL_INDEX_HDR_FLAG_HAVE_DIRTY;
		map->write_base_header = TRUE;
	}

	if (map->hdr_base != map->hdr_copy_buf->data) {
		/* if syncing updates the header, it updates hdr_copy_buf
		   and updates hdr_base to hdr_copy_buf. so the buffer must
		   initially contain a valid header or we'll break it when
		   writing it. */
		buffer_reset(map->hdr_copy_buf);
		buffer_append(map->hdr_copy_buf, map->hdr_base,
			      map->hdr.header_size);
		map->hdr_base = map->hdr_copy_buf->data;
	}

	if (type != MAIL_INDEX_SYNC_HANDLER_VIEW) {
		i_assert(index->map == NULL && index->hdr == NULL);
		index->map = map;
		index->hdr = &map->hdr;
	}

	mail_index_sync_map_init(&sync_map_ctx, view, type);
	map = NULL;

	/* FIXME: when transaction sync lock is removed, we'll need to handle
	   the case when a transaction is committed while mailbox is being
	   synced ([synced transactions][new transaction][ext transaction]).
	   this means int_offset contains [synced] and ext_offset contains
	   all */
	expunge_seq = expunge_offset = 0;
	while ((ret = mail_transaction_log_view_next(view->log_view, &thdr,
						     &tdata, NULL)) > 0) {
		mail_transaction_log_view_get_prev_pos(view->log_view,
						       &prev_seq, &prev_offset);

		if ((thdr->type & MAIL_TRANSACTION_EXTERNAL) != 0) {
			/* see if this transaction is already synced */
			if (prev_seq < view->map->hdr.log_file_seq ||
			    (prev_seq == view->map->hdr.log_file_seq &&
			     prev_offset <
			     view->map->hdr.log_file_index_ext_offset))
				continue;
		} else if ((thdr->type & MAIL_TRANSACTION_TYPE_MASK) ==
			   MAIL_TRANSACTION_EXPUNGE) {
			/* if the message hasn't yet been expunged from the
			   mailbox, skip this expunge */
			if (prev_seq > mailbox_sync_seq ||
			    (prev_seq == mailbox_sync_seq &&
			     prev_offset >= mailbox_sync_offset)) {
				if (expunge_seq == 0) {
					expunge_seq = prev_seq;
					expunge_offset = prev_offset;
				}
				continue;
			}
		}

		/* we'll just skip over broken entries */
		(void)mail_index_sync_record(&sync_map_ctx, thdr, tdata);
	}
	map = view->map;

	if (view->broken_counters)
		mail_index_view_recalc_counters(view);

	if (had_dirty)
		mail_index_sync_update_hdr_dirty_flag(map);

	/* update sync position */
	// FIXME: eol=TRUE gives intro errors
	mail_index_sync_update_log_offset(&sync_map_ctx, map, FALSE);
	if (expunge_seq != 0) {
		i_assert(expunge_seq == map->hdr.log_file_seq);
		map->hdr.log_file_index_int_offset = expunge_offset;
		map->write_base_header = TRUE;
	}

	/* although mailbox_sync_update gets updated by the header update
	   records, transaction log syncing can internally also update
	   mailbox_sync_max_offset to skip over following external
	   transactions. use it to avoid extra unneeded log reading. */
	map->hdr.log_file_mailbox_offset =
		index->log->head->mailbox_sync_max_offset;

	/*FIXME: if (first_append_uid != 0)
		mail_index_update_day_headers(&map->hdr, first_append_uid);*/

	if (map->write_base_header) {
		i_assert(MAIL_INDEX_MAP_IS_IN_MEMORY(map));
		buffer_write(map->hdr_copy_buf, 0, &map->hdr, sizeof(map->hdr));
	}

	/*FIXME:if (mail_index_map_msync(index, map) < 0)
		ret = -1;*/

	/* restore refcount before closing the view. this is necessary also
	   if map got cloned, because view closing would otherwise destroy it */
	map->refcount++;
	mail_index_view_close(&view);

	mail_index_sync_map_deinit(&sync_map_ctx);

	if (type != MAIL_INDEX_SYNC_HANDLER_VIEW) {
		i_assert(index->map == map);
		index->map = NULL;
		index->hdr = NULL;
	}

	*_map = map;
	return ret < 0 ? -1 : 1;
}
