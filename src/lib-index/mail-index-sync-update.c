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

#include <stdlib.h>

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
mail_index_sync_init_expunge_handlers(struct mail_index_sync_map_ctx *ctx)
{
	const mail_index_expunge_handler_t *const *handlers;
        const struct mail_index_ext *extensions;
	const uint32_t *id_map;
	struct mail_index_expunge_handler eh;
	size_t handlers_count, id_map_size, size;
	uint32_t ext_id;

	handlers = buffer_get_data(ctx->view->index->expunge_handlers,
				   &handlers_count);
	handlers_count /= sizeof(*handlers);

	if (handlers_count == 0)
		return;

	/* set expunge handlers */
	memset(&eh, 0, sizeof(eh));
	if (ctx->expunge_handlers != NULL)
		buffer_set_used_size(ctx->expunge_handlers, 0);
	else {
		ctx->expunge_handlers =
			buffer_create_dynamic(default_pool, 256);
	}

	extensions = ctx->view->map->extensions->data;
	id_map = buffer_get_data(ctx->view->map->ext_id_map, &id_map_size);
	id_map_size /= sizeof(*id_map);

	size = I_MIN(handlers_count, id_map_size);
	for (ext_id = 0; ext_id < size; ext_id++) {
		if (handlers[ext_id] == NULL || id_map[ext_id] == (uint32_t)-1)
			continue;

		eh.handler = handlers[ext_id];
		eh.context = &ctx->extra_context[ext_id];
		eh.record_offset = extensions[id_map[ext_id]].record_offset;
		buffer_append(ctx->expunge_handlers, &eh, sizeof(eh));
	}
	ctx->expunge_handlers_set = TRUE;
	ctx->expunge_handlers_used = TRUE;
}

static void
mail_index_sync_deinit_expunge_handlers(struct mail_index_sync_map_ctx *ctx)
{
	const struct mail_index_expunge_handler *eh;
	size_t i, size;

	if (ctx->expunge_handlers == NULL)
		return;

	eh = buffer_get_data(ctx->expunge_handlers, &size);
	size /= sizeof(*eh);

	for (i = 0; i < size; i++) {
		if (eh->context != NULL)
			eh[i].handler(ctx, 0, NULL, eh->context);
	}

	buffer_free(ctx->expunge_handlers);
}

static void mail_index_sync_init_handlers(struct mail_index_sync_map_ctx *ctx)
{
	size_t size;

	if (ctx->view->map->extensions == NULL)
		return;

	/* set space for extra contexts */
	size = sizeof(void *) * (ctx->view->index->extensions->used /
				 sizeof(struct mail_index_ext));
	if (ctx->extra_context_buf == NULL) {
		ctx->extra_context_buf =
			buffer_create_dynamic(default_pool, size);
	} else {
		buffer_set_used_size(ctx->extra_context_buf, 0);
	}
	buffer_append_zero(ctx->extra_context_buf, size);
	ctx->extra_context =
		buffer_get_modifyable_data(ctx->extra_context_buf, NULL);

	ctx->expunge_handlers_set = FALSE;
	ctx->sync_handlers_initialized = TRUE;
}

static void mail_index_sync_deinit_handlers(struct mail_index_sync_map_ctx *ctx)
{
	mail_index_sync_handler_t *const *sync_handlers;
	size_t i, size;

	if (ctx->extra_context == NULL)
		return;

	sync_handlers = buffer_get_data(ctx->view->index->sync_handlers, &size);
	size /= sizeof(*sync_handlers);

	i_assert(size <= ctx->extra_context_buf->used / sizeof(void *));

	for (i = 0; i < size; i++) {
		if (ctx->extra_context[i] != NULL) {
			sync_handlers[i](ctx, 0, NULL, NULL,
					 &ctx->extra_context[i]);
		}
	}

	buffer_free(ctx->extra_context_buf);
}

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

static int sync_expunge(const struct mail_transaction_expunge *e, void *context)
{
        struct mail_index_sync_map_ctx *ctx = context;
	struct mail_index_view *view = ctx->view;
	struct mail_index_map *map = view->map;
	struct mail_index_header *hdr;
	struct mail_index_record *rec;
	uint32_t count, seq, seq1, seq2;
        struct mail_index_expunge_handler *expunge_handlers, *eh;
	size_t i, expunge_handlers_count;

	if (e->uid1 > e->uid2 || e->uid1 == 0) {
		mail_transaction_log_view_set_corrupted(ctx->view->log_view,
				"Invalid UID range in expunge (%u .. %u)",
				e->uid1, e->uid2);
		return -1;
	}

	if (!view->map->write_to_disk) {
		/* expunges have to be atomic. so we'll have to copy
		   the mapping, do the changes there and then finally
		   replace the whole index file. to avoid extra disk
		   I/O we copy the index into memory rather than to
		   temporary file */
		map = mail_index_map_to_memory(map,
					       map->hdr->record_size);
		mail_index_sync_replace_map(view, map);
	}
	i_assert(MAIL_INDEX_MAP_IS_IN_MEMORY(map));

	if (mail_index_lookup_uid_range(view, e->uid1, e->uid2,
					&seq1, &seq2) < 0)
		return -1;

	if (seq1 == 0)
		return 1;

	if (ctx->sync_handlers_initialized) {
		if (!ctx->expunge_handlers_set)
			mail_index_sync_init_expunge_handlers(ctx);

		expunge_handlers =
			buffer_get_modifyable_data(ctx->expunge_handlers,
						   &expunge_handlers_count);
		expunge_handlers_count /= sizeof(*expunge_handlers);
	} else {
		/* syncing view - don't call expunge handlers */
		expunge_handlers = NULL;
		expunge_handlers_count = 0;
	}

	hdr = buffer_get_modifyable_data(map->hdr_copy_buf, NULL);
	for (seq = seq1; seq <= seq2; seq++) {
                rec = MAIL_INDEX_MAP_IDX(map, seq-1);
		mail_index_header_update_counts(hdr, rec->flags, 0);
	}

	for (i = 0; i < expunge_handlers_count; i++) {
		eh = &expunge_handlers[i];

		for (seq = seq1; seq <= seq2; seq++) {
			rec = MAIL_INDEX_MAP_IDX(map, seq-1);
			eh->handler(ctx, seq,
				    PTR_OFFSET(rec, eh->record_offset),
				    eh->context);
		}
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

	if ((rec->flags & MAIL_INDEX_MAIL_FLAG_DIRTY) != 0)
		hdr->flags |= MAIL_INDEX_HDR_FLAG_HAVE_DIRTY;

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

	if (u->uid1 > u->uid2 || u->uid1 == 0) {
		mail_transaction_log_view_set_corrupted(ctx->view->log_view,
				"Invalid UID range in flag update (%u .. %u)",
				u->uid1, u->uid2);
		return -1;
	}

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

static struct mail_index_ext_header *
get_ext_header(struct mail_index_map *map, const struct mail_index_ext *ext)
{
	struct mail_index_ext_header *ext_hdr;
	uint32_t offset;
	void *hdr;

	/* do some kludgy jumping to get to it. */
	offset = ext->hdr_offset -
		MAIL_INDEX_HEADER_SIZE_ALIGN(sizeof(*ext_hdr) +
					     strlen(ext->name));

	hdr = buffer_get_modifyable_data(map->hdr_copy_buf, NULL);
	ext_hdr = PTR_OFFSET(hdr, offset);
	i_assert(memcmp((char *)(ext_hdr + 1),
			ext->name, strlen(ext->name)) == 0);
	return ext_hdr;
}

static int mail_index_ext_align_cmp(const void *p1, const void *p2)
{
	const struct mail_index_ext *const *e1 = p1, *const *e2 = p2;

	return (int)(*e2)->record_align - (int)(*e1)->record_align;
}

static struct mail_index_map *
sync_ext_reorder(struct mail_index_map *map, uint32_t ext_id, uint16_t old_size)
{
	struct mail_index_map *new_map;
	struct mail_index_ext *ext, **sorted;
	struct mail_index_ext_header *ext_hdr;
	uint16_t *old_offsets, min_align;
	uint32_t offset, old_records_count, rec_idx;
	const void *src;
	size_t i, size;

	t_push();
	ext = buffer_get_modifyable_data(map->extensions, &size);
	size /= sizeof(*ext);

	/* @UNSAFE */
	old_offsets = t_new(uint16_t, size);
	sorted = t_new(struct mail_index_ext *, size);
	for (i = 0; i < size; i++) {
		old_offsets[i] = ext[i].record_offset;
		ext[i].record_offset = 0;
		sorted[i] = &ext[i];
	}
	qsort(sorted, size, sizeof(struct mail_index_ext *),
	      mail_index_ext_align_cmp);

	/* we simply try to use the extensions with largest alignment
	   requirement first. FIXME: if the extension sizes don't match
	   alignmentation, this may not give the minimal layout. */
	offset = sizeof(struct mail_index_record);
	for (;;) {
		min_align = (uint16_t)-1;
		for (i = 0; i < size; i++) {
			if (sorted[i]->record_offset == 0) {
				if ((offset % sorted[i]->record_align) == 0)
					break;
				if (sorted[i]->record_align < min_align)
					min_align = sorted[i]->record_align;
			}
		}
		if (i == size) {
			if (min_align == (uint16_t)-1) {
				/* all done */
				break;
			}
			/* we have to leave space here */
			i_assert(min_align > 1 && min_align < (uint16_t)-1);
			offset += min_align - (offset % min_align);
		} else {
			sorted[i]->record_offset = offset;
			offset += sorted[i]->record_size;
		}

		i_assert(offset < (uint16_t)-1);
	}

	if ((offset % sizeof(uint32_t)) != 0) {
		/* keep 32bit alignment */
		offset += sizeof(uint32_t) - (offset % sizeof(uint32_t));
	}

	/* create a new mapping without records. a bit kludgy. */
	old_records_count = map->records_count;
	map->records_count = 0;
	new_map = mail_index_map_to_memory(map, offset);
	map->records_count = old_records_count;

	/* now copy the records to new mapping */
	src = map->records;
	offset = 0;
	for (rec_idx = 0; rec_idx < old_records_count; rec_idx++) {
		buffer_write(new_map->buffer, offset, src,
			     sizeof(struct mail_index_record));
		for (i = 0; i < size; i++) {
			buffer_write(new_map->buffer,
				     offset + ext[i].record_offset,
				     CONST_PTR_OFFSET(src, old_offsets[i]),
				     i == ext_id ? old_size :
				     ext[i].record_size);
		}
		src = CONST_PTR_OFFSET(src, map->hdr->record_size);
		offset += new_map->hdr->record_size;
	}

	new_map->records = buffer_get_modifyable_data(new_map->buffer, NULL);
	new_map->records_count = old_records_count;

	/* update record offsets in headers */
	for (i = 0; i < size; i++) {
                ext_hdr = get_ext_header(new_map, &ext[i]);
		ext_hdr->record_offset = ext[i].record_offset;
	}

	t_pop();
	return new_map;
}

static void
sync_ext_resize(const struct mail_transaction_ext_intro *u, uint32_t ext_id,
		struct mail_index_sync_map_ctx *ctx)
{
	struct mail_index_map *map = ctx->view->map;
	struct mail_index_ext *ext;
	struct mail_index_ext_header *ext_hdr;
	struct mail_index_header *hdr;
	uint32_t old_size, new_size, old_record_size;
	int modified = FALSE;

	ext = buffer_get_modifyable_data(map->extensions, NULL);
	ext += ext_id;

	old_size = MAIL_INDEX_HEADER_SIZE_ALIGN(ext->hdr_size);
	new_size = MAIL_INDEX_HEADER_SIZE_ALIGN(u->hdr_size);

	if (new_size < old_size) {
		/* header shrinked */
		buffer_delete(map->hdr_copy_buf, ext->hdr_offset + new_size,
			      old_size - new_size);
		modified = TRUE;
	} else if (new_size > old_size) {
		/* header grown */
		buffer_insert_zero(map->hdr_copy_buf,
				   ext->hdr_offset + old_size,
				   new_size - old_size);
		modified = TRUE;
	}

	old_record_size = ext->record_size;
	ext->hdr_size = u->hdr_size;
	ext->record_size = u->record_size;
	ext->record_align = u->record_align;

	if (old_record_size != u->record_size)
		modified = TRUE;

	if (modified) {
		hdr = buffer_get_modifyable_data(map->hdr_copy_buf, NULL);
		hdr->header_size = map->hdr_copy_buf->used;
		map->hdr = hdr;

		ext_hdr = get_ext_header(map, ext);
		ext_hdr->reset_id = ext->reset_id;
		ext_hdr->hdr_size = ext->hdr_size;
		ext_hdr->record_offset = ext->record_offset;
		ext_hdr->record_size = ext->record_size;
		ext_hdr->record_align = ext->record_align;
	}

	if (old_record_size != u->record_size) {
		map = sync_ext_reorder(map, ext_id, old_record_size);
		mail_index_sync_replace_map(ctx->view, map);
	}
}

static int sync_ext_intro(const struct mail_transaction_ext_intro *u,
			  void *context)
{
	struct mail_index_sync_map_ctx *ctx = context;
	struct mail_index_map *map = ctx->view->map;
	struct mail_index_ext_header ext_hdr;
	const struct mail_index_ext *ext;
	struct mail_index_header *hdr;
	const char *name;
	buffer_t *hdr_buf;
	uint32_t ext_id, hdr_offset;

	if (u->ext_id != (uint32_t)-1 &&
	    (map->extensions == NULL ||
	     u->ext_id >= map->extensions->used / sizeof(*ext))) {
		mail_transaction_log_view_set_corrupted(ctx->view->log_view,
			"Extension introduction for unknown id %u", u->ext_id);
		return -1;
	}

	if (u->ext_id == (uint32_t)-1 && u->name_size == 0) {
		mail_transaction_log_view_set_corrupted(ctx->view->log_view,
			"Extension introduction without id or name");
		return -1;
	}

	t_push();
	if (u->ext_id != (uint32_t)-1) {
		name = NULL;
		ext_id = u->ext_id;
	} else {
		name = t_strndup(u + 1, u->name_size);
		ext_id = mail_index_map_lookup_ext(map, name);
	}

	if (ext_id != (uint32_t)-1) {
		/* exists already */
		ext = map->extensions->data;
		ext += ext_id;

		if (u->reset_id == ext->reset_id) {
			/* check if we need to resize anything */
			sync_ext_resize(u, ext_id, ctx);
			ctx->cur_ext_ignore = FALSE;
		} else {
			/* extension was reset and this transaction hadn't
			   yet seen it. ignore this update. */
			ctx->cur_ext_ignore = TRUE;
		}
		t_pop();

		ctx->cur_ext_id = ext_id;
		return 1;
	}

	hdr_buf = map->hdr_copy_buf;
	if (MAIL_INDEX_HEADER_SIZE_ALIGN(hdr_buf->used) != hdr_buf->used) {
		/* we need to add padding between base header and extensions */
		buffer_append_zero(hdr_buf,
				   MAIL_INDEX_HEADER_SIZE_ALIGN(hdr_buf->used) -
				   hdr_buf->used);
	}

	/* register record offset initially using zero,
	   sync_ext_reorder() will fix it. */
	hdr_offset = map->hdr_copy_buf->used + sizeof(ext_hdr) + strlen(name);
	hdr_offset = MAIL_INDEX_HEADER_SIZE_ALIGN(hdr_offset);
	ext_id = mail_index_map_register_ext(ctx->view->index, map, name,
					     hdr_offset, u->hdr_size, 0,
					     u->record_size, u->record_align,
					     u->reset_id);

	ext = map->extensions->data;
	ext += ext_id;

	/* <ext_hdr> <name> [padding] [header data] */
	memset(&ext_hdr, 0, sizeof(ext_hdr));
	ext_hdr.name_size = strlen(name);
	ext_hdr.reset_id = ext->reset_id;
	ext_hdr.hdr_size = ext->hdr_size;
	ext_hdr.record_offset = ext->record_offset;
	ext_hdr.record_size = ext->record_size;
	ext_hdr.record_align = ext->record_align;
	buffer_append(hdr_buf, &ext_hdr, sizeof(ext_hdr));
	buffer_append(hdr_buf, name, strlen(name));
	/* header must begin and end in correct alignment */
	buffer_append_zero(hdr_buf,
		MAIL_INDEX_HEADER_SIZE_ALIGN(hdr_buf->used) - hdr_buf->used +
		MAIL_INDEX_HEADER_SIZE_ALIGN(ext->hdr_size));
	i_assert(hdr_buf->used ==
		 hdr_offset + MAIL_INDEX_HEADER_SIZE_ALIGN(ext->hdr_size));

	hdr = buffer_get_modifyable_data(hdr_buf, NULL);
	hdr->header_size = hdr_buf->used;
	map->hdr = hdr;

	t_pop();

        mail_index_sync_init_handlers(ctx);

	map = sync_ext_reorder(map, ext_id, 0);
	mail_index_sync_replace_map(ctx->view, map);

	ctx->cur_ext_ignore = FALSE;
	ctx->cur_ext_id = ext_id;
	return 1;
}

static int sync_ext_reset(const struct mail_transaction_ext_reset *u,
			  void *context)
{
        struct mail_index_sync_map_ctx *ctx = context;
	struct mail_index_view *view = ctx->view;
	struct mail_index_map *map = view->map;
	struct mail_index_ext_header *ext_hdr;
        struct mail_index_ext *ext;
	struct mail_index_record *rec;
	uint32_t i;

	if (ctx->cur_ext_id == (uint32_t)-1) {
		mail_transaction_log_view_set_corrupted(view->log_view,
			"Extension reset without intro prefix");
		return -1;
	}
	if (ctx->cur_ext_ignore)
		return 1;

	ext = buffer_get_modifyable_data(map->extensions, NULL);
	ext += ctx->cur_ext_id;
	ext->reset_id = u->new_reset_id;

	memset(buffer_get_space_unsafe(map->hdr_copy_buf, ext->hdr_offset,
				       ext->hdr_size), 0, ext->hdr_size);
	map->hdr = map->hdr_copy_buf->data;

	for (i = 0; i < view->messages_count; i++) {
		rec = MAIL_INDEX_MAP_IDX(view->map, i);
		memset(PTR_OFFSET(rec, ext->record_offset), 0,
		       ext->record_size);
	}

	ext_hdr = get_ext_header(map, ext);
	ext_hdr->reset_id = u->new_reset_id;

	return 1;
}

static int sync_ext_hdr_update(const struct mail_transaction_ext_hdr_update *u,
			       void *context)
{
        struct mail_index_sync_map_ctx *ctx = context;
	struct mail_index_map *map = ctx->view->map;
        const struct mail_index_ext *ext;

	if (ctx->cur_ext_id == (uint32_t)-1) {
		mail_transaction_log_view_set_corrupted(ctx->view->log_view,
			"Extension header update without intro prefix");
		return -1;
	}
	if (ctx->cur_ext_ignore)
		return 1;

	ext = map->extensions->data;
	ext += ctx->cur_ext_id;

	buffer_write(map->hdr_copy_buf, ext->hdr_offset + u->offset,
		     u + 1, u->size);
	map->hdr = map->hdr_copy_buf->data;
	return 1;
}

static int
sync_ext_rec_update(const struct mail_transaction_ext_rec_update *u,
		    void *context)
{
        struct mail_index_sync_map_ctx *ctx = context;
	struct mail_index_view *view = ctx->view;
	struct mail_index_record *rec;
	mail_index_sync_handler_t *const *sync_handlers;
	const struct mail_index_ext *ext;
	void *old_data;
	uint32_t seq;
	int ret;

	i_assert(ctx->cur_ext_id != (uint32_t)-1);
	i_assert(!ctx->cur_ext_ignore);

	if (mail_index_lookup_uid_range(view, u->uid, u->uid, &seq, &seq) < 0)
		return -1;

	if (seq == 0)
		return 1;

	ext = view->map->extensions->data;
	ext += ctx->cur_ext_id;

	rec = MAIL_INDEX_MAP_IDX(view->map, seq-1);
	old_data = PTR_OFFSET(rec, ext->record_offset);

	/* @UNSAFE */
	sync_handlers = view->index->sync_handlers->data;
	sync_handlers += ctx->cur_ext_id;

	/* call sync handlers only when we're syncing index (not view) */
	if (*sync_handlers != NULL && ctx->sync_handlers_initialized) {
		ret = (*sync_handlers)(ctx, seq, old_data, u + 1,
				       &ctx->extra_context[ctx->cur_ext_id]);
		if (ret <= 0)
			return ret;
	}

	memcpy(old_data, u + 1, ext->record_size);
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

		for (i = 0; i < hdr->size; ) {
			if (i + sizeof(*rec) > hdr->size) {
				/* should be just extra padding */
				break;
			}

			rec = CONST_PTR_OFFSET(data, i);
			ret = sync_ext_intro(rec, ctx);
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
		ret = sync_ext_reset(rec, ctx);
		break;
	}
	case MAIL_TRANSACTION_EXT_HDR_UPDATE: {
		const struct mail_transaction_ext_hdr_update *rec = data;
		unsigned int i;

		for (i = 0; i < hdr->size; ) {
			rec = CONST_PTR_OFFSET(data, i);
			ret = sync_ext_hdr_update(rec, ctx);
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
			mail_transaction_log_view_set_corrupted(
				ctx->view->log_view,
				"Extension record update update "
				"without intro prefix");
			ret = -1;
			break;
		}

		if (ctx->cur_ext_ignore) {
			ret = 1;
			break;
		}

		ext = ctx->view->map->extensions->data;
		record_size = sizeof(*rec) + ext[ctx->cur_ext_id].record_size;

		rec = data;
		end = CONST_PTR_OFFSET(data, hdr->size);
		while (rec < end) {
			ret = sync_ext_rec_update(rec, ctx);
			if (ret <= 0)
				break;

			rec = CONST_PTR_OFFSET(rec, record_size);
		}
		break;
	}
	default:
		i_unreached();
	}

	return ret;
}

void mail_index_sync_map_init(struct mail_index_sync_map_ctx *sync_map_ctx,
			      struct mail_index_view *view)
{
	memset(sync_map_ctx, 0, sizeof(*sync_map_ctx));
	sync_map_ctx->view = view;
        sync_map_ctx->cur_ext_id = (uint32_t)-1;
}

int mail_index_sync_update_index(struct mail_index_sync_ctx *sync_ctx,
				 int sync_only_external)
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
	int ret, had_dirty, skipped, check_ext_offsets;

        mail_index_sync_map_init(&sync_map_ctx, view);
	mail_index_sync_init_handlers(&sync_map_ctx);

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
		index->hdr = map->hdr;
	}

	mail_index_unmap(index, view->map);
	view->map = map;
	view->map->refcount++;

	tmphdr = buffer_get_modifyable_data(map->hdr_copy_buf, NULL);
	had_dirty = (tmphdr->flags & MAIL_INDEX_HDR_FLAG_HAVE_DIRTY) != 0;
	if (had_dirty)
		tmphdr->flags &= ~MAIL_INDEX_HDR_FLAG_HAVE_DIRTY;

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
			uint32_t prev_seq;
			uoff_t prev_offset;

			mail_transaction_log_view_get_prev_pos(view->log_view,
							       &prev_seq,
							       &prev_offset);
			if (prev_offset < index->hdr->log_file_ext_offset) {
				/* we have already synced this change */
				continue;
			}
			check_ext_offsets = FALSE;
		}

		if ((thdr->type & MAIL_TRANSACTION_APPEND) != 0) {
			const struct mail_index_record *rec = data;

			if (first_append_uid == 0)
				first_append_uid = rec->uid;

			map = view->map;
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

		if (mail_index_sync_record(&sync_map_ctx, thdr, data) < 0) {
			ret = -1;
			break;
		}
	}
	map = view->map;

	if (sync_map_ctx.expunge_handlers_used)
		mail_index_sync_deinit_expunge_handlers(&sync_map_ctx);
	mail_index_sync_deinit_handlers(&sync_map_ctx);

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
	if (!sync_only_external)
		tmphdr->log_file_int_offset = offset;
	tmphdr->log_file_ext_offset = offset;

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
		index->hdr = map->hdr;
	}
	i_assert(view->map == index->map);

        mail_index_view_unlock(view);
	return ret;
}
