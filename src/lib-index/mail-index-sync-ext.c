/* Copyright (C) 2004 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "mail-index-view-private.h"
#include "mail-index-sync-private.h"
#include "mail-transaction-log.h"

#include <stdlib.h>

void mail_index_sync_init_expunge_handlers(struct mail_index_sync_map_ctx *ctx)
{
	const mail_index_expunge_handler_t *const *handlers;
        const struct mail_index_ext *extensions;
	const uint32_t *id_map;
	struct mail_index_expunge_handler eh;
	size_t handlers_count, id_map_size, size;
	uint32_t idx_ext_id, map_ext_id;

	if (ctx->view->map->extensions == NULL)
		return;

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
	for (idx_ext_id = 0; idx_ext_id < size; idx_ext_id++) {
		map_ext_id = id_map[idx_ext_id];
		if (handlers[idx_ext_id] == NULL || map_ext_id == (uint32_t)-1)
			continue;

		eh.handler = handlers[idx_ext_id];
		eh.context = &ctx->extra_context[map_ext_id];
		eh.record_offset = extensions[map_ext_id].record_offset;
		buffer_append(ctx->expunge_handlers, &eh, sizeof(eh));
	}
	ctx->expunge_handlers_set = TRUE;
	ctx->expunge_handlers_used = TRUE;
}

void
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

void mail_index_sync_init_handlers(struct mail_index_sync_map_ctx *ctx)
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
}

void mail_index_sync_deinit_handlers(struct mail_index_sync_map_ctx *ctx)
{
	const struct mail_index_sync_handler *sync_handlers;
	const struct mail_index_ext *ext;
	size_t i, synch_size, size;

	if (ctx->extra_context == NULL)
		return;

	sync_handlers = buffer_get_data(ctx->view->index->sync_handlers,
					&synch_size);
	synch_size /= sizeof(*sync_handlers);

	i_assert(synch_size <= ctx->extra_context_buf->used / sizeof(void *));

	ext = buffer_get_data(ctx->view->map->extensions, &size);
	size /= sizeof(*ext);
	i_assert(size <= synch_size);

	/* sync_handlers[] is ordered by index->extensions while
	   extra_context is ordered by map->extensions. */
	for (i = 0; i < size; i++) {
		if (ctx->extra_context[i] != NULL) {
			sync_handlers[ext[i].index_idx].
				callback(ctx, 0, NULL, NULL,
					 &ctx->extra_context[i]);
		}
	}

	buffer_free(ctx->extra_context_buf);
}

static struct mail_index_ext_header *
get_ext_header(struct mail_index_map *map, const struct mail_index_ext *ext)
{
	struct mail_index_ext_header *ext_hdr;
	uint32_t offset;
	void *hdr_base;

	/* do some kludgy jumping to get to it. */
	offset = ext->hdr_offset -
		MAIL_INDEX_HEADER_SIZE_ALIGN(sizeof(*ext_hdr) +
					     strlen(ext->name));

	hdr_base = buffer_get_modifyable_data(map->hdr_copy_buf, NULL);
	ext_hdr = PTR_OFFSET(hdr_base, offset);
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
	new_map = mail_index_map_clone(map, offset);
	map->records_count = old_records_count;

	if (old_size > ext[ext_id].record_size) {
		/* we are shrinking the record */
		old_size = ext[ext_id].record_size;
	}

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
		src = CONST_PTR_OFFSET(src, map->hdr.record_size);
		offset += new_map->hdr.record_size;
	}

	if (new_map->buffer->used !=
	    old_records_count * new_map->hdr.record_size) {
		/* we didn't fully write the last record */
		size_t space = old_records_count * new_map->hdr.record_size -
			new_map->buffer->used;
		i_assert(space < new_map->hdr.record_size);
		buffer_append_zero(new_map->buffer, space);
	}

	new_map->records = buffer_get_modifyable_data(new_map->buffer, NULL);
	new_map->records_count = old_records_count;
	i_assert(new_map->records_count == new_map->hdr.messages_count);

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
		i_assert((map->hdr_copy_buf->used % sizeof(uint64_t)) == 0);
		map->hdr_base = map->hdr_copy_buf->data;
		map->hdr.header_size = map->hdr_copy_buf->used;

		ext_hdr = get_ext_header(map, ext);
		ext_hdr->reset_id = ext->reset_id;
		ext_hdr->hdr_size = ext->hdr_size;
		ext_hdr->record_offset = ext->record_offset;
		ext_hdr->record_size = ext->record_size;
		ext_hdr->record_align = ext->record_align;
	}

	if (old_record_size != u->record_size) {
		map = sync_ext_reorder(map, ext_id, old_record_size);
		mail_index_sync_replace_map(ctx, map);
	}
}

int mail_index_sync_ext_intro(struct mail_index_sync_map_ctx *ctx,
			      const struct mail_transaction_ext_intro *u)
{
	struct mail_index_map *map = ctx->view->map;
	struct mail_index_ext_header ext_hdr;
	const struct mail_index_ext *ext;
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
	i_assert((hdr_buf->used % sizeof(uint64_t)) == 0);

	map->hdr.header_size = hdr_buf->used;
	map->hdr_base = map->hdr_copy_buf->data;

	t_pop();

        mail_index_sync_init_handlers(ctx);

	map = sync_ext_reorder(map, ext_id, 0);
	mail_index_sync_replace_map(ctx, map);

	ctx->cur_ext_ignore = FALSE;
	ctx->cur_ext_id = ext_id;
	return 1;
}

int mail_index_sync_ext_reset(struct mail_index_sync_map_ctx *ctx,
			      const struct mail_transaction_ext_reset *u)
{
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
	map->hdr_base = map->hdr_copy_buf->data;

	for (i = 0; i < view->map->records_count; i++) {
		rec = MAIL_INDEX_MAP_IDX(view->map, i);
		memset(PTR_OFFSET(rec, ext->record_offset), 0,
		       ext->record_size);
	}

	ext_hdr = get_ext_header(map, ext);
	ext_hdr->reset_id = u->new_reset_id;

	return 1;
}

int
mail_index_sync_ext_hdr_update(struct mail_index_sync_map_ctx *ctx,
			       const struct mail_transaction_ext_hdr_update *u)
{
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
	map->hdr_base = map->hdr_copy_buf->data;
	return 1;
}

int
mail_index_sync_ext_rec_update(struct mail_index_sync_map_ctx *ctx,
			       const struct mail_transaction_ext_rec_update *u)
{
	struct mail_index_view *view = ctx->view;
	struct mail_index_record *rec;
        const struct mail_index_sync_handler *sync_handlers;
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

	sync_handlers = view->index->sync_handlers->data;
	sync_handlers += ext->index_idx;

	/* call sync handlers only when we're syncing index (not view) */
	if ((sync_handlers->type & ctx->type) != 0) {
		ret = sync_handlers->callback(ctx, seq, old_data, u + 1,
					&ctx->extra_context[ctx->cur_ext_id]);
		if (ret <= 0)
			return ret;
	}

	/* @UNSAFE */
	memcpy(old_data, u + 1, ext->record_size);
	return 1;
}
