/* Copyright (C) 2004 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "buffer.h"
#include "mail-index-view-private.h"
#include "mail-index-sync-private.h"
#include "mail-transaction-log.h"

#include <stdlib.h>

void mail_index_sync_init_expunge_handlers(struct mail_index_sync_map_ctx *ctx)
{
        const struct mail_index_ext *ext;
	const struct mail_index_registered_ext *rext;
	const uint32_t *id_map;
	void **contexts;
	struct mail_index_expunge_handler eh;
	unsigned int ext_count, id_map_count;
	unsigned int rext_count, context_count;
	uint32_t idx_ext_id, map_ext_id;

	if (!array_is_created(&ctx->view->map->extensions))
		return;

	memset(&eh, 0, sizeof(eh));
	if (array_is_created(&ctx->expunge_handlers))
		array_clear(&ctx->expunge_handlers);
	else
		i_array_init(&ctx->expunge_handlers, 64);

	rext = array_get(&ctx->view->index->extensions, &rext_count);
	ext = array_get(&ctx->view->map->extensions, &ext_count);
	id_map = array_get(&ctx->view->map->ext_id_map, &id_map_count);
	contexts = array_get_modifiable(&ctx->extra_contexts, &context_count);

	i_assert(id_map_count <= rext_count);

	for (idx_ext_id = 0; idx_ext_id < id_map_count; idx_ext_id++) {
		map_ext_id = id_map[idx_ext_id];
		if (rext[idx_ext_id].expunge_handler == NULL ||
		    (map_ext_id == (uint32_t)-1 &&
		     !rext[idx_ext_id].expunge_handler_call_always))
			continue;

		eh.handler = rext[idx_ext_id].expunge_handler;
		eh.context = rext[idx_ext_id].expunge_context;
		eh.sync_context = &contexts[idx_ext_id];
		eh.record_offset = map_ext_id == (uint32_t)-1 ? 0 :
			ext[map_ext_id].record_offset;
		array_append(&ctx->expunge_handlers, &eh, 1);
	}
	ctx->expunge_handlers_set = TRUE;
	ctx->expunge_handlers_used = TRUE;
}

void
mail_index_sync_deinit_expunge_handlers(struct mail_index_sync_map_ctx *ctx)
{
	const struct mail_index_expunge_handler *eh;
	unsigned int i, count;

	if (!array_is_created(&ctx->expunge_handlers))
		return;

	eh = array_get(&ctx->expunge_handlers, &count);
	for (i = 0; i < count; i++) {
		if (eh->sync_context != NULL) {
			eh[i].handler(ctx, 0, NULL, eh->sync_context,
				      eh[i].context);
		}
	}

	array_free(&ctx->expunge_handlers);
}

void mail_index_sync_init_handlers(struct mail_index_sync_map_ctx *ctx)
{
	unsigned int count;

	if (!array_is_created(&ctx->view->map->extensions))
		return;

	/* set space for extra contexts */
	count = array_count(&ctx->view->index->extensions);
	i_assert(count > 0);

	if (!array_is_created(&ctx->extra_contexts))
		i_array_init(&ctx->extra_contexts, count);

	/* make sure the extra_contexts contains everything */
	(void)array_idx_modifiable(&ctx->extra_contexts, count - 1);
	/* we need to update the expunge handler list in case they had
	   already been called */
	ctx->expunge_handlers_set = FALSE;
}

void mail_index_sync_deinit_handlers(struct mail_index_sync_map_ctx *ctx)
{
	const struct mail_index_registered_ext *rext;
	void **extra_contexts;
	unsigned int i, rext_count, context_count;

	if (!array_is_created(&ctx->extra_contexts))
		return;

	rext = array_get(&ctx->view->index->extensions, &rext_count);
	extra_contexts =
		array_get_modifiable(&ctx->extra_contexts, &context_count);
	i_assert(context_count <= rext_count);

	for (i = 0; i < context_count; i++) {
		if (extra_contexts[i] != NULL) {
			rext[i].sync_handler.callback(ctx, 0, NULL, NULL,
						      &extra_contexts[i]);
		}
	}

	array_free(&ctx->extra_contexts);
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

	hdr_base = buffer_get_modifiable_data(map->hdr_copy_buf, NULL);
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
	uint16_t *old_offsets, min_align, max_align;
	uint32_t offset, old_records_count, rec_idx;
	unsigned int i, count;
	const void *src;

	t_push();
	ext = array_get_modifiable(&map->extensions, &count);

	/* @UNSAFE */
	old_offsets = t_new(uint16_t, count);
	sorted = t_new(struct mail_index_ext *, count);
	for (i = 0; i < count; i++) {
		old_offsets[i] = ext[i].record_offset;
		ext[i].record_offset = 0;
		sorted[i] = &ext[i];
	}
	qsort(sorted, count, sizeof(struct mail_index_ext *),
	      mail_index_ext_align_cmp);

	/* we simply try to use the extensions with largest alignment
	   requirement first. FIXME: if the extension sizes don't match
	   alignmentation, this may not give the minimal layout. */
	offset = sizeof(struct mail_index_record);
	max_align = sizeof(uint32_t);
	for (;;) {
		min_align = (uint16_t)-1;
		for (i = 0; i < count; i++) {
			if (sorted[i]->record_align > max_align)
				max_align = sorted[i]->record_align;

			if (sorted[i]->record_offset == 0) {
				if ((offset % sorted[i]->record_align) == 0)
					break;
				if (sorted[i]->record_align < min_align)
					min_align = sorted[i]->record_align;
			}
		}
		if (i == count) {
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

	if ((offset % max_align) != 0) {
		/* keep record size divisible with maximum alignment */
		offset += max_align - (offset % max_align);
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
		for (i = 0; i < count; i++) {
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

	new_map->records = buffer_get_modifiable_data(new_map->buffer, NULL);
	new_map->records_count = old_records_count;
	i_assert(new_map->records_count == new_map->hdr.messages_count);

	/* update record offsets in headers */
	for (i = 0; i < count; i++) {
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
	bool modified = FALSE;

	ext = array_idx_modifiable(&map->extensions, ext_id);

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

	if (new_size != old_size) {
		/* move all hdr_offset of all extensions after this one */
		unsigned i, count = array_count(&map->extensions);
		ssize_t diff = (ssize_t)new_size - (ssize_t)old_size;

		ext = array_idx_modifiable(&map->extensions, 0);
		for (i = ext_id + 1; i < count; i++)
			ext[i].hdr_offset += diff;
	}

	if (old_record_size != u->record_size) {
		map = sync_ext_reorder(map, ext_id, old_record_size);
		mail_index_sync_replace_map(ctx, map);
	} else if (modified) {
		/* header size changed. recreate index file. */
		map = mail_index_map_clone(map, map->hdr.record_size);
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
	    (!array_is_created(&map->extensions) ||
	     u->ext_id >= array_count(&map->extensions))) {
		mail_index_sync_set_corrupted(ctx,
			"Extension introduction for unknown id %u", u->ext_id);
		return -1;
	}

	if (u->ext_id == (uint32_t)-1 && u->name_size == 0) {
		mail_index_sync_set_corrupted(ctx,
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
		ext = array_idx(&map->extensions, ext_id);

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

	if (map->refcount != 1) {
		/* below we'll first add the extension to the mapping, and then
		   call sync_ext_reorder() which clones the map. that however
		   leaves this mapping with the new extension, but without
		   a resized record_size. if the mapping is still used
		   elsewhere, it will create problems. so here we'll just make
		   sure that the partially updated mapping will get destroyed
		   once the resize is complete. */
		map = mail_index_map_clone(map, map->hdr.record_size);
		mail_index_sync_replace_map(ctx, map);
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

	ext = array_idx(&map->extensions, ext_id);

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
		mail_index_sync_set_corrupted(ctx,
			"Extension reset without intro prefix");
		return -1;
	}
	if (ctx->cur_ext_ignore)
		return 1;

	if (!map->write_to_disk || map->refcount != 1) {
		/* a new index file will be created, so the old data won't be
		   accidentally used by other processes. */
		map = mail_index_map_clone(map, map->hdr.record_size);
		mail_index_sync_replace_map(ctx, map);
	}

	ext = array_idx_modifiable(&map->extensions, ctx->cur_ext_id);
	ext->reset_id = u->new_reset_id;

	memset(buffer_get_space_unsafe(map->hdr_copy_buf, ext->hdr_offset,
				       ext->hdr_size), 0, ext->hdr_size);
	map->hdr_base = map->hdr_copy_buf->data;

	for (i = 0; i < view->map->records_count; i++) {
		rec = MAIL_INDEX_MAP_IDX(view->map, i);
		memset(PTR_OFFSET(rec, ext->record_offset), 0,
		       ext->record_size);
	}
	map->write_seq_first = 1;
	map->write_seq_last = view->map->records_count;

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
		mail_index_sync_set_corrupted(ctx,
			"Extension header update without intro prefix");
		return -1;
	}
	if (ctx->cur_ext_ignore)
		return 1;

	ext = array_idx(&map->extensions, ctx->cur_ext_id);
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
	const struct mail_index_ext *ext;
	const struct mail_index_registered_ext *rext;
	void *old_data;
	uint32_t seq;
	int ret;

	i_assert(ctx->cur_ext_id != (uint32_t)-1);
	i_assert(!ctx->cur_ext_ignore);

	if (mail_index_lookup_uid_range(view, u->uid, u->uid, &seq, &seq) < 0)
		return -1;

	if (seq == 0)
		return 1;

	ext = array_idx(&view->map->extensions, ctx->cur_ext_id);

	rec = MAIL_INDEX_MAP_IDX(view->map, seq-1);
	old_data = PTR_OFFSET(rec, ext->record_offset);

	rext = array_idx(&view->index->extensions, ext->index_idx);

	/* call sync handlers only when its registered type matches with
	   current synchronization type (index/view) */
	if ((rext->sync_handler.type & ctx->type) != 0) {
		void **extra_context =
			array_idx_modifiable(&ctx->extra_contexts,
					     ext->index_idx);
		ret = rext->sync_handler.callback(ctx, seq, old_data, u + 1,
						  extra_context);
		if (ret <= 0)
			return ret;
	}

	if (view->map->write_seq_first == 0 || view->map->write_seq_first > seq)
		view->map->write_seq_first = seq;
	if (view->map->write_seq_last < seq)
                view->map->write_seq_last = seq;

	/* @UNSAFE */
	memcpy(old_data, u + 1, ext->record_size);
	return 1;
}
