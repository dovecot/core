/* Copyright (c) 2004-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "buffer.h"
#include "mail-index-view-private.h"
#include "mail-index-sync-private.h"
#include "mail-index-modseq.h"
#include "mail-transaction-log.h"


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

	i_zero(&eh);
	if (array_is_created(&ctx->expunge_handlers))
		array_clear(&ctx->expunge_handlers);
	else
		i_array_init(&ctx->expunge_handlers, 64);

	rext = array_get(&ctx->view->index->extensions, &rext_count);
	ext = array_get(&ctx->view->map->extensions, &ext_count);
	id_map = array_get(&ctx->view->map->ext_id_map, &id_map_count);
	contexts = array_get_modifiable(&ctx->extra_contexts, &context_count);

	i_assert(context_count >= rext_count);
	for (idx_ext_id = 0; idx_ext_id < rext_count; idx_ext_id++) {
		map_ext_id = idx_ext_id >= id_map_count ? (uint32_t)-1 :
			id_map[idx_ext_id];
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

	if (!array_is_created(&ctx->expunge_handlers))
		return;

	array_foreach(&ctx->expunge_handlers, eh) {
		if (eh->sync_context != NULL) {
			eh->handler(ctx, 0, NULL, eh->sync_context,
				    eh->context);
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
	(void)array_idx_get_space(&ctx->extra_contexts, count - 1);
	/* we need to update the expunge handler list in case they had
	   already been called */
	ctx->expunge_handlers_set = FALSE;
}

void mail_index_sync_deinit_handlers(struct mail_index_sync_map_ctx *ctx)
{
	if (array_is_created(&ctx->extra_contexts))
		array_free(&ctx->extra_contexts);
}

static struct mail_index_ext_header *
get_ext_header(struct mail_index_map *map, const struct mail_index_ext *ext)
{
	struct mail_index_ext_header *ext_hdr;
	void *hdr_base;

	/* do some kludgy jumping to get to it. */
	hdr_base = buffer_get_modifiable_data(map->hdr_copy_buf, NULL);
	ext_hdr = PTR_OFFSET(hdr_base, ext->ext_offset);
	i_assert(memcmp((char *)(ext_hdr + 1),
			ext->name, strlen(ext->name)) == 0);
	return ext_hdr;
}

static int mail_index_ext_align_cmp(const void *p1, const void *p2)
{
	const struct mail_index_ext *const *e1 = p1, *const *e2 = p2;

	return (int)(*e2)->record_align - (int)(*e1)->record_align;
}

static void sync_ext_reorder(struct mail_index_map *map, uint32_t ext_map_idx,
			     uint16_t old_ext_size)
{
	struct mail_index_ext *ext, **sorted;
	struct mail_index_ext_header *ext_hdr;
	uint16_t *old_offsets, *copy_sizes, min_align, max_align;
	uint32_t offset, new_record_size, rec_idx;
	unsigned int i, count;
	const void *src;
	buffer_t *new_buffer;
	size_t new_buffer_size;

	i_assert(MAIL_INDEX_MAP_IS_IN_MEMORY(map) && map->refcount == 1);

	ext = array_get_modifiable(&map->extensions, &count);
	i_assert(ext_map_idx < count);

	/* @UNSAFE */
	old_offsets = t_new(uint16_t, count);
	copy_sizes = t_new(uint16_t, count);
	sorted = t_new(struct mail_index_ext *, count);
	for (i = 0; i < count; i++) {
		old_offsets[i] = ext[i].record_offset;
		copy_sizes[i] = ext[i].record_size;
		ext[i].record_offset = 0;
		sorted[i] = &ext[i];
	}
	qsort(sorted, count, sizeof(struct mail_index_ext *),
	      mail_index_ext_align_cmp);

	if (copy_sizes[ext_map_idx] > old_ext_size) {
		/* we are growing the extension record. remember this
		   so we don't write extra data while copying the record */
		copy_sizes[ext_map_idx] = old_ext_size;
	}

	/* we simply try to use the extensions with largest alignment
	   requirement first. FIXME: if the extension sizes don't match
	   alignment, this may not give the minimal layout. */
	offset = MAIL_INDEX_RECORD_MIN_SIZE;
	max_align = sizeof(uint32_t);
	for (;;) {
		min_align = (uint16_t)-1;
		for (i = 0; i < count; i++) {
			if (sorted[i]->record_align > max_align)
				max_align = sorted[i]->record_align;

			if (sorted[i]->record_offset == 0 &&
			    sorted[i]->record_size > 0) {
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
	new_record_size = offset;
	i_assert(new_record_size >= sizeof(struct mail_index_record));

	/* copy the records to new buffer */
	new_buffer_size = map->rec_map->records_count * new_record_size;
	new_buffer = buffer_create_dynamic(default_pool, new_buffer_size);
	src = map->rec_map->records;
	offset = 0;
	for (rec_idx = 0; rec_idx < map->rec_map->records_count; rec_idx++) {
		/* write the base record */
		buffer_write(new_buffer, offset, src,
			     sizeof(struct mail_index_record));

		/* write extensions */
		for (i = 0; i < count; i++) {
			buffer_write(new_buffer, offset + ext[i].record_offset,
				     CONST_PTR_OFFSET(src, old_offsets[i]),
				     copy_sizes[i]);
		}
		src = CONST_PTR_OFFSET(src, map->hdr.record_size);
		offset += new_record_size;
	}

	if (new_buffer->used != new_buffer_size) {
		/* we didn't fully write the last record */
		size_t space = new_buffer_size - new_buffer->used;
		i_assert(space < new_record_size);
		buffer_append_zero(new_buffer, space);
	}

	buffer_free(&map->rec_map->buffer);
	map->rec_map->buffer = new_buffer;
	map->rec_map->records =
		buffer_get_modifiable_data(map->rec_map->buffer, NULL);
	map->hdr.record_size = new_record_size;

	/* update record offsets in headers */
	for (i = 0; i < count; i++) {
                ext_hdr = get_ext_header(map, &ext[i]);
		ext_hdr->record_offset = ext[i].record_offset;
	}
}

static void
sync_ext_resize(const struct mail_transaction_ext_intro *u,
		uint32_t ext_map_idx, struct mail_index_sync_map_ctx *ctx,
		bool no_shrink)
{
	struct mail_index_map *map;
	struct mail_index_ext *ext;
	struct mail_index_ext_header *ext_hdr;
	uint32_t old_padded_hdr_size, new_padded_hdr_size, old_record_size;
	bool reorder = FALSE;

	ext = array_idx_modifiable(&ctx->view->map->extensions, ext_map_idx);
	old_padded_hdr_size = MAIL_INDEX_HEADER_SIZE_ALIGN(ext->hdr_size);
	new_padded_hdr_size = MAIL_INDEX_HEADER_SIZE_ALIGN(u->hdr_size);

	if (ext->record_align != u->record_align ||
	    ext->record_size != u->record_size) {
		/* record changed */
	} else if (new_padded_hdr_size < old_padded_hdr_size) {
		/* header is shrunk. do we allow? */
		if (no_shrink)
			return;
	} else if (ext->hdr_size == u->hdr_size) {
		/* no changes */
		return;
	}
	/* something changed. get ourself a new map before we start changing
	   anything in it. */
	map = mail_index_sync_get_atomic_map(ctx);
	/* ext was duplicated to the new map. */
	ext = array_idx_modifiable(&map->extensions, ext_map_idx);

	if (new_padded_hdr_size < old_padded_hdr_size) {
		/* header shrank */
		if (no_shrink)
			new_padded_hdr_size = old_padded_hdr_size;
		else {
			buffer_delete(map->hdr_copy_buf,
				      ext->hdr_offset + new_padded_hdr_size,
				      old_padded_hdr_size - new_padded_hdr_size);
			ext->hdr_size = u->hdr_size;
		}
	} else if (new_padded_hdr_size > old_padded_hdr_size) {
		/* header grown */
		buffer_insert_zero(map->hdr_copy_buf,
				   ext->hdr_offset + old_padded_hdr_size,
				   new_padded_hdr_size - old_padded_hdr_size);
		ext->hdr_size = u->hdr_size;
	} else {
		if (ext->hdr_size != u->hdr_size) {
			/* aligned sizes were the same, but the actual sizes
			   had changed */
			ext->hdr_size = u->hdr_size;
		}
	}

	if (ext->record_align < u->record_align ||
	    (ext->record_align > u->record_align && !no_shrink)) {
		ext->record_align = u->record_align;
		reorder = TRUE;
	}

	old_record_size = ext->record_size;
	if (ext->record_size < u->record_size ||
	    (ext->record_size > u->record_size && !no_shrink)) {
		ext->record_size = u->record_size;
		reorder = TRUE;
	}

	i_assert((map->hdr_copy_buf->used % sizeof(uint64_t)) == 0);
	map->hdr_base = map->hdr_copy_buf->data;
	map->hdr.header_size = map->hdr_copy_buf->used;

	ext_hdr = get_ext_header(map, ext);
	ext_hdr->reset_id = ext->reset_id;
	ext_hdr->hdr_size = ext->hdr_size;
	ext_hdr->record_offset = ext->record_offset;
	ext_hdr->record_size = ext->record_size;
	ext_hdr->record_align = ext->record_align;

	if (new_padded_hdr_size != old_padded_hdr_size) {
		/* move all hdr_offset of all extensions after this one */
		unsigned int i, count = array_count(&map->extensions);
		ssize_t diff = (ssize_t)new_padded_hdr_size -
			(ssize_t)old_padded_hdr_size;

		ext = array_first_modifiable(&map->extensions);
		for (i = ext_map_idx + 1; i < count; i++) {
			ext[i].ext_offset += diff;
			ext[i].hdr_offset += diff;
		}
	}

	if (reorder)
		sync_ext_reorder(map, ext_map_idx, old_record_size);
}

static bool
mail_index_sync_ext_unknown_complain(struct mail_index_sync_map_ctx *ctx,
				     uint32_t ext_map_idx)
{
	unsigned char *p;

	if (ext_map_idx >= 1024) {
		/* don't try to track too high values */
		return TRUE;
	}

	if (ctx->unknown_extensions == NULL) {
		ctx->unknown_extensions =
			buffer_create_dynamic(default_pool, ext_map_idx + 8);
	}
	p = buffer_get_space_unsafe(ctx->unknown_extensions, ext_map_idx, 1);
	if (*p != 0) {
		/* we've already complained once */
		return FALSE;
	}
	*p = 1;
	return TRUE;
}

static void
mail_index_sync_ext_init_new(struct mail_index_sync_map_ctx *ctx,
			     const char *name,
			     const struct mail_index_ext_header *ext_hdr,
			     uint32_t *ext_map_idx_r)
{
	struct mail_index_map *map;
	const struct mail_index_ext *ext;
	buffer_t *hdr_buf;
	uint32_t ext_map_idx;

	/* be sure to get a unique mapping before we modify the extensions,
	   otherwise other map users will see the new extension but not the
	   data records that sync_ext_reorder() adds. */
	map = mail_index_sync_get_atomic_map(ctx);

	hdr_buf = map->hdr_copy_buf;
	i_assert(hdr_buf->used == map->hdr.header_size);

	if (MAIL_INDEX_HEADER_SIZE_ALIGN(hdr_buf->used) != hdr_buf->used) {
		/* we need to add padding between base header and extensions */
		buffer_append_zero(hdr_buf,
				   MAIL_INDEX_HEADER_SIZE_ALIGN(hdr_buf->used) -
				   hdr_buf->used);
	}

	/* register record offset initially using zero,
	   sync_ext_reorder() will fix it. */
	ext_map_idx = mail_index_map_register_ext(map, name, hdr_buf->used,
						  ext_hdr);
	ext = array_idx(&map->extensions, ext_map_idx);

	/* <ext_hdr> <name> [padding] [header data] */
	i_assert(ext_hdr->name_size == strlen(name));
	buffer_append(hdr_buf, ext_hdr, sizeof(*ext_hdr));
	buffer_append(hdr_buf, name, ext_hdr->name_size);
	/* header must begin and end in correct alignment */
	buffer_append_zero(hdr_buf,
		MAIL_INDEX_HEADER_SIZE_ALIGN(hdr_buf->used) - hdr_buf->used +
		MAIL_INDEX_HEADER_SIZE_ALIGN(ext->hdr_size));
	i_assert(hdr_buf->used ==
		 ext->hdr_offset + MAIL_INDEX_HEADER_SIZE_ALIGN(ext->hdr_size));
	i_assert((hdr_buf->used % sizeof(uint64_t)) == 0);

	map->hdr.header_size = hdr_buf->used;
	map->hdr_base = hdr_buf->data;

        mail_index_sync_init_handlers(ctx);
	sync_ext_reorder(map, ext_map_idx, 0);
	i_assert(ext->record_offset != 0 || ext->record_size == 0);

	*ext_map_idx_r = ext_map_idx;
}

void mail_index_sync_ext_init(struct mail_index_sync_map_ctx *ctx,
			      const char *name, bool fix_size,
			      uint32_t *ext_map_idx_r)
{
	struct mail_index_map *map = ctx->view->map;
	const struct mail_index_registered_ext *rext;
	struct mail_index_ext_header ext_hdr;
	struct mail_transaction_ext_intro u;
	uint32_t ext_id;

	if (!mail_index_ext_lookup(ctx->view->index, name, &ext_id))
		i_unreached();
	rext = array_idx(&ctx->view->index->extensions, ext_id);

	if (mail_index_map_lookup_ext(map, name, ext_map_idx_r)) {
		if (!fix_size)
			return;

		/* make sure it's the expected size */
		i_zero(&u);
		u.hdr_size = rext->hdr_size;
		u.record_size = rext->record_size;
		u.record_align = rext->record_align;
		sync_ext_resize(&u, *ext_map_idx_r, ctx, FALSE);
	} else {
		i_zero(&ext_hdr);
		ext_hdr.name_size = strlen(name);
		ext_hdr.hdr_size = rext->hdr_size;
		ext_hdr.record_size = rext->record_size;
		ext_hdr.record_align = rext->record_align;
		mail_index_sync_ext_init_new(ctx, name, &ext_hdr,
					     ext_map_idx_r);
	}
}

int mail_index_sync_ext_intro(struct mail_index_sync_map_ctx *ctx,
			      const struct mail_transaction_ext_intro *u)
{
	struct mail_index_map *map = ctx->view->map;
	struct mail_index_ext_header ext_hdr;
	const struct mail_index_ext *ext;
	const char *name, *error;
	uint32_t ext_map_idx;
	bool no_shrink;

	/* default to ignoring the following extension updates in case this
	   intro is corrupted */
	ctx->cur_ext_map_idx = (uint32_t)-2;
	ctx->cur_ext_ignore = TRUE;
	ctx->cur_ext_record_size = 0;

	if (u->ext_id != (uint32_t)-1 &&
	    (!array_is_created(&map->extensions) ||
	     u->ext_id >= array_count(&map->extensions))) {
		if (!mail_index_sync_ext_unknown_complain(ctx, u->ext_id))
			return -1;
		mail_index_sync_set_corrupted(ctx,
			"Extension introduction for unknown id %u", u->ext_id);
		return -1;
	}

	if (u->ext_id == (uint32_t)-1 && u->name_size == 0) {
		mail_index_sync_set_corrupted(ctx,
			"Extension introduction without id or name");
		return -1;
	}

	if (u->ext_id != (uint32_t)-1) {
		name = NULL;
		ext_map_idx = u->ext_id;
	} else {
		name = t_strndup(u + 1, u->name_size);
		if (!mail_index_map_lookup_ext(map, name, &ext_map_idx))
			ext_map_idx = (uint32_t)-1;
	}
	if (ext_map_idx == (uint32_t)-1)
		ext = NULL;
	else {
		ext = array_idx(&map->extensions, ext_map_idx);
		name = ext->name;
	}
	i_assert(name != NULL);

	if (!ctx->internal_update &&
	    strcmp(name, MAIL_INDEX_EXT_KEYWORDS) == 0) {
		/* Keyword extension is handled internally by the keyword
		   code. Any attempt to modify them directly could cause
		   assert-crashes later, so prevent them immediately. */
		mail_index_sync_set_corrupted(ctx,
			"Extension introduction for keywords");
		return -1;
	}

	i_zero(&ext_hdr);
	ext_hdr.name_size = strlen(name);
	ext_hdr.reset_id = u->reset_id;
	ext_hdr.hdr_size = u->hdr_size;
	ext_hdr.record_size = u->record_size;
	ext_hdr.record_align = u->record_align;
	no_shrink = (u->flags & MAIL_TRANSACTION_EXT_INTRO_FLAG_NO_SHRINK) != 0;

	/* make sure the header looks valid before doing anything with it */
	if (mail_index_map_ext_hdr_check(&map->hdr, &ext_hdr,
					 name, &error) < 0) {
		mail_index_sync_set_corrupted(ctx,
			"Broken extension introduction: %s", error);
		return -1;
	}

	ctx->cur_ext_record_size = u->record_size;
	if (ext != NULL) {
		/* exists already */
		if (u->reset_id == ext->reset_id) {
			/* check if we need to resize anything */
			sync_ext_resize(u, ext_map_idx, ctx, no_shrink);
			ctx->cur_ext_ignore = FALSE;
		} else {
			/* extension was reset and this transaction hadn't
			   yet seen it. ignore this update (except for
			   resets). */
			ctx->cur_ext_ignore = TRUE;
		}

		ctx->cur_ext_map_idx = ext_map_idx;
		return 1;
	}

	mail_index_sync_ext_init_new(ctx, name, &ext_hdr, &ext_map_idx);

	ctx->cur_ext_ignore = FALSE;
	ctx->cur_ext_map_idx = ctx->internal_update ?
		(uint32_t)-1 : ext_map_idx;
	return 1;
}

static void mail_index_sync_ext_clear(struct mail_index_view *view,
				      struct mail_index_map *map,
				      struct mail_index_ext *ext)
{
	struct mail_index_record *rec;
	uint32_t seq;

	memset(buffer_get_space_unsafe(map->hdr_copy_buf, ext->hdr_offset,
				       ext->hdr_size), 0, ext->hdr_size);
	map->hdr_base = map->hdr_copy_buf->data;
	i_assert(map->hdr_copy_buf->used == map->hdr.header_size);

	for (seq = 1; seq <= view->map->rec_map->records_count; seq++) {
		rec = MAIL_INDEX_REC_AT_SEQ(view->map, seq);
		memset(PTR_OFFSET(rec, ext->record_offset), 0,
		       ext->record_size);
	}
}

int mail_index_sync_ext_reset(struct mail_index_sync_map_ctx *ctx,
			      const struct mail_transaction_ext_reset *u)
{
	struct mail_index_map *map;
	struct mail_index_ext_header *ext_hdr;
        struct mail_index_ext *ext;

	if (ctx->cur_ext_map_idx == (uint32_t)-1) {
		mail_index_sync_set_corrupted(ctx,
			"Extension reset without intro prefix");
		return -1;
	}
	if (ctx->cur_ext_map_idx == (uint32_t)-2 && ctx->cur_ext_ignore) {
		/* previous extension intro was broken */
		return -1;
	}
	/* since we're resetting the extension, don't check cur_ext_ignore */

	/* a new index file will be created, so the old data won't be
	   accidentally used by other processes. */
	map = mail_index_sync_get_atomic_map(ctx);

	ext = array_idx_modifiable(&map->extensions, ctx->cur_ext_map_idx);
	ext->reset_id = u->new_reset_id;

	if (u->preserve_data == 0)
		mail_index_sync_ext_clear(ctx->view, map, ext);

	ext_hdr = get_ext_header(map, ext);
	ext_hdr->reset_id = u->new_reset_id;
	return 1;
}

int mail_index_sync_ext_hdr_update(struct mail_index_sync_map_ctx *ctx,
				   uint32_t offset, uint32_t size,
				   const void *data)
{
	struct mail_index_map *map = ctx->view->map;
        const struct mail_index_ext *ext;

	if (ctx->cur_ext_map_idx == (uint32_t)-1) {
		mail_index_sync_set_corrupted(ctx,
			"Extension header update without intro prefix");
		return -1;
	}
	if (ctx->cur_ext_ignore)
		return 1;

	ext = array_idx(&map->extensions, ctx->cur_ext_map_idx);
	if (offset + size > ext->hdr_size) {
		mail_index_sync_set_corrupted(ctx,
			"Extension header update points outside header size");
		return -1;
	}

	buffer_write(map->hdr_copy_buf, ext->hdr_offset + offset, data, size);
	map->hdr_base = map->hdr_copy_buf->data;
	i_assert(map->hdr_copy_buf->used == map->hdr.header_size);

	if (ext->index_idx == ctx->view->index->modseq_ext_id)
		mail_index_modseq_hdr_update(ctx->modseq_ctx);
	return 1;
}

int
mail_index_sync_ext_rec_update(struct mail_index_sync_map_ctx *ctx,
			       const struct mail_transaction_ext_rec_update *u)
{
	struct mail_index_view *view = ctx->view;
	struct mail_index_record *rec;
	const struct mail_index_ext *ext;
	void *old_data;
	uint32_t seq;

	i_assert(ctx->cur_ext_map_idx != (uint32_t)-1);
	i_assert(!ctx->cur_ext_ignore);

	if (u->uid == 0 || u->uid >= view->map->hdr.next_uid) {
		mail_index_sync_set_corrupted(ctx,
			"Extension record update for invalid uid=%u", u->uid);
		return -1;
	}

	if (!mail_index_lookup_seq(view, u->uid, &seq))
		return 1;

	ext = array_idx(&view->map->extensions, ctx->cur_ext_map_idx);
	i_assert(ext->record_offset + ctx->cur_ext_record_size <=
		 view->map->hdr.record_size);

	rec = MAIL_INDEX_REC_AT_SEQ(view->map, seq);
	old_data = PTR_OFFSET(rec, ext->record_offset);

	/* @UNSAFE */
	memcpy(old_data, u + 1, ctx->cur_ext_record_size);
	if (ctx->cur_ext_record_size < ext->record_size) {
		memset(PTR_OFFSET(old_data, ctx->cur_ext_record_size), 0,
		       ext->record_size - ctx->cur_ext_record_size);
	}
	return 1;
}

int
mail_index_sync_ext_atomic_inc(struct mail_index_sync_map_ctx *ctx,
			       const struct mail_transaction_ext_atomic_inc *u)
{
	struct mail_index_view *view = ctx->view;
	struct mail_index_record *rec;
	const struct mail_index_ext *ext;
	void *data;
	uint32_t seq;
	uint64_t min_value, max_value, orig_num;

	i_assert(ctx->cur_ext_map_idx != (uint32_t)-1);
	i_assert(!ctx->cur_ext_ignore);

	if (u->uid == 0 || u->uid >= view->map->hdr.next_uid) {
		mail_index_sync_set_corrupted(ctx,
			"Extension record inc for invalid uid=%u", u->uid);
		return -1;
	}

	if (!mail_index_lookup_seq(view, u->uid, &seq))
		return 1;

	ext = array_idx(&view->map->extensions, ctx->cur_ext_map_idx);
	i_assert(ext->record_offset + ctx->cur_ext_record_size <=
		 view->map->hdr.record_size);

	rec = MAIL_INDEX_REC_AT_SEQ(view->map, seq);
	data = PTR_OFFSET(rec, ext->record_offset);

	min_value = u->diff >= 0 ? 0 : (uint64_t)(-(int64_t)u->diff);

	max_value = ctx->cur_ext_record_size == 8 ? (uint64_t)-1 :
		((uint64_t)1 << (ctx->cur_ext_record_size*8)) - 1;
	if (u->diff <= 0) {
		/* skip */
	} else if (max_value >= (uint32_t)u->diff) {
		max_value -= u->diff;
	} else {
		mail_index_sync_set_corrupted(ctx,
			"Extension record inc diff=%d larger than max value=%u "
			"(uid=%u)", u->diff, (unsigned int)max_value, u->uid);
		return -1;
	}

	switch (ctx->cur_ext_record_size) {
	case 1: {
		uint8_t *num = data;

		orig_num = *num;
		if (orig_num >= min_value && orig_num <= max_value)
			*num += u->diff;
		break;
	}
	case 2: {
		uint16_t *num = data;
		orig_num = *num;
		if (orig_num >= min_value && orig_num <= max_value)
			*num += u->diff;
		break;
	}
	case 4: {
		uint32_t *num = data;
		orig_num = *num;
		if (orig_num >= min_value && orig_num <= max_value)
			*num += u->diff;
		break;
	}
	case 8: {
		uint64_t *num = data;
		orig_num = *num;
		if (orig_num >= min_value && orig_num <= max_value)
			*num += u->diff;
		break;
	}
	default:
		mail_index_sync_set_corrupted(ctx,
			"Extension record inc with invalid size=%u",
			ctx->cur_ext_record_size);
		return -1;
	}
	if (orig_num < min_value) {
		mail_index_sync_set_corrupted(ctx,
			"Extension record inc drops number below zero "
			"(uid=%u, diff=%d, orig=%"PRIu64")",
			u->uid, u->diff, orig_num);
		return -1;
	} else if (orig_num > max_value) {
		mail_index_sync_set_corrupted(ctx,
			"Extension record inc overflows number "
			"(uid=%u, diff=%d, orig=%"PRIu64")",
			u->uid, u->diff, orig_num);
		return -1;
	}
	return 1;
}
