/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "buffer.h"
#include "str.h"
#include "mail-cache-private.h"

#include <stdlib.h>

#define CACHE_PREFETCH 1024

int mail_cache_get_record(struct mail_cache *cache, uint32_t offset,
			  const struct mail_cache_record **rec_r)
{
	const struct mail_cache_record *rec;

	i_assert(offset != 0);

	/* we don't know yet how large the record is, so just guess */
	if (mail_cache_map(cache, offset, sizeof(*rec) + CACHE_PREFETCH) < 0)
		return -1;

	if (offset + sizeof(*rec) > cache->mmap_length) {
		mail_cache_set_corrupted(cache, "record points outside file");
		return -1;
	}
	rec = CACHE_RECORD(cache, offset);

	if (rec->size < sizeof(*rec)) {
		mail_cache_set_corrupted(cache, "invalid record size");
		return -1;
	}
	if (rec->size > CACHE_PREFETCH) {
		/* larger than we guessed. map the rest of the record. */
		if (mail_cache_map(cache, offset, rec->size) < 0)
			return -1;
		rec = CACHE_RECORD(cache, offset);
	}

	if (rec->size > cache->mmap_length ||
	    offset + rec->size > cache->mmap_length) {
		mail_cache_set_corrupted(cache, "record points outside file");
		return -1;
	}

	*rec_r = rec;
	return 0;
}

static int
mail_cache_lookup_offset(struct mail_cache *cache, struct mail_index_view *view,
			 uint32_t seq, uint32_t *offset_r)
{
	struct mail_index_map *map;
	const struct mail_index_ext *ext;
	const void *data;
	uint32_t idx;
	int i, ret;

	if (mail_index_lookup_ext_full(view, seq, cache->ext_id,
				       &map, &data) < 0)
		return -1;
	if (data == NULL || *((const uint32_t *)data) == 0) {
		/* nothing in cache (for this record) */
		return 0;
	}

	if (!mail_index_map_get_ext_idx(map, cache->ext_id, &idx))
		i_unreached();
	ext = array_idx(&map->extensions, idx);

	/* reset_id must match file_seq or the offset is for a different cache
	   file. if this happens, try if reopening the cache helps. if not,
	   it was probably for an old cache file that's already lost by now. */
	i = 0;
	while (cache->hdr->file_seq != ext->reset_id) {
		if (++i == 2)
			return 0;

		if ((ret = mail_cache_reopen(cache)) <= 0) {
			/* error / we already have the latest file open */
			return ret;
		}
	}

	*offset_r = *((const uint32_t *)data);
	return 1;
}

static int
mail_cache_foreach_rec(struct mail_cache_view *view, uint32_t *offset,
		       mail_cache_foreach_callback_t *callback, void *context)
{
	struct mail_cache *cache = view->cache;
	const struct mail_cache_record *rec;
	unsigned int data_size;
	uint32_t pos, rec_size, file_field;
	unsigned int field;
	int ret;

	if (mail_cache_get_record(view->cache, *offset, &rec) < 0)
		return -1;

	rec_size = rec->size;
	for (pos = sizeof(*rec); pos + sizeof(uint32_t) <= rec_size; ) {
		file_field = *((const uint32_t *)CONST_PTR_OFFSET(rec, pos));
		pos += sizeof(uint32_t);

		if (file_field >= cache->file_fields_count) {
			/* new field, have to re-read fields header to figure
			   out its size */
			if (mail_cache_header_fields_read(cache) < 0)
				return -1;
			if (file_field >= cache->file_fields_count) {
				mail_cache_set_corrupted(cache,
					"field index too large (%u >= %u)",
					file_field, cache->file_fields_count);
				return -1;
			}

			/* field reading might have re-mmaped the file and
			   caused rec pointer to break. need to get it again. */
			if (mail_cache_get_record(view->cache, *offset,
						  &rec) < 0)
				return -1;
		}

		field = cache->file_field_map[file_field];
		data_size = cache->fields[field].field.field_size;
		if (data_size == (unsigned int)-1) {
			/* variable size field. get its size from the file. */
			if (pos + sizeof(uint32_t) > rec_size) {
				/* broken. we'll catch this error below. */
			} else {
				data_size = *((const uint32_t *)
					      CONST_PTR_OFFSET(rec, pos));
				pos += sizeof(uint32_t);
			}
		}

		if (rec_size - pos < data_size) {
			mail_cache_set_corrupted(cache,
				"record continues outside its allocated size");
			return -1;
		}

		ret = callback(view, field, CONST_PTR_OFFSET(rec, pos),
			       data_size, context);
		if (ret != 1)
			return ret;

		/* each record begins from 32bit aligned position */
		pos += (data_size + sizeof(uint32_t)-1) & ~(sizeof(uint32_t)-1);
	}

	if (pos != rec_size) {
		mail_cache_set_corrupted(cache, "record has invalid size");
		return -1;
	}

	*offset = rec->prev_offset;
	return 1;
}

bool mail_cache_track_loops(ARRAY_TYPE(uint32_t) *array, uint32_t offset)
{
	const uint32_t *offsets;
	unsigned int i, count;

	offsets = array_get(array, &count);
	for (i = 0; i < count; i++) {
		if (offsets[i] == offset)
			return TRUE;
	}
	array_append(array, &offset, 1);
	return FALSE;
}

int mail_cache_foreach(struct mail_cache_view *view, uint32_t seq,
                       mail_cache_foreach_callback_t *callback, void *context)
{
	uint32_t offset;
	int ret;

	if (!view->cache->opened)
		(void)mail_cache_open_and_verify(view->cache);

        if (MAIL_CACHE_IS_UNUSABLE(view->cache))
		return 0;

	if ((ret = mail_cache_lookup_offset(view->cache, view->view,
					    seq, &offset)) <= 0)
		return ret;

	ret = 1;
	array_clear(&view->looping_offsets);
	while (offset != 0 && ret > 0) {
		if (mail_cache_track_loops(&view->looping_offsets, offset)) {
			mail_cache_set_corrupted(view->cache,
						 "record list is circular");
			return -1;
		}
		ret = mail_cache_foreach_rec(view, &offset,
					     callback, context);
	}

	if (ret > 0 && view->trans_seq1 <= seq && view->trans_seq2 >= seq &&
	    mail_cache_lookup_offset(view->cache, view->trans_view,
				     seq, &offset) > 0) {
		array_clear(&view->looping_offsets);
		while (offset != 0 && ret > 0) {
			if (mail_cache_track_loops(&view->looping_offsets,
						   offset)) {
				mail_cache_set_corrupted(view->cache,
					"record list is circular");
				return -1;
			}
			ret = mail_cache_foreach_rec(view, &offset,
						     callback, context);
		}
	}

	return ret;
}

static int
mail_cache_seq_callback(struct mail_cache_view *view, uint32_t field,
			const void *data __attr_unused__,
			size_t data_size __attr_unused__,
			void *context __attr_unused__)
{
	buffer_write(view->cached_exists_buf, field,
		     &view->cached_exists_value, 1);
	return 1;
}

static int mail_cache_seq(struct mail_cache_view *view, uint32_t seq)
{
	int ret;

	if (++view->cached_exists_value == 0) {
		/* wrapped, we'll have to clear the buffer */
		buffer_reset(view->cached_exists_buf);
		view->cached_exists_value++;
	}

	view->cached_exists_seq = seq;
	ret = mail_cache_foreach(view, seq, mail_cache_seq_callback, NULL);
	return ret < 0 ? -1 : 0;
}

static bool
mail_cache_file_has_field(struct mail_cache *cache, unsigned int field)
{
	i_assert(field < cache->fields_count);
	return cache->field_file_map[field] != (uint32_t)-1;
}

int mail_cache_field_exists(struct mail_cache_view *view, uint32_t seq,
			    unsigned int field)
{
	const uint8_t *data;

	i_assert(seq > 0);

	if (!view->cache->opened)
		(void)mail_cache_open_and_verify(view->cache);

	if (!mail_cache_file_has_field(view->cache, field))
		return 0;

	/* FIXME: we should discard the cache if view has been synced */
	if (view->cached_exists_seq != seq) {
		if (mail_cache_seq(view, seq) < 0)
			return -1;
	}

	data = view->cached_exists_buf->data;
	return (field <= view->cached_exists_buf->used &&
		data[field] == view->cached_exists_value) ? 1 : 0;
}

enum mail_cache_decision_type
mail_cache_field_get_decision(struct mail_cache *cache, unsigned int field)
{
	i_assert(field < cache->fields_count);

	return cache->fields[field].field.decision;
}

struct mail_cache_lookup_context {
	buffer_t *dest_buf;
	uint32_t field;
	bool found;
};

static int
mail_cache_lookup_callback(struct mail_cache_view *view __attr_unused__,
			   uint32_t field, const void *data,
			   size_t data_size, void *context)
{
        struct mail_cache_lookup_context *ctx = context;

	i_assert(!ctx->found);

	if (ctx->field != field)
		return 1;

	buffer_append(ctx->dest_buf, data, data_size);
	ctx->found = TRUE;
	return 0;
}

static int
mail_cache_lookup_bitmask_callback(struct mail_cache_view *view __attr_unused__,
				   uint32_t field, const void *data,
				   size_t data_size, void *context)
{
        struct mail_cache_lookup_context *ctx = context;
	const unsigned char *src = data;
	unsigned char *dest;
	size_t i;

        if (ctx->field != field)
		return 1;

	/* merge all bits */
	dest = buffer_get_space_unsafe(ctx->dest_buf, 0, data_size);
	for (i = 0; i < data_size; i++)
		dest[i] |= src[i];
	ctx->found = TRUE;
	return 1;
}

int mail_cache_lookup_field(struct mail_cache_view *view, buffer_t *dest_buf,
			    uint32_t seq, unsigned int field)
{
	struct mail_cache_lookup_context ctx;
	const struct mail_cache_field *field_def;
	int ret;

	if ((ret = mail_cache_field_exists(view, seq, field)) <= 0)
		return ret;
	field_def = &view->cache->fields[field].field;

	mail_cache_decision_state_update(view, seq, field);

	/* the field should exist */
	memset(&ctx, 0, sizeof(ctx));
	ctx.field = field;
	ctx.dest_buf = dest_buf;

	if (field_def->type != MAIL_CACHE_FIELD_BITMASK) {
		ret = mail_cache_foreach(view, seq, mail_cache_lookup_callback,
					 &ctx);
	} else {
		/* make sure all bits are cleared first */
		buffer_write_zero(dest_buf, 0, field_def->field_size);
		ret = mail_cache_foreach(view, seq,
					 mail_cache_lookup_bitmask_callback,
					 &ctx);
	}
	return ret < 0 ? -1 : (ctx.found ? 1 : 0);
}

struct header_lookup_data {
	uint32_t offset;
	uint32_t data_size;
};

struct header_lookup_line {
	uint32_t line_num;
        struct header_lookup_data *data;
};

enum {
	HDR_FIELD_STATE_DONTWANT = 0,
	HDR_FIELD_STATE_WANT,
	HDR_FIELD_STATE_SEEN
};

struct header_lookup_context {
	ARRAY_DEFINE(lines, struct header_lookup_line);

	unsigned int max_field;
	uint8_t *field_state;
};

static int
headers_find_callback(struct mail_cache_view *view, uint32_t field,
		      const void *data, size_t data_size, void *context)
{
	struct header_lookup_context *ctx = context;
	const uint32_t *lines = data;
	struct header_lookup_line hdr_line;
        struct header_lookup_data *hdr_data;
	unsigned int i, lines_count;

	if (field > ctx->max_field ||
	    ctx->field_state[field] != HDR_FIELD_STATE_WANT) {
		/* a) don't want it, b) duplicate */
		return 1;
	}
	ctx->field_state[field] = HDR_FIELD_STATE_SEEN;

	/* data = { line_nums[], 0, "headers" } */
	for (i = 0; data_size >= sizeof(uint32_t); i++) {
		data_size -= sizeof(uint32_t);
		if (lines[i] == 0)
			break;
	}
	lines_count = i;

	hdr_data = t_new(struct header_lookup_data, 1);
	hdr_data->offset = (const char *)&lines[lines_count+1] -
		(const char *)view->cache->data;
	hdr_data->data_size = (uint32_t)data_size;

	for (i = 0; i < lines_count; i++) {
		hdr_line.line_num = lines[i];
		hdr_line.data = hdr_data;
		array_append(&ctx->lines, &hdr_line, 1);
	}
	return 1;
}

static int header_lookup_line_cmp(const void *p1, const void *p2)
{
	const struct header_lookup_line *l1 = p1, *l2 = p2;

	return (int)l1->line_num - (int)l2->line_num;
}

int mail_cache_lookup_headers(struct mail_cache_view *view, string_t *dest,
			      uint32_t seq, unsigned int fields[],
			      unsigned int fields_count)
{
	struct mail_cache *cache = view->cache;
	struct header_lookup_context ctx;
	struct header_lookup_line *lines;
	const unsigned char *p, *start, *end;
	unsigned int i, count;
	size_t hdr_size;
	uint8_t want = HDR_FIELD_STATE_WANT;
	buffer_t *buf;
	int ret;

	if (fields_count == 0)
		return 1;

	if (!view->cache->opened)
		(void)mail_cache_open_and_verify(view->cache);

	t_push();
	memset(&ctx, 0, sizeof(ctx));

	/* mark all the fields we want to find. */
	buf = buffer_create_dynamic(pool_datastack_create(), 32);
	for (i = 0; i < fields_count; i++) {
		if (!mail_cache_file_has_field(cache, fields[i])) {
			t_pop();
			return 0;
		}

		if (fields[i] > ctx.max_field)
			ctx.max_field = fields[i];

		buffer_write(buf, fields[i], &want, 1);
	}
	ctx.field_state = buffer_get_modifiable_data(buf, NULL);

	/* lookup the fields */
	t_array_init(&ctx.lines, 32);
	ret = mail_cache_foreach(view, seq, headers_find_callback, &ctx);
	if (ret <= 0) {
		t_pop();
		return ret;
	}

	/* check that all fields were found */
	for (i = 0; i <= ctx.max_field; i++) {
		if (ctx.field_state[i] == HDR_FIELD_STATE_WANT) {
			t_pop();
			return 0;
		}
	}

	for (i = 0; i < fields_count; i++)
		mail_cache_decision_state_update(view, seq, fields[i]);

	/* we need to return headers in the order they existed originally.
	   we can do this by sorting the messages by their line numbers. */
	lines = array_get_modifiable(&ctx.lines, &count);
	qsort(lines, count, sizeof(*lines), header_lookup_line_cmp);

	/* then start filling dest buffer from the headers */
	for (i = 0; i < count; i++) {
		start = CONST_PTR_OFFSET(cache->data, lines[i].data->offset);
		end = start + lines[i].data->data_size;

		/* find the end of the (multiline) header */
		for (p = start; p != end; p++) {
			if (*p == '\n' &&
			    (p+1 == end || (p[1] != ' ' && p[1] != '\t'))) {
				p++;
				break;
			}
		}
		hdr_size = (size_t)(p - start);
		buffer_append(dest, start, hdr_size);

		/* if there are more lines for this header, the following lines
		   continue after this one. so skip this line. */
		lines[i].data->offset += hdr_size;
		lines[i].data->data_size -= hdr_size;
	}

	t_pop();
	return 1;
}
