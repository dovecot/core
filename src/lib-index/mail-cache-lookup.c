/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "mail-cache-private.h"

#include <stdlib.h>

#define CACHE_PREFETCH 1024

struct mail_cache_record *
mail_cache_get_record(struct mail_cache *cache, uint32_t offset)
{
	struct mail_cache_record *cache_rec;

	if (offset == 0)
		return NULL;

	if (mail_cache_map(cache, offset,
			   sizeof(*cache_rec) + CACHE_PREFETCH) < 0)
		return NULL;

	if (offset + sizeof(*cache_rec) > cache->mmap_length) {
		mail_cache_set_corrupted(cache, "record points outside file");
		return NULL;
	}
	cache_rec = CACHE_RECORD(cache, offset);

	if (cache_rec->size < sizeof(*cache_rec)) {
		mail_cache_set_corrupted(cache, "invalid record size");
		return NULL;
	}
	if (cache_rec->size > CACHE_PREFETCH) {
		if (mail_cache_map(cache, offset, cache_rec->size) < 0)
			return NULL;
		cache_rec = CACHE_RECORD(cache, offset);
	}

	if (offset + cache_rec->size > cache->mmap_length) {
		mail_cache_set_corrupted(cache, "record points outside file");
		return NULL;
	}
	return cache_rec;
}

static int mail_cache_lookup_offset(struct mail_cache_view *view, uint32_t seq,
				    uint32_t *offset_r)
{
	const struct mail_index_record *rec;
	struct mail_index_map *map;
	int i, ret;

	for (i = 0; i < 2; i++) {
		if (mail_index_lookup_full(view->view, seq, &map, &rec) < 0)
			return -1;

		if (map->hdr->cache_file_seq == view->cache->hdr->file_seq) {
			*offset_r = rec->cache_offset;
			return 1;
		}

		if ((ret = mail_cache_reopen(view->cache)) <= 0)
			return ret;
	}

	return 0;
}

static int
mail_cache_foreach_rec(struct mail_cache_view *view,
		       const struct mail_cache_record *cache_rec,
		       mail_cache_foreach_callback_t *callback, void *context)
{
	struct mail_cache *cache = view->cache;
	size_t pos, next_pos, max_size, data_size;
	uint32_t file_field;
	unsigned int field;
	int ret;

	max_size = cache_rec->size;
	if (max_size < sizeof(*cache_rec) + sizeof(uint32_t)*2) {
		mail_cache_set_corrupted(cache, "record has invalid size");
		return -1;
	}
	max_size -= sizeof(uint32_t);

	for (pos = sizeof(*cache_rec); pos < max_size; ) {
		file_field =
			*((const uint32_t *)CONST_PTR_OFFSET(cache_rec, pos));
		pos += sizeof(uint32_t);

		if (file_field >= cache->file_fields_count) {
			/* new field, have to re-read fields header to figure
			   out it's size */
			if (mail_cache_header_fields_read(cache) < 0)
				return -1;
			if (file_field >= cache->file_fields_count) {
				mail_cache_set_corrupted(cache,
					"field index too large");
				return -1;
			}
		}

		field = cache->file_field_map[file_field];
		data_size = cache->fields[field].field.field_size;
		if (data_size == (unsigned int)-1) {
			data_size = *((const uint32_t *)
				      CONST_PTR_OFFSET(cache_rec, pos));
			pos += sizeof(uint32_t);
		}

		next_pos = pos + ((data_size + 3) & ~3);
		if (next_pos > cache_rec->size) {
			mail_cache_set_corrupted(cache,
				"Record continues outside it's allocated size");
			return -1;
		}

		ret = callback(view, file_field,
			       CONST_PTR_OFFSET(cache_rec, pos),
			       data_size, context);
		if (ret != 1)
			return ret;

		pos = next_pos;
	}
	return 1;
}

int mail_cache_foreach(struct mail_cache_view *view, uint32_t seq,
                       mail_cache_foreach_callback_t *callback, void *context)
{
	const struct mail_cache_record *cache_rec;
	uint32_t offset;
	int ret;

        if (MAIL_CACHE_IS_UNUSABLE(view->cache))
		return 0;

	if (view->cached_offset_seq == seq)
		offset = view->cached_offset;
	else {
		if ((ret = mail_cache_lookup_offset(view, seq, &offset)) <= 0)
			return ret;

		view->cached_offset_seq = seq;
		view->cached_offset = offset;
	}

	cache_rec = mail_cache_get_record(view->cache, offset);
	while (cache_rec != NULL) {
		ret = mail_cache_foreach_rec(view, cache_rec,
					     callback, context);
		if (ret <= 0)
			return ret;
		cache_rec = mail_cache_get_record(view->cache,
						  cache_rec->prev_offset);
	}

	if (view->trans_seq1 <= seq && view->trans_seq2 >= seq &&
	    mail_cache_transaction_lookup(view->transaction, seq, &offset)) {
		cache_rec = mail_cache_get_record(view->cache, offset);
		if (cache_rec != NULL) {
			return mail_cache_foreach_rec(view, cache_rec,
						      callback, context);
		}
	}
	return 1;
}

static int
mail_cache_seq_callback(struct mail_cache_view *view, uint32_t file_field,
			const void *data __attr_unused__,
			size_t data_size __attr_unused__,
			void *context __attr_unused__)
{
	buffer_write(view->cached_exists_buf, file_field,
		     &view->cached_exists_value, 1);
	return 1;
}

static int mail_cache_seq(struct mail_cache_view *view, uint32_t seq)
{
	int ret;

	if (++view->cached_exists_value == 0) {
		/* wrapped, we'll have to clear the buffer */
		memset(buffer_get_modifyable_data(view->cached_exists_buf,
						  NULL), 0,
		       buffer_get_size(view->cached_exists_buf));
		view->cached_exists_value++;
	}

	view->cached_exists_seq = seq;
	ret = mail_cache_foreach(view, seq, mail_cache_seq_callback, NULL);
	return ret < 0 ? -1 : 0;
}

int mail_cache_field_exists(struct mail_cache_view *view, uint32_t seq,
			    unsigned int field)
{
	const uint8_t *data;
	uint32_t file_field;
	size_t size;

	i_assert(field < view->cache->fields_count);

	file_field = view->cache->field_file_map[field];
	if (file_field == (uint32_t)-1)
		return 0;

	if (view->cached_exists_seq != seq) {
		if (mail_cache_seq(view, seq) < 0)
			return -1;
	}

	data = buffer_get_data(view->cached_exists_buf, &size);
	return size <= file_field ? FALSE :
		data[file_field] == view->cached_exists_value;
}

enum mail_cache_decision_type
mail_cache_field_get_decision(struct mail_cache *cache, unsigned int field)
{
	i_assert(field < cache->fields_count);

	return cache->fields[field].field.decision;
}

struct mail_cache_lookup_context {
	buffer_t *dest_buf;
	uint32_t file_field;
};

static int
mail_cache_lookup_callback(struct mail_cache_view *view __attr_unused__,
			   uint32_t file_field, const void *data,
			   size_t data_size, void *context)
{
        struct mail_cache_lookup_context *ctx = context;

	if (ctx->file_field != file_field)
		return 1;

	buffer_append(ctx->dest_buf, data, data_size);
	return 0;
}

int mail_cache_lookup_field(struct mail_cache_view *view, buffer_t *dest_buf,
			    uint32_t seq, unsigned int field)
{
	struct mail_cache_lookup_context ctx;
	int ret;

	if ((ret = mail_cache_field_exists(view, seq, field)) <= 0)
		return ret;

	mail_cache_decision_lookup(view, seq, field);

	/* should exist. find it. */
	ctx.file_field = view->cache->field_file_map[field];
	ctx.dest_buf = dest_buf;
	return mail_cache_foreach(view, seq, mail_cache_lookup_callback,
				  &ctx) == 0;
}

struct header_lookup_data_rec {
	uint32_t offset;
	uint32_t data_size;
};

struct header_lookup_data {
	uint32_t line_num;
        struct header_lookup_data_rec *data;
};

struct header_lookup_context {
	unsigned int *fields;
	size_t fields_count;
	buffer_t *data;

	unsigned int max_field;
	uint8_t *fields_found;
};

static int
headers_find_callback(struct mail_cache_view *view, uint32_t file_field,
		      const void *data, size_t data_size, void *context)
{
	struct header_lookup_context *ctx = context;
	const uint32_t *lines = data;
	struct header_lookup_data hdr_data;
        struct header_lookup_data_rec *hdr_data_rec;
	unsigned int i, lines_count;

	if (file_field > ctx->max_field || ctx->fields_found[file_field] != 1) {
		/* a) don't want it, b) duplicate */
		return 1;
	}
	ctx->fields_found[file_field]++;

	/* data = { line_nums[], 0, "headers" } */
	for (i = 0; data_size >= sizeof(uint32_t); i++) {
		data_size -= sizeof(uint32_t);
		if (lines[i] == 0)
			break;
	}
	lines_count = i;

	/* FIXME: this relies on mmap() too heavily */
	hdr_data_rec = t_new(struct header_lookup_data_rec, 1);
	hdr_data_rec->offset = (const char *)&lines[lines_count+1] -
		(const char *)view->cache->mmap_base;
	hdr_data_rec->data_size = (uint32_t)data_size;

	for (i = 0; i < lines_count; i++) {
		hdr_data.line_num = lines[i];
		hdr_data.data = hdr_data_rec;
		buffer_append(ctx->data, &hdr_data, sizeof(hdr_data));
	}
	return 1;
}

static int header_lookup_data_cmp(const void *p1, const void *p2)
{
	const struct header_lookup_data *d1 = p1, *d2 = p2;

	return (int)d1->line_num - (int)d2->line_num;
}

int mail_cache_lookup_headers(struct mail_cache_view *view, string_t *dest,
			      uint32_t seq, unsigned int fields[],
			      size_t fields_count)
{
	struct mail_cache *cache = view->cache;
	struct header_lookup_context ctx;
	struct header_lookup_data *data;
	const unsigned char *p, *start, *end;
	size_t i, size, hdr_size;
	unsigned int field_idx;
	uint8_t one = 1;
	buffer_t *buf;
	int ret;

	if (fields_count == 0)
		return 1;

	t_push();

	/* @UNSAFE */
	memset(&ctx, 0, sizeof(ctx));
	ctx.fields = t_new(unsigned int, fields_count);
	ctx.fields_count = fields_count;

	ctx.max_field = 0;
	buf = buffer_create_dynamic(pool_datastack_create(), 32, (size_t)-1);
	for (i = 0; i < fields_count; i++) {
		i_assert(fields[i] < cache->fields_count);
		field_idx = cache->field_file_map[fields[i]];
		if (field_idx == (unsigned int)-1) {
			/* not cached at all */
			t_pop();
			return 0;
		}

		if (field_idx > ctx.max_field)
			ctx.max_field = field_idx;

		buffer_write(buf, field_idx, &one, 1);
                ctx.fields[i] = field_idx;
	}
	ctx.fields_found = buffer_get_modifyable_data(buf, NULL);

	ctx.data = buffer_create_dynamic(pool_datastack_create(),
					 256, (size_t)-1);

	/* we need to return them in sorted order. create array:
	   { line number -> cache file offset } */
	ret = mail_cache_foreach(view, seq, headers_find_callback, &ctx);
	if (ret <= 0) {
		t_pop();
		return ret;
	}

	/* check that all fields were found */
	for (i = 0; i <= ctx.max_field; i++) {
		if (ctx.fields_found[i] == 1) {
			t_pop();
			return 0;
		}
	}

	data = buffer_get_modifyable_data(ctx.data, &size);
	size /= sizeof(*data);
	qsort(data, size, sizeof(*data), header_lookup_data_cmp);

	/* then start filling dest buffer from the headers */
	for (i = 0; i < size; i++) {
		start = CONST_PTR_OFFSET(cache->mmap_base,
					 data[i].data->offset);
		end = start + data[i].data->data_size;

		for (p = start; p != end; p++) {
			if (*p == '\n' &&
			    (p+1 == end || (p[1] != ' ' && p[1] != '\t'))) {
				p++;
				break;
			}
		}
		hdr_size = (size_t)(p - start);
		data[i].data->offset += hdr_size;
		data[i].data->data_size += hdr_size;
		buffer_append(dest, start, hdr_size);
	}

	t_pop();
	return 1;
}
