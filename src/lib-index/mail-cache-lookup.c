/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "mail-cache-private.h"

#define CACHE_PREFETCH 1024

const char *
mail_cache_get_header_fields_str(struct mail_cache *cache, unsigned int idx)
{
	uint32_t offset, data_size;
	const unsigned char *buf;

	if (MAIL_CACHE_IS_UNUSABLE(cache))
		return NULL;

	offset = mail_cache_offset_to_uint32(cache->hdr->header_offsets[idx]);

	if (offset == 0)
		return NULL;

	if (mail_cache_map(cache, offset, CACHE_PREFETCH) < 0)
		return NULL;

	if (offset + sizeof(data_size) > cache->mmap_length) {
		mail_cache_set_corrupted(cache, "Header %u points outside file",
					 idx);
		return NULL;
	}

	buf = cache->mmap_base;
	memcpy(&data_size, buf + offset, sizeof(data_size));
	offset += sizeof(data_size);

	if (data_size == 0) {
		mail_cache_set_corrupted(cache,
			"Header %u points to empty string", idx);
		return NULL;
	}

	if (data_size + sizeof(data_size) > CACHE_PREFETCH) {
		if (mail_cache_map(cache, offset, data_size) < 0)
			return NULL;
	}

	if (offset + data_size > cache->mmap_length) {
		mail_cache_set_corrupted(cache, "Header %u points outside file",
					 idx);
		return NULL;
	}

	buf = cache->mmap_base;
	if (buf[offset + data_size - 1] != '\0') {
		mail_cache_set_corrupted(cache,
			"Header %u points to invalid string", idx);
		return NULL;
	}

	return buf + offset;
}

const char *const *
mail_cache_split_header(struct mail_cache *cache, const char *header)
{
	const char *const *arr, *const *tmp;
	const char *null = NULL;
	char *str;
	buffer_t *buf;

	if (header == NULL)
		return NULL;

	arr = t_strsplit(header, "\n");
	buf = buffer_create_dynamic(cache->split_header_pool, 32, (size_t)-1);
	for (tmp = arr; *tmp != NULL; tmp++) {
		str = p_strdup(cache->split_header_pool, *tmp);
		buffer_append(buf, &str, sizeof(str));
	}
	buffer_append(buf, &null, sizeof(null));

	return buffer_get_data(buf, NULL);
}

const char *const *mail_cache_get_header_fields(struct mail_cache_view *view,
						unsigned int idx)
{
	struct mail_cache *cache = view->cache;
	const char *str;
	int i;

	i_assert(idx < MAIL_CACHE_HEADERS_COUNT);

	if (MAIL_CACHE_IS_UNUSABLE(view->cache))
		return NULL;

	/* t_strsplit() is a bit slow, so we cache it */
	if (cache->hdr->header_offsets[idx] != cache->split_offsets[idx]) {
		p_clear(cache->split_header_pool);

		t_push();
		for (i = 0; i < MAIL_CACHE_HEADERS_COUNT; i++) {
			cache->split_offsets[i] =
				cache->hdr->header_offsets[i];

			str = mail_cache_get_header_fields_str(cache, i);
			cache->split_headers[i] =
				mail_cache_split_header(cache, str);
		}
		t_pop();
	}

	return cache->split_headers[idx];
}

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
	size_t pos, next_pos, max_size, data_size;
	uint32_t field;
	int ret;

	max_size = cache_rec->size;
	if (max_size < sizeof(*cache_rec) + sizeof(uint32_t)*2) {
		mail_cache_set_corrupted(view->cache,
					 "record has invalid size");
		return -1;
	}
	max_size -= sizeof(uint32_t);

	for (pos = sizeof(*cache_rec); pos < max_size; ) {
		field = *((const uint32_t *)CONST_PTR_OFFSET(cache_rec, pos));
		pos += sizeof(uint32_t);

		data_size = mail_cache_field_sizes[field];
		if (data_size == (unsigned int)-1) {
			data_size = *((const uint32_t *)
				      CONST_PTR_OFFSET(cache_rec, pos));
			pos += sizeof(uint32_t);
		}

		next_pos = pos + ((data_size + 3) & ~3);
		if (next_pos > cache_rec->size) {
			mail_cache_set_corrupted(view->cache,
				"Record continues outside it's allocated size");
			return -1;
		}

		ret = callback(view, field, CONST_PTR_OFFSET(cache_rec, pos),
			       data_size, context);
		if (ret <= 0)
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

	if ((ret = mail_cache_lookup_offset(view, seq, &offset)) <= 0)
		return ret;

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

static int mail_cache_seq_callback(struct mail_cache_view *view,
				   enum mail_cache_field field,
				   const void *data __attr_unused__,
				   size_t data_size __attr_unused__,
				   void *context __attr_unused__)
{
	view->cached_exists[field] = TRUE;
	return 1;
}

static int mail_cache_seq(struct mail_cache_view *view, uint32_t seq)
{
	int ret;

	view->cached_exists_seq = seq;
	memset(view->cached_exists, 0, sizeof(view->cached_exists));

	ret = mail_cache_foreach(view, seq, mail_cache_seq_callback, NULL);
	return ret < 0 ? -1 : 0;
}

int mail_cache_field_exists(struct mail_cache_view *view, uint32_t seq,
			    enum mail_cache_field field)
{
	i_assert(field < MAIL_CACHE_FIELD_COUNT);

        if (MAIL_CACHE_IS_UNUSABLE(view->cache))
		return 0;

	if (view->cached_exists_seq != seq) {
		if (mail_cache_seq(view, seq) < 0)
			return -1;
	}
	return view->cached_exists[field];
}

enum mail_cache_decision_type
mail_cache_field_get_decision(struct mail_cache *cache,
			      enum mail_cache_field field)
{
	i_assert(field < MAIL_CACHE_FIELD_COUNT);

        if (MAIL_CACHE_IS_UNUSABLE(cache))
		return cache->default_field_usage_decision_type[field];

	return cache->hdr->field_usage_decision_type[field];
}

struct mail_cache_lookup_context {
	buffer_t *dest_buf;
	enum mail_cache_field field;
};

static int
mail_cache_lookup_callback(struct mail_cache_view *view __attr_unused__,
			   enum mail_cache_field field,
			   const void *data, size_t data_size, void *context)
{
        struct mail_cache_lookup_context *ctx = context;

	if (ctx->field != field)
		return 1;

	buffer_append(ctx->dest_buf, data, data_size);
	return 0;
}

int mail_cache_lookup_field(struct mail_cache_view *view, buffer_t *dest_buf,
			    uint32_t seq, enum mail_cache_field field)
{
        struct mail_cache_lookup_context ctx;

	i_assert(field < MAIL_CACHE_FIELD_COUNT);

        if (MAIL_CACHE_IS_UNUSABLE(view->cache))
		return 0;

	mail_cache_decision_lookup(view, seq, field);

	if (view->cached_exists_seq != seq) {
		if (mail_cache_seq(view, seq) < 0)
			return -1;
	}

	if (!view->cached_exists[field])
		return 0;

	/* should exist. find it. */
	ctx.field = field;
	ctx.dest_buf = dest_buf;
	return mail_cache_foreach(view, seq, mail_cache_lookup_callback,
				  &ctx) == 0;
}

int mail_cache_lookup_string_field(struct mail_cache_view *view, string_t *dest,
				   uint32_t seq, enum mail_cache_field field)
{
	size_t old_size, new_size;

	i_assert(field < MAIL_CACHE_FIELD_COUNT);

        if (MAIL_CACHE_IS_UNUSABLE(view->cache))
		return 0;

	old_size = str_len(dest);
	if (!mail_cache_lookup_field(view, dest, seq, field))
		return 0;

	new_size = str_len(dest);
	if (old_size == new_size ||
	    str_data(dest)[new_size-1] != '\0') {
		mail_cache_set_corrupted(view->cache,
			"String field %x doesn't end with NUL", field);
		return -1;
	}
	str_truncate(dest, new_size-1);
	return 1;
}

enum mail_cache_record_flag
mail_cache_get_record_flags(struct mail_cache_view *view, uint32_t seq)
{
	// FIXME:
	return 0;
}
