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

struct mail_cache_record *
mail_cache_lookup(struct mail_cache_view *view, uint32_t seq)
{
	uint32_t offset;

	// FIXME: check transactions too

        if (MAIL_CACHE_IS_UNUSABLE(view->cache))
		return NULL;

	if (mail_cache_lookup_offset(view, seq, &offset) <= 0)
		return NULL;

	return mail_cache_get_record(view->cache, offset);
}

enum mail_cache_field
mail_cache_get_fields(struct mail_cache_view *view, uint32_t seq)
{
	struct mail_cache_record *cache_rec;
        enum mail_cache_field fields = 0;

	cache_rec = mail_cache_lookup(view, seq);
	while (cache_rec != NULL) {
		fields |= cache_rec->fields;
		cache_rec = mail_cache_get_record(view->cache,
						  cache_rec->prev_offset);
	}

	return fields;
}

static int cache_get_field(struct mail_cache *cache,
			   const struct mail_cache_record *cache_rec,
			   enum mail_cache_field field, buffer_t *dest_buf)
{
	unsigned int mask;
	uint32_t data_size;
	size_t offset, prev_offset;
	int i;

	offset = sizeof(*cache_rec);

	for (i = 0, mask = 1; i < 31; i++, mask <<= 1) {
		if ((cache_rec->fields & mask) == 0)
			continue;

		/* all records are at least 32bit. we have to check this
		   before getting data_size. */
		if (offset + sizeof(uint32_t) > cache_rec->size) {
			mail_cache_set_corrupted(cache,
				"Record continues outside it's allocated size");
			return FALSE;
		}

		if ((mask & MAIL_CACHE_FIXED_MASK) != 0)
			data_size = mail_cache_field_sizes[i];
		else {
			memcpy(&data_size, CONST_PTR_OFFSET(cache_rec, offset),
			       sizeof(data_size));
			offset += sizeof(data_size);
		}

		prev_offset = offset + ((data_size + 3) & ~3);
		if (prev_offset > cache_rec->size) {
			mail_cache_set_corrupted(cache,
				"Record continues outside it's allocated size");
			return FALSE;
		}

		if (field == mask) {
			if (data_size == 0) {
				mail_cache_set_corrupted(cache,
							 "Field size is 0");
				return FALSE;
			}
			buffer_append(dest_buf,
				      CONST_PTR_OFFSET(cache_rec, offset),
				      data_size);
			return TRUE;
		}
		offset = prev_offset;
	}

	i_unreached();
	return FALSE;
}

int mail_cache_lookup_field(struct mail_cache_view *view, buffer_t *dest_buf,
			    uint32_t seq, enum mail_cache_field field)
{
	struct mail_cache_record *cache_rec;

	mail_cache_handle_decisions(view, seq, field);

	cache_rec = mail_cache_lookup(view, seq);
	while (cache_rec != NULL) {
		if ((cache_rec->fields & field) != 0) {
			return cache_get_field(view->cache, cache_rec, field,
					       dest_buf);
		}
		cache_rec = mail_cache_get_record(view->cache,
						  cache_rec->prev_offset);
	}

	return FALSE;
}

int mail_cache_lookup_string_field(struct mail_cache_view *view, string_t *dest,
				   uint32_t seq, enum mail_cache_field field)
{
	size_t old_size, new_size;

	i_assert((field & MAIL_CACHE_STRING_MASK) != 0);

	old_size = str_len(dest);
	if (!mail_cache_lookup_field(view, dest, seq, field))
		return FALSE;

	new_size = str_len(dest);
	if (old_size == new_size ||
	    str_data(dest)[new_size-1] != '\0') {
		mail_cache_set_corrupted(view->cache,
			"String field %x doesn't end with NUL", field);
		return FALSE;
	}
	str_truncate(dest, new_size-1);
	return TRUE;
}

enum mail_cache_record_flag
mail_cache_get_record_flags(struct mail_cache_view *view, uint32_t seq)
{
	// FIXME:
	return 0;
}
