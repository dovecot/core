/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "byteorder.h"
#include "mail-cache-private.h"

const char *
mail_cache_get_header_fields_str(struct mail_cache *cache, unsigned int idx)
{
	uint32_t offset, data_size;
	unsigned char *buf;

	offset = mail_cache_offset_to_uint32(cache->hdr->header_offsets[idx]);

	if (offset == 0)
		return NULL;

	if (mail_cache_mmap_update(cache, offset, 1024) < 0)
		return NULL;

	if (offset + sizeof(data_size) > cache->mmap_length) {
		mail_cache_set_corrupted(cache, "Header %u points outside file",
					 idx);
		return NULL;
	}

	buf = cache->mmap_base;
	memcpy(&data_size, buf + offset, sizeof(data_size));
	data_size = nbo_to_uint32(data_size);
	offset += sizeof(data_size);

	if (data_size == 0) {
		mail_cache_set_corrupted(cache,
			"Header %u points to empty string", idx);
		return NULL;
	}

	if (mail_cache_mmap_update(cache, offset, data_size) < 0)
		return NULL;

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
mail_cache_get_record(struct mail_cache *cache, uint32_t offset,
		      int index_offset)
{
#define CACHE_PREFETCH 1024
	struct mail_cache_record *cache_rec;
	size_t size;

	if (!index_offset)
		offset = mail_cache_offset_to_uint32(offset);
	if (offset == 0)
		return NULL;

	if (mail_cache_mmap_update(cache, offset,
				   sizeof(*cache_rec) + CACHE_PREFETCH) < 0)
		return NULL;

	if (offset + sizeof(*cache_rec) > cache->mmap_length) {
		mail_cache_set_corrupted(cache, "record points outside file");
		return NULL;
	}
	cache_rec = CACHE_RECORD(cache, offset);

	size = nbo_to_uint32(cache_rec->size);
	if (size < sizeof(*cache_rec)) {
		mail_cache_set_corrupted(cache, "invalid record size");
		return NULL;
	}
	if (size > CACHE_PREFETCH) {
		if (mail_cache_mmap_update(cache, offset, size) < 0)
			return NULL;
	}

	if (offset + size > cache->mmap_length) {
		mail_cache_set_corrupted(cache, "record points outside file");
		return NULL;
	}
	return cache_rec;
}

struct mail_cache_record *
mail_cache_get_next_record(struct mail_cache *cache,
			   struct mail_cache_record *rec)
{
	struct mail_cache_record *next;

	next = mail_cache_get_record(cache, rec->next_offset, FALSE);
	if (next != NULL && next <= rec) {
		mail_cache_set_corrupted(cache, "next_offset points backwards");
		return NULL;
	}
	return next;
}

struct mail_cache_record *
mail_cache_lookup(struct mail_cache_view *view, uint32_t seq,
		  enum mail_cache_field fields)
{
	const struct mail_index_record *rec;

	if (mail_cache_transaction_autocommit(view, seq, fields) < 0)
		return NULL;
	/* FIXME: check cache_offset in transaction
	   FIXME: if rec doesn't point to header record, the file seq may
	   be different and the offset wrong */
	if (mail_index_lookup(view->view, seq, &rec) < 0)
		return NULL;

	return mail_cache_get_record(view->cache, rec->cache_offset, TRUE);
}

enum mail_cache_field
mail_cache_get_fields(struct mail_cache_view *view, uint32_t seq)
{
	struct mail_cache_record *cache_rec;
        enum mail_cache_field fields = 0;

	cache_rec = mail_cache_lookup(view, seq, 0);
	while (cache_rec != NULL) {
		fields |= cache_rec->fields;
		cache_rec = mail_cache_get_next_record(view->cache, cache_rec);
	}

	return fields;
}

static int cache_get_field(struct mail_cache *cache,
			   struct mail_cache_record *cache_rec,
			   enum mail_cache_field field,
			   void **data_r, size_t *size_r)
{
	unsigned char *buf;
	unsigned int mask;
	uint32_t rec_size, data_size;
	size_t offset, next_offset;
	int i;

	rec_size = nbo_to_uint32(cache_rec->size);
	buf = (unsigned char *) cache_rec;
	offset = sizeof(*cache_rec);

	for (i = 0, mask = 1; i < 31; i++, mask <<= 1) {
		if ((cache_rec->fields & mask) == 0)
			continue;

		/* all records are at least 32bit. we have to check this
		   before getting data_size. */
		if (offset + sizeof(uint32_t) > rec_size) {
			mail_cache_set_corrupted(cache,
				"Record continues outside it's allocated size");
			return FALSE;
		}

		if ((mask & MAIL_CACHE_FIXED_MASK) != 0)
			data_size = mail_cache_field_sizes[i];
		else {
			memcpy(&data_size, buf + offset, sizeof(data_size));
			data_size = nbo_to_uint32(data_size);
			offset += sizeof(data_size);
		}

		next_offset = offset + ((data_size + 3) & ~3);
		if (next_offset > rec_size) {
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
			*data_r = buf + offset;
			*size_r = data_size;
			return TRUE;
		}
		offset = next_offset;
	}

	i_unreached();
	return FALSE;
}

static int cache_lookup_field(struct mail_cache_view *view, uint32_t seq,
			      enum mail_cache_field field,
			      void **data_r, size_t *size_r)
{
	struct mail_cache_record *cache_rec;

	cache_rec = mail_cache_lookup(view, seq, field);
	while (cache_rec != NULL) {
		if ((cache_rec->fields & field) != 0) {
			return cache_get_field(view->cache, cache_rec, field,
					       data_r, size_r);
		}
		cache_rec = mail_cache_get_next_record(view->cache, cache_rec);
	}

	return FALSE;
}

int mail_cache_lookup_field(struct mail_cache_view *view, uint32_t seq,
			    enum mail_cache_field field,
			    const void **data_r, size_t *size_r)
{
	void *data;

	if (!cache_lookup_field(view, seq, field, &data, size_r))
		return FALSE;

	*data_r = data;
	return TRUE;
}

const char *
mail_cache_lookup_string_field(struct mail_cache_view *view, uint32_t seq,
			       enum mail_cache_field field)
{
	const void *data;
	size_t size;

	i_assert((field & MAIL_CACHE_STRING_MASK) != 0);

	if (!mail_cache_lookup_field(view, seq, field, &data, &size))
		return NULL;

	if (((const char *) data)[size-1] != '\0') {
		mail_cache_set_corrupted(view->cache,
			"String field %x doesn't end with NUL", field);
		return NULL;
	}
	return data;
}

int mail_cache_copy_fixed_field(struct mail_cache_view *view, uint32_t seq,
				enum mail_cache_field field,
				void *buffer, size_t buffer_size)
{
	const void *data;
	size_t size;

	i_assert((field & MAIL_CACHE_FIXED_MASK) != 0);

	if (!mail_cache_lookup_field(view, seq, field, &data, &size))
		return FALSE;

	if (buffer_size != size) {
		i_panic("cache: fixed field %x wrong size "
			"(%"PRIuSIZE_T" vs %"PRIuSIZE_T")",
			field, size, buffer_size);
	}

	memcpy(buffer, data, buffer_size);
	return TRUE;
}

enum mail_cache_record_flag
mail_cache_get_record_flags(struct mail_cache_view *view, uint32_t seq)
{
	// FIXME:
	return 0;
}
