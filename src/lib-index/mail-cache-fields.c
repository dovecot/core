/* Copyright (C) 2004 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "hash.h"
#include "mail-cache-private.h"

#include <stddef.h>

#define CACHE_HDR_PREFETCH 1024

static const unsigned char *null4[] = { 0, 0, 0, 0 };

void mail_cache_register_fields(struct mail_cache *cache,
				struct mail_cache_field *fields,
				size_t fields_count)
{
	void *orig_key, *orig_value;
	unsigned int new_idx;
	size_t i;

	new_idx = cache->fields_count;
	for (i = 0; i < fields_count; i++) {
		if (hash_lookup_full(cache->field_name_hash, fields[i].name,
				     &orig_key, &orig_value)) {
			fields[i].idx =
				POINTER_CAST_TO(orig_value, unsigned int);
			continue;
		}

		fields[i].idx = new_idx++;
	}

	if (new_idx == cache->fields_count)
		return;

	/* @UNSAFE */
	cache->fields = p_realloc(cache->field_pool, cache->fields,
				  cache->fields_count * sizeof(*cache->fields),
				  new_idx * sizeof(*cache->fields));
	cache->field_file_map =
		p_realloc(cache->field_pool, cache->field_file_map,
			  cache->fields_count * sizeof(*cache->field_file_map),
			  new_idx * sizeof(*cache->field_file_map));

	for (i = 0; i < fields_count; i++) {
		unsigned int idx = fields[i].idx;

		if (idx < cache->fields_count)
			continue;

		/* new index - save it */
		cache->fields[idx] = fields[i];
		cache->fields[idx].name =
			p_strdup(cache->field_pool, fields[i].name);
		cache->field_file_map[idx] = (uint32_t)-1;

		switch (cache->fields[idx].type) {
		case MAIL_CACHE_FIELD_FIXED_SIZE:
		case MAIL_CACHE_FIELD_BITMASK:
			break;
		case MAIL_CACHE_FIELD_VARIABLE_SIZE:
		case MAIL_CACHE_FIELD_STRING:
		case MAIL_CACHE_FIELD_HEADER:
			cache->fields[idx].field_size = (unsigned int)-1;
			break;
		}

		hash_insert(cache->field_name_hash,
			    (char *)cache->fields[idx].name,
			    POINTER_CAST(idx));
	}
	cache->fields_count = new_idx;
}

unsigned int
mail_cache_register_lookup(struct mail_cache *cache, const char *name)
{
	void *orig_key, *orig_value;

	if (hash_lookup_full(cache->field_name_hash, name,
			     &orig_key, &orig_value))
		return POINTER_CAST_TO(orig_value, unsigned int);
	else
		return (unsigned int)-1;
}

static int mail_cache_header_fields_get_offset(struct mail_cache *cache,
					       uint32_t *offset_r)
{
	const struct mail_cache_header_fields *field_hdr;
	uint32_t offset, next_offset;

	if (MAIL_CACHE_IS_UNUSABLE(cache)) {
		*offset_r = 0;
		return 0;
	}

	/* find the latest header */
	offset = 0;
	next_offset =
		mail_cache_offset_to_uint32(cache->hdr->field_header_offset);
	while (next_offset != 0) {
		offset = next_offset;

		if (mail_cache_map(cache, offset,
				   sizeof(*field_hdr) + CACHE_HDR_PREFETCH) < 0)
			return -1;

		field_hdr = CONST_PTR_OFFSET(cache->mmap_base, offset);
		next_offset =
			mail_cache_offset_to_uint32(field_hdr->next_offset);
	}

	*offset_r = offset;
	return 0;
}

int mail_cache_header_fields_read(struct mail_cache *cache)
{
	const struct mail_cache_header_fields *field_hdr = NULL;
	struct mail_cache_field field;
	const uint32_t *last_used, *sizes;
	const uint8_t *types, *decisions;
	const char *p, *names, *end;
	uint32_t offset, i;

	if (mail_cache_header_fields_get_offset(cache, &offset) < 0)
		return -1;

	if (offset == 0) {
		/* no fields - the file is empty */
		return 0;
	}

	field_hdr = CONST_PTR_OFFSET(cache->mmap_base, offset);
	if (offset + field_hdr->size > cache->mmap_length) {
		mail_cache_set_corrupted(cache,
					 "field header points outside file");
		return -1;
	}

	/* check the fixed size of the header. name[] has to be checked
	   separately */
	if (field_hdr->size < sizeof(*field_hdr) +
	    field_hdr->fields_count * (sizeof(uint32_t)*2 + 1 + 2)) {
		mail_cache_set_corrupted(cache, "invalid field header size");
		return -1;
	}

	if (field_hdr->size > sizeof(*field_hdr) + CACHE_HDR_PREFETCH) {
		if (mail_cache_map(cache, offset, field_hdr->size) < 0)
			return -1;
	}
	field_hdr = CONST_PTR_OFFSET(cache->mmap_base, offset);

	cache->file_field_map =
		i_realloc(cache->file_field_map,
			  cache->file_fields_count * sizeof(unsigned int),
			  field_hdr->fields_count * sizeof(unsigned int));
	cache->file_fields_count = field_hdr->fields_count;

        last_used = MAIL_CACHE_FIELD_LAST_USED(field_hdr);
	sizes = MAIL_CACHE_FIELD_SIZE(field_hdr);
	types = MAIL_CACHE_FIELD_TYPE(field_hdr);
	decisions = MAIL_CACHE_FIELD_DECISION(field_hdr);
	names = MAIL_CACHE_FIELD_NAMES(field_hdr);
	end = CONST_PTR_OFFSET(field_hdr, field_hdr->size);

	/* clear the old mapping */
	for (i = 0; i < cache->fields_count; i++)
		cache->field_file_map[i] = (uint32_t)-1;

	memset(&field, 0, sizeof(field));
	for (i = 0; i < field_hdr->fields_count; i++) {
		for (p = names; p != end && *p != '\0'; p++) ;
		if (p == end) {
			mail_cache_set_corrupted(cache,
				"field header names corrupted");
			return -1;
		}

		field.name = names;
		field.type = types[i];
		field.field_size = sizes[i];
		field.decision = decisions[i];
		field.last_used = (time_t)last_used[i];
		mail_cache_register_fields(cache, &field, 1);
		cache->field_file_map[field.idx] = i;
		cache->file_field_map[i] = field.idx;

		names = p + 1;
	}
	return 0;
}

int mail_cache_header_fields_update(struct mail_cache *cache)
{
	int locked = cache->locked;

	if (!locked) {
		if (mail_cache_lock(cache) <= 0)
			return -1;
	}

	// FIXME

	if (!locked)
		mail_cache_unlock(cache);
}

#define UGLY_COPY_MACRO(field_name, type) \
	for (i = 0; i < cache->file_fields_count; i++) {                \
		field = cache->file_field_map[i];                       \
		field_name = (type)cache->fields[field].field_name;     \
		buffer_append(dest, &field_name, sizeof(field_name));   \
	}                                                               \
	for (i = 0; i < cache->fields_count; i++) {                     \
		if (cache->field_file_map[i] != (uint32_t)-1)           \
			continue;                                       \
		field_name = (type)cache->fields[i].field_name;         \
		buffer_append(dest, &field_name, sizeof(field_name));   \
	}

void mail_cache_header_fields_get(struct mail_cache *cache, buffer_t *dest)
{
	struct mail_cache_header_fields hdr;
	unsigned int field;
	const char *name;
	uint32_t i, last_used, field_size;
	uint8_t type, decision;

	memset(&hdr, 0, sizeof(hdr));
	hdr.fields_count = cache->fields_count;
	buffer_append(dest, &hdr, sizeof(hdr));

	/* we have to keep the field order for the existing fields. */
        UGLY_COPY_MACRO(last_used, uint32_t);
        UGLY_COPY_MACRO(field_size, uint32_t);
        UGLY_COPY_MACRO(type, uint8_t);
        UGLY_COPY_MACRO(decision, uint8_t);

	for (i = 0; i < cache->file_fields_count; i++) {
		field = cache->file_field_map[i];
		name = cache->fields[field].name;
		buffer_append(dest, name, strlen(name)+1);
	}
	for (i = 0; i < cache->fields_count; i++) {
		if (cache->field_file_map[i] != (uint32_t)-1)
			continue;
		name = cache->fields[i].name;
		buffer_append(dest, name, strlen(name)+1);
	}

	hdr.size = buffer_get_used_size(dest);
	buffer_write(dest, 0, &hdr, sizeof(hdr));

	if ((hdr.size & 3) != 0)
		buffer_append(dest, null4, 4 - (hdr.size & 3));
}

int mail_cache_header_fields_get_next_offset(struct mail_cache *cache,
					     uint32_t *offset_r)
{
	if (mail_cache_header_fields_get_offset(cache, offset_r) < 0)
		return -1;

	if (*offset_r == 0) {
		*offset_r = offsetof(struct mail_cache_header,
				     field_header_offset);
	} else {
		*offset_r += offsetof(struct mail_cache_header_fields,
				      next_offset);
	}
	return 0;
}
