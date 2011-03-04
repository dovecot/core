/* Copyright (c) 2004-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "buffer.h"
#include "hash.h"
#include "file-cache.h"
#include "read-full.h"
#include "write-full.h"
#include "mmap-util.h"
#include "mail-cache-private.h"

#include <stddef.h>

#define CACHE_FIELD_IS_NEWLY_WANTED(cache, field_idx) \
	((cache)->field_file_map[field_idx] == (uint32_t)-1 && \
	 (cache)->fields[field_idx].used)

static bool field_has_fixed_size(enum mail_cache_field_type type)
{
	switch (type) {
	case MAIL_CACHE_FIELD_FIXED_SIZE:
	case MAIL_CACHE_FIELD_BITMASK:
		return TRUE;
	case MAIL_CACHE_FIELD_VARIABLE_SIZE:
	case MAIL_CACHE_FIELD_STRING:
	case MAIL_CACHE_FIELD_HEADER:
		return FALSE;

	case MAIL_CACHE_FIELD_COUNT:
		break;
	}

	i_unreached();
	return FALSE;
}

static bool field_decision_is_valid(enum mail_cache_decision_type type)
{
	switch (type & ~MAIL_CACHE_DECISION_FORCED) {
	case MAIL_CACHE_DECISION_NO:
	case MAIL_CACHE_DECISION_TEMP:
	case MAIL_CACHE_DECISION_YES:
		return TRUE;
	default:
		return FALSE;
	}
}

static int field_type_verify(struct mail_cache *cache, unsigned int idx,
			     enum mail_cache_field_type type, unsigned int size)
{
	const struct mail_cache_field *field = &cache->fields[idx].field;

	if (field->type != type) {
		mail_cache_set_corrupted(cache,
			"registered field %s type changed", field->name);
		return -1;
	}
	if (field->field_size != size && field_has_fixed_size(type)) {
		mail_cache_set_corrupted(cache,
			"registered field %s size changed", field->name);
		return -1;
	}
	return 0;
}

void mail_cache_register_fields(struct mail_cache *cache,
				struct mail_cache_field *fields,
				unsigned int fields_count)
{
	struct mail_cache_field *orig_field;
	void *orig_key, *orig_value;
	char *name;
	unsigned int new_idx;
	unsigned int i, j;

	new_idx = cache->fields_count;
	for (i = 0; i < fields_count; i++) {
		if (hash_table_lookup_full(cache->field_name_hash,
					   fields[i].name,
					   &orig_key, &orig_value)) {
			i_assert(fields[i].type < MAIL_CACHE_FIELD_COUNT);

			fields[i].idx =
				POINTER_CAST_TO(orig_value, unsigned int);

			orig_field = &cache->fields[fields[i].idx].field;
			if (orig_field->decision == MAIL_CACHE_DECISION_NO)
				orig_field->decision = fields[i].decision;

			(void)field_type_verify(cache, fields[i].idx,
						fields[i].type,
						fields[i].field_size);
			continue;
		}

		/* check if the same header is being registered in the
		   same field array */
		for (j = 0; j < i; j++) {
			if (strcasecmp(fields[i].name, fields[j].name) == 0) {
				fields[i].idx = fields[j].idx;
				break;
			}
		}

		if (j == i)
			fields[i].idx = new_idx++;
	}

	if (new_idx == cache->fields_count)
		return;

	/* @UNSAFE */
	cache->fields = i_realloc(cache->fields,
				  cache->fields_count * sizeof(*cache->fields),
				  new_idx * sizeof(*cache->fields));
	cache->field_file_map =
		i_realloc(cache->field_file_map,
			  cache->fields_count * sizeof(*cache->field_file_map),
			  new_idx * sizeof(*cache->field_file_map));

	for (i = 0; i < fields_count; i++) {
		unsigned int idx = fields[i].idx;

		if (idx < cache->fields_count)
			continue;

		/* new index - save it */
		name = p_strdup(cache->field_pool, fields[i].name);
		cache->fields[idx].field = fields[i];
		cache->fields[idx].field.name = name;
		cache->field_file_map[idx] = (uint32_t)-1;

		if (!field_has_fixed_size(cache->fields[idx].field.type))
			cache->fields[idx].field.field_size = (unsigned int)-1;

		hash_table_insert(cache->field_name_hash,
				  name, POINTER_CAST(idx));
	}
	cache->fields_count = new_idx;
}

unsigned int
mail_cache_register_lookup(struct mail_cache *cache, const char *name)
{
	void *orig_key, *orig_value;

	if (hash_table_lookup_full(cache->field_name_hash, name,
				   &orig_key, &orig_value))
		return POINTER_CAST_TO(orig_value, unsigned int);
	else
		return (unsigned int)-1;
}

const struct mail_cache_field *
mail_cache_register_get_field(struct mail_cache *cache, unsigned int field_idx)
{
	i_assert(field_idx < cache->fields_count);

	return &cache->fields[field_idx].field;
}

const struct mail_cache_field *
mail_cache_register_get_list(struct mail_cache *cache, pool_t pool,
			     unsigned int *count_r)
{
        struct mail_cache_field *list;
	unsigned int i;

	if (!cache->opened)
		(void)mail_cache_open_and_verify(cache);

	list = cache->fields_count == 0 ? NULL :
		p_new(pool, struct mail_cache_field, cache->fields_count);
	for (i = 0; i < cache->fields_count; i++) {
		list[i] = cache->fields[i].field;
		list[i].name = p_strdup(pool, list[i].name);
	}

	*count_r = cache->fields_count;
	return list;
}

static int mail_cache_header_fields_get_offset(struct mail_cache *cache,
					       uint32_t *offset_r, bool map)
{
	const struct mail_cache_header_fields *field_hdr;
	struct mail_cache_header_fields tmp_field_hdr;
	uint32_t offset = 0, next_offset;
	unsigned int next_count = 0;
	bool invalidate = FALSE;
	int ret;

	if (MAIL_CACHE_IS_UNUSABLE(cache)) {
		*offset_r = 0;
		return 0;
	}

	/* find the latest header */
	offset = 0;
	next_offset = cache->last_field_header_offset != 0 ?
		cache->last_field_header_offset :
		mail_index_offset_to_uint32(cache->hdr->field_header_offset);
	while (next_offset != 0) {
		if (next_offset == offset) {
			mail_cache_set_corrupted(cache,
				"next_offset in field header loops");
			return -1;
		}
		offset = next_offset;
		invalidate = TRUE;

		if (cache->mmap_base != NULL) {
			if (mail_cache_map(cache, offset,
					   sizeof(*field_hdr)) < 0)
				return -1;
			if (offset >= cache->mmap_length) {
				mail_cache_set_corrupted(cache,
					"header field next_offset points outside file");
				return -1;
			}

			field_hdr = CONST_PTR_OFFSET(cache->data, offset);
		} else {
			/* if we need to follow multiple offsets to get to
			   the last one, it's faster to just pread() the file
			   instead of going through cache */
			ret = pread_full(cache->fd, &tmp_field_hdr,
					 sizeof(tmp_field_hdr), offset);
			if (ret < 0) {
				mail_cache_set_syscall_error(cache, "pread()");
				return -1;
			}
			if (ret == 0) {
				mail_cache_set_corrupted(cache,
					"header field next_offset points outside file");
				return -1;
			}
			field_hdr = &tmp_field_hdr;
		}

		next_offset =
			mail_index_offset_to_uint32(field_hdr->next_offset);
		next_count++;
	}

	if (offset == 0) {
		mail_cache_set_corrupted(cache, "missing header fields");
		return -1;
	}
	cache->last_field_header_offset = offset;

	if (next_count > MAIL_CACHE_HEADER_FIELD_CONTINUE_COUNT)
		cache->need_compress_file_seq = cache->hdr->file_seq;

	if (map) {
		if (cache->file_cache != NULL && invalidate) {
			/* if this isn't the first header in file and we hadn't
			   read this before, we can't trust that the cached
			   data is valid */
			file_cache_invalidate(cache->file_cache, offset,
					      field_hdr->size);
		}
		if (mail_cache_map(cache, offset, field_hdr->size) < 0)
			return -1;
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
	void *orig_key, *orig_value;
	unsigned int fidx, new_fields_count;
	enum mail_cache_decision_type dec;
	time_t max_drop_time;
	uint32_t offset, i;

	if (mail_cache_header_fields_get_offset(cache, &offset, TRUE) < 0)
		return -1;

	if (offset == 0) {
		/* no fields - the file is empty */
		return 0;
	}

	field_hdr = CONST_PTR_OFFSET(cache->data, offset);
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

	field_hdr = CONST_PTR_OFFSET(cache->data, offset);
	new_fields_count = field_hdr->fields_count;

	if (new_fields_count != 0) {
		cache->file_field_map =
			i_realloc(cache->file_field_map,
				  cache->file_fields_count *
				  sizeof(unsigned int),
				  new_fields_count * sizeof(unsigned int));
	} else {
		i_free_and_null(cache->file_field_map);
	}
	cache->file_fields_count = new_fields_count;

	last_used = CONST_PTR_OFFSET(field_hdr, MAIL_CACHE_FIELD_LAST_USED());
	sizes = CONST_PTR_OFFSET(field_hdr,
		MAIL_CACHE_FIELD_SIZE(field_hdr->fields_count));
	types = CONST_PTR_OFFSET(field_hdr,
		MAIL_CACHE_FIELD_TYPE(field_hdr->fields_count));
	decisions = CONST_PTR_OFFSET(field_hdr,
		MAIL_CACHE_FIELD_DECISION(field_hdr->fields_count));
	names = CONST_PTR_OFFSET(field_hdr,
		MAIL_CACHE_FIELD_NAMES(field_hdr->fields_count));
	end = CONST_PTR_OFFSET(field_hdr, field_hdr->size);

	/* clear the old mapping */
	for (i = 0; i < cache->fields_count; i++)
		cache->field_file_map[i] = (uint32_t)-1;

	max_drop_time = cache->index->map->hdr.day_stamp == 0 ? 0 :
		cache->index->map->hdr.day_stamp - MAIL_CACHE_FIELD_DROP_SECS;

	memset(&field, 0, sizeof(field));
	for (i = 0; i < field_hdr->fields_count; i++) {
		for (p = names; p != end && *p != '\0'; p++) ;
		if (p == end || *names == '\0') {
			mail_cache_set_corrupted(cache,
				"field header names corrupted");
			return -1;
		}

		if (types[i] > MAIL_CACHE_FIELD_COUNT) {
			mail_cache_set_corrupted(cache, "field type corrupted");
			return -1;
		}
		if (!field_decision_is_valid(decisions[i])) {
			mail_cache_set_corrupted(cache,
				"field decision type corrupted");
			return -1;
		}

		if (hash_table_lookup_full(cache->field_name_hash, names,
					   &orig_key, &orig_value)) {
			/* already exists, see if decision can be updated */
			fidx = POINTER_CAST_TO(orig_value, unsigned int);
			if (!cache->fields[fidx].decision_dirty) {
				cache->fields[fidx].field.decision =
					decisions[i];
			}
			if (field_type_verify(cache, fidx,
					      types[i], sizes[i]) < 0)
				return -1;
		} else {
			field.name = names;
			field.type = types[i];
			field.field_size = sizes[i];
			field.decision = decisions[i];
			mail_cache_register_fields(cache, &field, 1);
			fidx = field.idx;
		}
		if (cache->field_file_map[fidx] != (uint32_t)-1) {
			mail_cache_set_corrupted(cache,
				"Duplicated field in header: %s", names);
			return -1;
		}
		cache->fields[fidx].used = TRUE;

		cache->field_file_map[fidx] = i;
		cache->file_field_map[i] = fidx;

		/* update last_used if it's newer than ours */
		if (last_used[i] > cache->fields[fidx].last_used)
			cache->fields[fidx].last_used = last_used[i];

		dec = cache->fields[fidx].field.decision;
		if ((time_t)cache->fields[fidx].last_used < max_drop_time &&
		    cache->fields[fidx].last_used != 0 &&
		    (dec & MAIL_CACHE_DECISION_FORCED) == 0 &&
		    dec != MAIL_CACHE_DECISION_NO) {
			/* time to drop this field. don't bother dropping
			   fields that have never been used. */
			cache->need_compress_file_seq = cache->hdr->file_seq;
		}

                names = p + 1;
	}
	return 0;
}

static void copy_to_buf(struct mail_cache *cache, buffer_t *dest, bool add_new,
			size_t offset, size_t size)
{
	const void *data;
	unsigned int i, field;

	/* copy the existing fields */
	for (i = 0; i < cache->file_fields_count; i++) {
		field = cache->file_field_map[i];
                data = CONST_PTR_OFFSET(&cache->fields[field], offset);
		buffer_append(dest, data, size);
	}
	if (!add_new)
		return;

	/* copy newly wanted fields */
	for (i = 0; i < cache->fields_count; i++) {
		if (CACHE_FIELD_IS_NEWLY_WANTED(cache, i)) {
			data = CONST_PTR_OFFSET(&cache->fields[i], offset);
			buffer_append(dest, data, size);
		}
	}
}

static void copy_to_buf_byte(struct mail_cache *cache, buffer_t *dest,
			     bool add_new, size_t offset)
{
	const int *data;
	unsigned int i, field;
	uint8_t byte;

	/* copy the existing fields */
	for (i = 0; i < cache->file_fields_count; i++) {
		field = cache->file_field_map[i];
                data = CONST_PTR_OFFSET(&cache->fields[field], offset);
		byte = (uint8_t)*data;
		buffer_append(dest, &byte, 1);
	}
	if (!add_new)
		return;

	/* copy newly wanted fields */
	for (i = 0; i < cache->fields_count; i++) {
		if (CACHE_FIELD_IS_NEWLY_WANTED(cache, i)) {
			data = CONST_PTR_OFFSET(&cache->fields[i], offset);
			byte = (uint8_t)*data;
			buffer_append(dest, &byte, 1);
		}
	}
}

static int mail_cache_header_fields_update_locked(struct mail_cache *cache)
{
	buffer_t *buffer;
	uint32_t i, offset, dec_offset;
	int ret = 0;

	if (mail_cache_header_fields_read(cache) < 0 ||
	    mail_cache_header_fields_get_offset(cache, &offset, FALSE) < 0)
		return -1;

	buffer = buffer_create_dynamic(pool_datastack_create(), 256);

	copy_to_buf(cache, buffer, FALSE,
		    offsetof(struct mail_cache_field_private, last_used),
		    sizeof(uint32_t));
	ret = mail_cache_write(cache, buffer->data, buffer->used,
			       offset + MAIL_CACHE_FIELD_LAST_USED());
	if (ret == 0) {
		buffer_set_used_size(buffer, 0);
		copy_to_buf_byte(cache, buffer, FALSE,
				 offsetof(struct mail_cache_field, decision));

		dec_offset = offset +
			MAIL_CACHE_FIELD_DECISION(cache->file_fields_count);
		ret = mail_cache_write(cache, buffer->data, buffer->used,
				       dec_offset);
		if (ret == 0) {
			for (i = 0; i < cache->file_fields_count; i++)
				cache->fields[i].decision_dirty = FALSE;
		}
	}

	if (ret == 0)
		cache->field_header_write_pending = FALSE;
	return ret;
}

int mail_cache_header_fields_update(struct mail_cache *cache)
{
	int ret;

	if (cache->locked) {
		T_BEGIN {
			ret = mail_cache_header_fields_update_locked(cache);
		} T_END;
		return ret;
	}

	if (mail_cache_lock(cache, FALSE) <= 0)
		return -1;

	T_BEGIN {
		ret = mail_cache_header_fields_update_locked(cache);
	} T_END;
	if (mail_cache_unlock(cache) < 0)
		ret = -1;
	return ret;
}

void mail_cache_header_fields_get(struct mail_cache *cache, buffer_t *dest)
{
	struct mail_cache_header_fields hdr;
	unsigned int field;
	const char *name;
	uint32_t i;

	memset(&hdr, 0, sizeof(hdr));
	hdr.fields_count = cache->file_fields_count;
	for (i = 0; i < cache->fields_count; i++) {
		if (CACHE_FIELD_IS_NEWLY_WANTED(cache, i))
			hdr.fields_count++;
	}
	buffer_append(dest, &hdr, sizeof(hdr));

	/* we have to keep the field order for the existing fields. */
	copy_to_buf(cache, dest, TRUE,
		    offsetof(struct mail_cache_field_private, last_used),
		    sizeof(uint32_t));
	copy_to_buf(cache, dest, TRUE,
		    offsetof(struct mail_cache_field, field_size),
		    sizeof(uint32_t));
	copy_to_buf_byte(cache, dest, TRUE,
			 offsetof(struct mail_cache_field, type));
	copy_to_buf_byte(cache, dest, TRUE,
			 offsetof(struct mail_cache_field, decision));

	i_assert(dest->used == sizeof(hdr) +
		 (sizeof(uint32_t)*2 + 2) * hdr.fields_count);

	/* add existing fields' names */
	for (i = 0; i < cache->file_fields_count; i++) {
		field = cache->file_field_map[i];
		name = cache->fields[field].field.name;
		buffer_append(dest, name, strlen(name)+1);
	}
	/* add newly wanted fields' names */
	for (i = 0; i < cache->fields_count; i++) {
		if (CACHE_FIELD_IS_NEWLY_WANTED(cache, i)) {
			name = cache->fields[i].field.name;
			buffer_append(dest, name, strlen(name)+1);
		}
	}

	hdr.size = dest->used;
	buffer_write(dest, 0, &hdr, sizeof(hdr));

	if ((hdr.size & 3) != 0)
		buffer_append_zero(dest, 4 - (hdr.size & 3));
}

int mail_cache_header_fields_get_next_offset(struct mail_cache *cache,
					     uint32_t *offset_r)
{
	if (mail_cache_header_fields_get_offset(cache, offset_r, FALSE) < 0)
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
