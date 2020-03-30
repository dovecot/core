/* Copyright (c) 2004-2018 Dovecot authors, see the included COPYING file */

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

static void
mail_cache_field_update(struct mail_cache *cache,
			const struct mail_cache_field *newfield)
{
	struct mail_cache_field_private *orig;
	bool initial_registering;

	i_assert(newfield->type < MAIL_CACHE_FIELD_COUNT);

	/* are we still doing the initial cache field registering for
	   internal fields and for mail_*cache_fields settings? */
	initial_registering = cache->file_fields_count == 0;

	orig = &cache->fields[newfield->idx];
	if ((newfield->decision & MAIL_CACHE_DECISION_FORCED) != 0 ||
	    ((orig->field.decision & MAIL_CACHE_DECISION_FORCED) == 0 &&
	     newfield->decision > orig->field.decision)) {
		orig->field.decision = newfield->decision;
		if (!initial_registering)
			orig->decision_dirty = TRUE;
	}
	if (orig->field.last_used < newfield->last_used) {
		orig->field.last_used = newfield->last_used;
		if (!initial_registering)
			orig->decision_dirty = TRUE;
	}
	if (orig->decision_dirty)
		cache->field_header_write_pending = TRUE;

	(void)field_type_verify(cache, newfield->idx,
				newfield->type, newfield->field_size);
}

void mail_cache_register_fields(struct mail_cache *cache,
				struct mail_cache_field *fields,
				unsigned int fields_count)
{
	char *name;
	void *value;
	unsigned int new_idx;
	unsigned int i, j, registered_count;

	new_idx = cache->fields_count;
	for (i = 0; i < fields_count; i++) {
		if (hash_table_lookup_full(cache->field_name_hash,
					   fields[i].name, &name, &value)) {
			fields[i].idx = POINTER_CAST_TO(value, unsigned int);
			mail_cache_field_update(cache, &fields[i]);
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
	cache->fields = i_realloc_type(cache->fields,
				       struct mail_cache_field_private,
				       cache->fields_count, new_idx);
	cache->field_file_map =
		i_realloc_type(cache->field_file_map, uint32_t,
			       cache->fields_count, new_idx);

	registered_count = cache->fields_count;
	for (i = 0; i < fields_count; i++) {
		unsigned int idx = fields[i].idx;

		if (idx < registered_count)
			continue;

		/* new index - save it */
		name = p_strdup(cache->field_pool, fields[i].name);
		cache->fields[idx].field = fields[i];
		cache->fields[idx].field.name = name;
		cache->fields[idx].field.last_used = fields[i].last_used;
		cache->field_file_map[idx] = (uint32_t)-1;

		if (!field_has_fixed_size(cache->fields[idx].field.type))
			cache->fields[idx].field.field_size = UINT_MAX;

		hash_table_insert(cache->field_name_hash, name,
				  POINTER_CAST(idx));
		registered_count++;
	}
	i_assert(registered_count == new_idx);
	cache->fields_count = new_idx;
}

unsigned int
mail_cache_register_lookup(struct mail_cache *cache, const char *name)
{
	char *key;
	void *value;

	if (hash_table_lookup_full(cache->field_name_hash, name, &key, &value))
		return POINTER_CAST_TO(value, unsigned int);
	else
		return UINT_MAX;
}

const struct mail_cache_field *
mail_cache_register_get_field(struct mail_cache *cache, unsigned int field_idx)
{
	i_assert(field_idx < cache->fields_count);

	return &cache->fields[field_idx].field;
}

struct mail_cache_field *
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

static int
mail_cache_header_fields_get_offset(struct mail_cache *cache,
				    uint32_t *offset_r,
				    const struct mail_cache_header_fields **field_hdr_r)
{
	const struct mail_cache_header_fields *field_hdr;
	struct mail_cache_header_fields tmp_field_hdr;
	const void *data;
	uint32_t offset = 0, next_offset, field_hdr_size;
	unsigned int next_count = 0;
	int ret;

	if (MAIL_CACHE_IS_UNUSABLE(cache)) {
		*offset_r = 0;
		if (field_hdr_r != NULL)
			*field_hdr_r = NULL;
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
		/* In Dovecot v2.2+ we don't try to use any holes,
		   so next_offset must always be larger than current offset.
		   also makes it easier to guarantee there aren't any loops
		   (which we don't bother doing for old files) */
		if (next_offset < offset && cache->hdr->minor_version != 0) {
			mail_cache_set_corrupted(cache,
				"next_offset in field header decreases");
			return -1;
		}
		offset = next_offset;

		if (cache->mmap_base != NULL || cache->map_with_read) {
			ret = mail_cache_map(cache, offset, sizeof(*field_hdr),
					     &data);
			if (ret <= 0) {
				if (ret < 0)
					return -1;
				mail_cache_set_corrupted(cache,
					"header field next_offset points outside file");
				return -1;
			}
			field_hdr = data;
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

	if (next_count > cache->index->optimization_set.cache.compress_header_continue_count)
		cache->need_compress_file_seq = cache->hdr->file_seq;

	if (field_hdr_r != NULL) {
		/* detect corrupted size later */
		field_hdr_size = I_MAX(field_hdr->size, sizeof(*field_hdr));
		if (cache->file_cache != NULL) {
			/* invalidate the cache fields area to make sure we
			   get the latest cache decisions/last_used fields */
			file_cache_invalidate(cache->file_cache, offset,
					      field_hdr_size);
		}
		if (cache->read_buf != NULL)
			buffer_set_used_size(cache->read_buf, 0);
		ret = mail_cache_map(cache, offset, field_hdr_size, &data);
		if (ret < 0)
			return -1;
		if (ret == 0) {
			mail_cache_set_corrupted(cache,
				"header field size outside file");
			return -1;
		}
		*field_hdr_r = data;
	}
	*offset_r = offset;
	return 0;
}

int mail_cache_header_fields_read(struct mail_cache *cache)
{
	const struct mail_cache_header_fields *field_hdr;
	struct mail_cache_field field;
	const uint32_t *last_used, *sizes;
	const uint8_t *types, *decisions;
	const char *p, *names, *end;
	char *orig_key;
	void *orig_value;
	unsigned int fidx, new_fields_count;
	enum mail_cache_decision_type dec;
	time_t max_drop_time;
	uint32_t offset, i;

	if (mail_cache_header_fields_get_offset(cache, &offset, &field_hdr) < 0)
		return -1;

	if (offset == 0) {
		/* no fields - the file is empty */
		return 0;
	}

	/* check the fixed size of the header. name[] has to be checked
	   separately */
	if (field_hdr->fields_count > INT_MAX / MAIL_CACHE_FIELD_NAMES(1) ||
	    field_hdr->size < MAIL_CACHE_FIELD_NAMES(field_hdr->fields_count)) {
		mail_cache_set_corrupted(cache, "invalid field header size");
		return -1;
	}

	new_fields_count = field_hdr->fields_count;
	if (new_fields_count != 0) {
		cache->file_field_map =
			i_realloc_type(cache->file_field_map, unsigned int,
				       cache->file_fields_count, new_fields_count);
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
	i_assert(names <= end);

	/* clear the old mapping */
	for (i = 0; i < cache->fields_count; i++)
		cache->field_file_map[i] = (uint32_t)-1;

	max_drop_time = cache->index->map->hdr.day_stamp == 0 ? 0 :
		cache->index->map->hdr.day_stamp -
		cache->index->optimization_set.cache.unaccessed_field_drop_secs;

	i_zero(&field);
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

		/* ignore any forced-flags in the file */
		enum mail_cache_decision_type file_dec =
			decisions[i] & ~MAIL_CACHE_DECISION_FORCED;

		if (hash_table_lookup_full(cache->field_name_hash, names,
					   &orig_key, &orig_value)) {
			/* already exists, see if decision can be updated */
			fidx = POINTER_CAST_TO(orig_value, unsigned int);
			enum mail_cache_decision_type cur_dec =
				cache->fields[fidx].field.decision;
			if ((cur_dec & MAIL_CACHE_DECISION_FORCED) != 0) {
				/* Forced decision. If the decision has
				   changed, update the fields in the file. */
				if ((cur_dec & ~MAIL_CACHE_DECISION_FORCED) != file_dec)
					cache->field_header_write_pending = TRUE;
			} else if (cache->fields[fidx].decision_dirty) {
				/* Decisions have recently been updated
				   internally. Don't change them. */
			} else {
				/* Use the decision from the cache file. */
				cache->fields[fidx].field.decision = file_dec;
			}
			if (field_type_verify(cache, fidx,
					      types[i], sizes[i]) < 0)
				return -1;
		} else {
			/* field is currently unknown, so just use whatever
			   exists in the file. */
			field.name = names;
			field.type = types[i];
			field.field_size = sizes[i];
			field.decision = file_dec;
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
		if ((time_t)last_used[i] > cache->fields[fidx].field.last_used)
			cache->fields[fidx].field.last_used = last_used[i];

		dec = cache->fields[fidx].field.decision;
		if (cache->fields[fidx].field.last_used < max_drop_time &&
		    cache->fields[fidx].field.last_used != 0 &&
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
	    mail_cache_header_fields_get_offset(cache, &offset, NULL) < 0)
		return -1;

	buffer = t_buffer_create(256);

	copy_to_buf(cache, buffer, FALSE,
		    offsetof(struct mail_cache_field, last_used),
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

	if (mail_cache_lock(cache) <= 0)
		return -1;

	T_BEGIN {
		ret = mail_cache_header_fields_update_locked(cache);
	} T_END;
	i_assert(!cache->hdr_modified);
	mail_cache_unlock(cache);
	return ret;
}

void mail_cache_header_fields_get(struct mail_cache *cache, buffer_t *dest)
{
	struct mail_cache_header_fields hdr;
	unsigned int field;
	const char *name;
	uint32_t i;

	i_zero(&hdr);
	hdr.fields_count = cache->file_fields_count;
	for (i = 0; i < cache->fields_count; i++) {
		if (CACHE_FIELD_IS_NEWLY_WANTED(cache, i))
			hdr.fields_count++;
	}
	buffer_append(dest, &hdr, sizeof(hdr));

	/* we have to keep the field order for the existing fields. */
	copy_to_buf(cache, dest, TRUE,
		    offsetof(struct mail_cache_field, last_used),
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
	if (mail_cache_header_fields_get_offset(cache, offset_r, NULL) < 0)
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
