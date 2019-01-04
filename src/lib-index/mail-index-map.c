/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str-sanitize.h"
#include "mmap-util.h"
#include "mail-index-private.h"
#include "mail-index-modseq.h"

void mail_index_map_init_extbufs(struct mail_index_map *map,
				 unsigned int initial_count)
{
#define EXTENSION_NAME_APPROX_LEN 20
#define EXT_GLOBAL_ALLOC_SIZE \
	((sizeof(map->extensions) + sizeof(buffer_t)) * 2)
#define EXT_PER_ALLOC_SIZE \
	(EXTENSION_NAME_APPROX_LEN + \
	 sizeof(struct mail_index_ext) + sizeof(uint32_t))
	size_t size;

	if (map->extension_pool == NULL) {
		size = EXT_GLOBAL_ALLOC_SIZE +
			initial_count * EXT_PER_ALLOC_SIZE;
		map->extension_pool =
			pool_alloconly_create(MEMPOOL_GROWING"map extensions",
					      nearest_power(size));
	} else {
		p_clear(map->extension_pool);

		/* try to use the existing pool's size for initial_count so
		   we don't grow it needlessly */
		size = p_get_max_easy_alloc_size(map->extension_pool);
		if (size > EXT_GLOBAL_ALLOC_SIZE + EXT_PER_ALLOC_SIZE) {
			initial_count = (size - EXT_GLOBAL_ALLOC_SIZE) /
				EXT_PER_ALLOC_SIZE;
		}
	}

	p_array_init(&map->extensions, map->extension_pool, initial_count);
	p_array_init(&map->ext_id_map, map->extension_pool, initial_count);
}

bool mail_index_map_lookup_ext(struct mail_index_map *map, const char *name,
			       uint32_t *idx_r)
{
	const struct mail_index_ext *ext;

	if (!array_is_created(&map->extensions))
		return FALSE;

	array_foreach(&map->extensions, ext) {
		if (strcmp(ext->name, name) == 0) {
			*idx_r = array_foreach_idx(&map->extensions, ext);
			return TRUE;
		}
	}
	return FALSE;
}

unsigned int mail_index_map_ext_hdr_offset(unsigned int name_len)
{
	size_t size = sizeof(struct mail_index_ext_header) + name_len;
	return MAIL_INDEX_HEADER_SIZE_ALIGN(size);
}

uint32_t
mail_index_map_register_ext(struct mail_index_map *map,
			    const char *name, uint32_t ext_offset,
			    const struct mail_index_ext_header *ext_hdr)
{
	struct mail_index_ext *ext;
	uint32_t idx, ext_map_idx, empty_idx = (uint32_t)-1;

	if (!array_is_created(&map->extensions)) {
                mail_index_map_init_extbufs(map, 5);
		idx = 0;
	} else {
		idx = array_count(&map->extensions);
	}
	i_assert(!mail_index_map_lookup_ext(map, name, &ext_map_idx));

	ext = array_append_space(&map->extensions);
	ext->name = p_strdup(map->extension_pool, name);
	ext->ext_offset = ext_offset;
	ext->hdr_offset = ext_offset == (uint32_t)-1 ? (uint32_t)-1 :
		ext_offset + mail_index_map_ext_hdr_offset(strlen(name));
	ext->hdr_size = ext_hdr->hdr_size;
	ext->record_offset = ext_hdr->record_offset;
	ext->record_size = ext_hdr->record_size;
	ext->record_align = ext_hdr->record_align;
	ext->reset_id = ext_hdr->reset_id;

	ext->index_idx = mail_index_ext_register(map->index, name,
						 ext_hdr->hdr_size,
						 ext_hdr->record_size,
						 ext_hdr->record_align);

	/* Update index ext_id -> map ext_id mapping. Fill non-used
	   ext_ids with (uint32_t)-1 */
	while (array_count(&map->ext_id_map) < ext->index_idx)
		array_push_back(&map->ext_id_map, &empty_idx);
	array_idx_set(&map->ext_id_map, ext->index_idx, &idx);
	return idx;
}

int mail_index_map_ext_get_next(struct mail_index_map *map,
				unsigned int *offset_p,
				const struct mail_index_ext_header **ext_hdr_r,
				const char **name_r)
{
	const struct mail_index_ext_header *ext_hdr;
	unsigned int offset, name_offset;

	offset = *offset_p;
	*name_r = "";

	/* Extension header contains:
	   - struct mail_index_ext_header
	   - name (not 0-terminated)
	   - 64bit alignment padding
	   - extension header contents
	   - 64bit alignment padding
	*/
	name_offset = offset + sizeof(*ext_hdr);
	ext_hdr = CONST_PTR_OFFSET(map->hdr_base, offset);
	if (offset + sizeof(*ext_hdr) >= map->hdr.header_size)
		return -1;

	offset += mail_index_map_ext_hdr_offset(ext_hdr->name_size);
	if (offset > map->hdr.header_size)
		return -1;

	*name_r = t_strndup(CONST_PTR_OFFSET(map->hdr_base, name_offset),
			    ext_hdr->name_size);
	if (strcmp(*name_r, str_sanitize(*name_r, -1)) != 0) {
		/* we allow only plain ASCII names, so this extension
		   is most likely broken */
		*name_r = "";
	}

	/* finally make sure that the hdr_size is small enough.
	   do this last so that we could return a usable name. */
	offset += MAIL_INDEX_HEADER_SIZE_ALIGN(ext_hdr->hdr_size);
	if (offset > map->hdr.header_size)
		return -1;

	*offset_p = offset;
	*ext_hdr_r = ext_hdr;
	return 0;
}

static int
mail_index_map_ext_hdr_check_record(const struct mail_index_header *hdr,
				    const struct mail_index_ext_header *ext_hdr,
				    const char **error_r)
{
	if (ext_hdr->record_align == 0) {
		*error_r = "Record field alignment is zero";
		return -1;
	}

	/* until we get 128 bit CPUs having a larger alignment is pointless */
	if (ext_hdr->record_align > sizeof(uint64_t)) {
		*error_r = "Record alignment is too large";
		return -1;
	}
	/* a large record size is most likely a bug somewhere. the maximum
	   record size is limited to 64k anyway, so try to fail earlier. */
	if (ext_hdr->record_size >= 32768) {
		*error_r = "Record size is too large";
		return -1;
	}

	if (ext_hdr->record_offset == 0) {
		/* if we get here from extension introduction, record_offset=0
		   and hdr->record_size hasn't been updated yet */
		return 0;
	}

	if (ext_hdr->record_offset + ext_hdr->record_size > hdr->record_size) {
		*error_r = t_strdup_printf("Record field points "
					   "outside record size (%u+%u > %u)",
					   ext_hdr->record_offset,
					   ext_hdr->record_size,
					   hdr->record_size);
		return -1;
	}

	if ((ext_hdr->record_offset % ext_hdr->record_align) != 0) {
		*error_r = t_strdup_printf("Record field alignment %u "
					   "not used", ext_hdr->record_align);
		return -1;
	}
	if ((hdr->record_size % ext_hdr->record_align) != 0) {
		*error_r = t_strdup_printf("Record size not aligned by %u "
					   "as required by extension",
					   ext_hdr->record_align);
		return -1;
	}
	return 0;
}

int mail_index_map_ext_hdr_check(const struct mail_index_header *hdr,
				 const struct mail_index_ext_header *ext_hdr,
				 const char *name, const char **error_r)
{
	if (ext_hdr->record_size == 0 && ext_hdr->hdr_size == 0) {
		*error_r = "Invalid field values";
		return -1;
	}
	if (*name == '\0') {
		*error_r = "Broken name";
		return -1;
	}

	if (ext_hdr->record_size != 0) {
		if (mail_index_map_ext_hdr_check_record(hdr, ext_hdr,
							error_r) < 0)
			return -1;
	}
	if (ext_hdr->hdr_size > MAIL_INDEX_EXT_HEADER_MAX_SIZE) {
		*error_r = t_strdup_printf("Headersize too large (%u)",
					   ext_hdr->hdr_size);
		return -1;
	}
	return 0;
}

static void mail_index_header_init(struct mail_index *index,
				   struct mail_index_header *hdr)
{
	i_assert((sizeof(*hdr) % sizeof(uint64_t)) == 0);

	i_zero(hdr);

	hdr->major_version = MAIL_INDEX_MAJOR_VERSION;
	hdr->minor_version = MAIL_INDEX_MINOR_VERSION;
	hdr->base_header_size = sizeof(*hdr);
	hdr->header_size = sizeof(*hdr);
	hdr->record_size = sizeof(struct mail_index_record);

#ifndef WORDS_BIGENDIAN
	hdr->compat_flags |= MAIL_INDEX_COMPAT_LITTLE_ENDIAN;
#endif

	hdr->indexid = index->indexid;
	hdr->log_file_seq = 1;
	hdr->next_uid = 1;
	hdr->first_recent_uid = 1;
}

struct mail_index_map *mail_index_map_alloc(struct mail_index *index)
{
	struct mail_index_map tmp_map;

	i_zero(&tmp_map);
	mail_index_header_init(index, &tmp_map.hdr);
	tmp_map.index = index;
	tmp_map.hdr_base = &tmp_map.hdr;

	/* a bit kludgy way to do this, but it initializes everything
	   nicely and correctly */
	return mail_index_map_clone(&tmp_map);
}

static void mail_index_record_map_free(struct mail_index_map *map,
				       struct mail_index_record_map *rec_map)
{
	if (rec_map->buffer != NULL) {
		i_assert(rec_map->mmap_base == NULL);
		buffer_free(&rec_map->buffer);
	} else if (rec_map->mmap_base != NULL) {
		i_assert(rec_map->buffer == NULL);
		if (munmap(rec_map->mmap_base, rec_map->mmap_size) < 0)
			mail_index_set_syscall_error(map->index, "munmap()");
		rec_map->mmap_base = NULL;
	}
	array_free(&rec_map->maps);
	if (rec_map->modseq != NULL)
		mail_index_map_modseq_free(&rec_map->modseq);
	i_free(rec_map);
}

static void mail_index_record_map_unlink(struct mail_index_map *map)
{
	struct mail_index_map *const *maps;
	unsigned int idx = UINT_MAX;

	array_foreach(&map->rec_map->maps, maps) {
		if (*maps == map) {
			idx = array_foreach_idx(&map->rec_map->maps, maps);
			break;
		}
	}
	i_assert(idx != UINT_MAX);

	array_delete(&map->rec_map->maps, idx, 1);
	if (array_count(&map->rec_map->maps) == 0) {
		mail_index_record_map_free(map, map->rec_map);
		map->rec_map = NULL;
	}
}

void mail_index_unmap(struct mail_index_map **_map)
{
	struct mail_index_map *map = *_map;

	*_map = NULL;
	if (--map->refcount > 0)
		return;

	i_assert(map->refcount == 0);
	mail_index_record_map_unlink(map);

	pool_unref(&map->extension_pool);
	if (array_is_created(&map->keyword_idx_map))
		array_free(&map->keyword_idx_map);
	buffer_free(&map->hdr_copy_buf);
	i_free(map);
}

static void mail_index_map_copy_records(struct mail_index_record_map *dest,
					const struct mail_index_record_map *src,
					unsigned int record_size)
{
	size_t size;

	size = src->records_count * record_size;
	/* +1% so we have a bit of space to grow. useful for huge mailboxes. */
	dest->buffer = buffer_create_dynamic(default_pool,
					     size + I_MAX(size/100, 1024));
	buffer_append(dest->buffer, src->records, size);

	dest->records = buffer_get_modifiable_data(dest->buffer, NULL);
	dest->records_count = src->records_count;
}

static void mail_index_map_copy_header(struct mail_index_map *dest,
				       const struct mail_index_map *src)
{
	/* use src->hdr copy directly, because if we got here
	   from syncing it has the latest changes. */
	if (src != dest)
		dest->hdr = src->hdr;
	if (dest->hdr_copy_buf != NULL) {
		if (src == dest)
			return;

		buffer_set_used_size(dest->hdr_copy_buf, 0);
	} else {
		dest->hdr_copy_buf =
			buffer_create_dynamic(default_pool,
					      dest->hdr.header_size);
	}
	buffer_append(dest->hdr_copy_buf, &dest->hdr,
		      I_MIN(sizeof(dest->hdr), src->hdr.base_header_size));
	if (src != dest) {
		buffer_write(dest->hdr_copy_buf, src->hdr.base_header_size,
			     CONST_PTR_OFFSET(src->hdr_base,
					      src->hdr.base_header_size),
			     src->hdr.header_size - src->hdr.base_header_size);
	}
	dest->hdr_base = buffer_get_modifiable_data(dest->hdr_copy_buf, NULL);
	i_assert(dest->hdr_copy_buf->used == dest->hdr.header_size);
}

static struct mail_index_record_map *
mail_index_record_map_alloc(struct mail_index_map *map)
{
	struct mail_index_record_map *rec_map;

	rec_map = i_new(struct mail_index_record_map, 1);
	i_array_init(&rec_map->maps, 4);
	array_push_back(&rec_map->maps, &map);
	return rec_map;
}

struct mail_index_map *mail_index_map_clone(const struct mail_index_map *map)
{
	struct mail_index_map *mem_map;
	struct mail_index_ext *ext;
	unsigned int count;

	mem_map = i_new(struct mail_index_map, 1);
	mem_map->index = map->index;
	mem_map->refcount = 1;
	if (map->rec_map == NULL) {
		mem_map->rec_map = mail_index_record_map_alloc(mem_map);
		mem_map->rec_map->buffer =
			buffer_create_dynamic(default_pool, 1024);
	} else {
		mem_map->rec_map = map->rec_map;
		array_push_back(&mem_map->rec_map->maps, &mem_map);
	}

	mail_index_map_copy_header(mem_map, map);

	/* copy extensions */
	if (array_is_created(&map->ext_id_map)) {
		count = array_count(&map->ext_id_map);
		mail_index_map_init_extbufs(mem_map, count + 2);

		array_append_array(&mem_map->extensions, &map->extensions);
		array_append_array(&mem_map->ext_id_map, &map->ext_id_map);

		/* fix the name pointers to use our own pool */
		array_foreach_modifiable(&mem_map->extensions, ext) {
			i_assert(ext->record_offset + ext->record_size <=
				 mem_map->hdr.record_size);
			ext->name = p_strdup(mem_map->extension_pool,
					     ext->name);
		}
	}

	/* copy keyword map */
	if (array_is_created(&map->keyword_idx_map)) {
		i_array_init(&mem_map->keyword_idx_map,
			     array_count(&map->keyword_idx_map) + 4);
		array_append_array(&mem_map->keyword_idx_map,
				   &map->keyword_idx_map);
	}

	return mem_map;
}

void mail_index_record_map_move_to_private(struct mail_index_map *map)
{
	struct mail_index_record_map *new_map;
	const struct mail_index_record *rec;

	if (array_count(&map->rec_map->maps) > 1) {
		new_map = mail_index_record_map_alloc(map);
		mail_index_map_copy_records(new_map, map->rec_map,
					    map->hdr.record_size);
		mail_index_record_map_unlink(map);
		map->rec_map = new_map;
		if (map->rec_map->modseq != NULL)
			new_map->modseq = mail_index_map_modseq_clone(map->rec_map->modseq);
	} else {
		new_map = map->rec_map;
	}

	if (new_map->records_count != map->hdr.messages_count) {
		new_map->records_count = map->hdr.messages_count;
		if (new_map->records_count == 0)
			new_map->last_appended_uid = 0;
		else {
			rec = MAIL_INDEX_REC_AT_SEQ(map, new_map->records_count);
			new_map->last_appended_uid = rec->uid;
		}
		buffer_set_used_size(new_map->buffer, new_map->records_count *
				     map->hdr.record_size);
	}
}

void mail_index_map_move_to_memory(struct mail_index_map *map)
{
	struct mail_index_record_map *new_map;

	if (map->rec_map->mmap_base == NULL)
		return;

	if (array_count(&map->rec_map->maps) == 1)
		new_map = map->rec_map;
	else {
		new_map = mail_index_record_map_alloc(map);
		new_map->modseq = map->rec_map->modseq == NULL ? NULL :
			mail_index_map_modseq_clone(map->rec_map->modseq);
	}

	mail_index_map_copy_records(new_map, map->rec_map,
				    map->hdr.record_size);
	mail_index_map_copy_header(map, map);

	if (new_map != map->rec_map) {
		mail_index_record_map_unlink(map);
		map->rec_map = new_map;
	} else {
		if (munmap(new_map->mmap_base, new_map->mmap_size) < 0)
			mail_index_set_syscall_error(map->index, "munmap()");
		new_map->mmap_base = NULL;
	}
}

bool mail_index_map_get_ext_idx(struct mail_index_map *map,
				uint32_t ext_id, uint32_t *idx_r)
{
	const uint32_t *id;

	if (!array_is_created(&map->ext_id_map) ||
	    ext_id >= array_count(&map->ext_id_map))
		return FALSE;

	id = array_idx(&map->ext_id_map, ext_id);
	*idx_r = *id;
	return *idx_r != (uint32_t)-1;
}

static uint32_t mail_index_bsearch_uid(struct mail_index_map *map,
				       uint32_t uid, uint32_t left_idx,
				       int nearest_side)
{
	const struct mail_index_record *rec_base, *rec;
	uint32_t idx, right_idx, record_size;

	i_assert(map->hdr.messages_count <= map->rec_map->records_count);

	rec_base = map->rec_map->records;
	record_size = map->hdr.record_size;

	idx = left_idx;
	right_idx = I_MIN(map->hdr.messages_count, uid);

	i_assert(right_idx < INT_MAX);
	while (left_idx < right_idx) {
		idx = (left_idx + right_idx) / 2;

                rec = CONST_PTR_OFFSET(rec_base, idx * record_size);
		if (rec->uid < uid)
			left_idx = idx+1;
		else if (rec->uid > uid)
			right_idx = idx;
		else
			break;
	}
	i_assert(idx < map->hdr.messages_count);

	rec = CONST_PTR_OFFSET(rec_base, idx * record_size);
	if (rec->uid != uid) {
		if (nearest_side > 0) {
			/* we want uid or larger */
			return rec->uid > uid ? idx+1 :
				(idx == map->hdr.messages_count-1 ? 0 : idx+2);
		} else {
			/* we want uid or smaller */
			return rec->uid < uid ? idx + 1 : idx;
		}
	}

	return idx+1;
}

void mail_index_map_lookup_seq_range(struct mail_index_map *map,
				     uint32_t first_uid, uint32_t last_uid,
				     uint32_t *first_seq_r,
				     uint32_t *last_seq_r)
{
	i_assert(first_uid > 0);
	i_assert(first_uid <= last_uid);

	if (map->hdr.messages_count == 0) {
		*first_seq_r = *last_seq_r = 0;
		return;
	}

	*first_seq_r = mail_index_bsearch_uid(map, first_uid, 0, 1);
	if (*first_seq_r == 0 ||
	    MAIL_INDEX_REC_AT_SEQ(map, *first_seq_r)->uid > last_uid) {
		*first_seq_r = *last_seq_r = 0;
		return;
	}

	if (last_uid >= map->hdr.next_uid-1) {
		/* we want the last message */
		last_uid = map->hdr.next_uid-1;
		if (first_uid > last_uid) {
			*first_seq_r = *last_seq_r = 0;
			return;
		}

		*last_seq_r = map->hdr.messages_count;
		return;
	}

	if (first_uid == last_uid)
		*last_seq_r = *first_seq_r;
	else {
		/* optimization - binary lookup only from right side: */
		*last_seq_r = mail_index_bsearch_uid(map, last_uid,
						     *first_seq_r - 1, -1);
	}
	i_assert(*last_seq_r >= *first_seq_r);
}
