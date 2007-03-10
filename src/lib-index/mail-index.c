/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "buffer.h"
#include "hash.h"
#include "mmap-util.h"
#include "nfs-workarounds.h"
#include "read-full.h"
#include "write-full.h"
#include "mail-index-private.h"
#include "mail-index-view-private.h"
#include "mail-index-sync-private.h"
#include "mail-transaction-log.h"
#include "mail-cache.h"

#include <stdio.h>
#include <stddef.h>
#include <time.h>
#include <sys/stat.h>

unsigned int mail_index_module_id = 0;

static int mail_index_try_open_only(struct mail_index *index);
static void mail_index_create_in_memory(struct mail_index *index,
					const struct mail_index_header *hdr);

struct mail_index *mail_index_alloc(const char *dir, const char *prefix)
{
	struct mail_index *index;

	index = i_new(struct mail_index, 1);
	index->dir = i_strdup(dir);
	index->prefix = i_strdup(prefix);
	index->fd = -1;

	index->extension_pool =
		pool_alloconly_create(MEMPOOL_GROWING"index extension", 1024);
	p_array_init(&index->extensions, index->extension_pool, 5);
	i_array_init(&index->sync_lost_handlers, 4);
	array_create(&index->mail_index_module_contexts, default_pool,
		     sizeof(void *), I_MIN(5, mail_index_module_id));

	index->mode = 0600;
	index->gid = (gid_t)-1;

	index->keywords_ext_id =
		mail_index_ext_register(index, "keywords", 128, 2, 1);
	index->keywords_pool = pool_alloconly_create("keywords", 512);
	i_array_init(&index->keywords, 16);
	index->keywords_hash =
		hash_create(default_pool, index->keywords_pool, 0,
			    strcase_hash, (hash_cmp_callback_t *)strcasecmp);
	return index;
}

void mail_index_free(struct mail_index **_index)
{
	struct mail_index *index = *_index;

	*_index = NULL;
	mail_index_close(index);

	hash_destroy(index->keywords_hash);
	pool_unref(index->extension_pool);
	pool_unref(index->keywords_pool);

	array_free(&index->sync_lost_handlers);
	array_free(&index->keywords);
	array_free(&index->mail_index_module_contexts);

	i_free(index->error);
	i_free(index->dir);
	i_free(index->prefix);
	i_free(index);
}

void mail_index_set_permissions(struct mail_index *index,
				mode_t mode, gid_t gid)
{
	index->mode = mode & 0666;
	index->gid = gid;
}

uint32_t mail_index_ext_register(struct mail_index *index, const char *name,
				 uint32_t default_hdr_size,
				 uint16_t default_record_size,
				 uint16_t default_record_align)
{
        const struct mail_index_registered_ext *extensions;
	struct mail_index_registered_ext rext;
	unsigned int i, ext_count;

	extensions = array_get(&index->extensions, &ext_count);

	/* see if it's already there */
	for (i = 0; i < ext_count; i++) {
		if (strcmp(extensions[i].name, name) == 0)
			return i;
	}

	memset(&rext, 0, sizeof(rext));
	rext.name = p_strdup(index->extension_pool, name);
	rext.index_idx = ext_count;
	rext.hdr_size = default_hdr_size;
	rext.record_size = default_record_size;
	rext.record_align = default_record_align;

	array_append(&index->extensions, &rext, 1);
	return ext_count;
}

void mail_index_register_expunge_handler(struct mail_index *index,
					 uint32_t ext_id, bool call_always,
					 mail_index_expunge_handler_t *cb,
					 void *context)
{
	struct mail_index_registered_ext *rext;

	rext = array_idx_modifiable(&index->extensions, ext_id);
	i_assert(rext->expunge_handler == NULL || rext->expunge_handler == cb);

	rext->expunge_handler = cb;
	rext->expunge_context = context;
	rext->expunge_handler_call_always = call_always;
}

void mail_index_unregister_expunge_handler(struct mail_index *index,
					   uint32_t ext_id)
{
	struct mail_index_registered_ext *rext;

	rext = array_idx_modifiable(&index->extensions, ext_id);
	i_assert(rext->expunge_handler != NULL);

	rext->expunge_handler = NULL;
}

void mail_index_register_sync_handler(struct mail_index *index, uint32_t ext_id,
				      mail_index_sync_handler_t *cb,
				      enum mail_index_sync_handler_type type)
{
	struct mail_index_registered_ext *rext;

	rext = array_idx_modifiable(&index->extensions, ext_id);
	i_assert(rext->sync_handler.callback == NULL);

	rext->sync_handler.callback = cb;
	rext->sync_handler.type = type;
}

void mail_index_unregister_sync_handler(struct mail_index *index,
					uint32_t ext_id)
{
	struct mail_index_registered_ext *rext;

	rext = array_idx_modifiable(&index->extensions, ext_id);
	i_assert(rext->sync_handler.callback != NULL);

	rext->sync_handler.callback = NULL;
	rext->sync_handler.type = 0;
}

void mail_index_register_sync_lost_handler(struct mail_index *index,
					   mail_index_sync_lost_handler_t *cb)
{
	array_append(&index->sync_lost_handlers, &cb, 1);
}

void mail_index_unregister_sync_lost_handler(struct mail_index *index,
					     mail_index_sync_lost_handler_t *cb)
{
	mail_index_sync_lost_handler_t *const *handlers;
	unsigned int i, count;

	handlers = array_get(&index->sync_lost_handlers, &count);
	for (i = 0; i < count; i++) {
		if (handlers[i] == cb) {
			array_delete(&index->sync_lost_handlers, i, 1);
			break;
		}
	}
}

static void mail_index_map_init_extbufs(struct mail_index_map *map,
					unsigned int initial_count)
{
#define EXTENSION_NAME_APPROX_LEN 20
#define EXT_GLOBAL_ALLOC_SIZE \
	((sizeof(map->extensions) + BUFFER_APPROX_SIZE) * 2)
#define EXT_PER_ALLOC_SIZE \
	(EXTENSION_NAME_APPROX_LEN + \
	 sizeof(struct mail_index_ext) + sizeof(uint32_t))
	size_t size;

	if (map->extension_pool == NULL) {
		size = EXT_GLOBAL_ALLOC_SIZE +
			initial_count * EXT_PER_ALLOC_SIZE;
		map->extension_pool =
			pool_alloconly_create("map extensions",
					      nearest_power(size));
	} else {
		p_clear(map->extension_pool);

		/* try to use the existing pool's size for initial_count so
		   we don't grow it unneededly */
		size = p_get_max_easy_alloc_size(map->extension_pool);
		if (size > EXT_GLOBAL_ALLOC_SIZE + EXT_PER_ALLOC_SIZE) {
			initial_count = (size - EXT_GLOBAL_ALLOC_SIZE) /
				EXT_PER_ALLOC_SIZE;
		}
	}

	p_array_init(&map->extensions, map->extension_pool, initial_count);
	p_array_init(&map->ext_id_map, map->extension_pool, initial_count);
}

uint32_t mail_index_map_lookup_ext(struct mail_index_map *map, const char *name)
{
	const struct mail_index_ext *extensions;
	unsigned int i, size;

	if (!array_is_created(&map->extensions))
		return (uint32_t)-1;

	extensions = array_get(&map->extensions, &size);
	for (i = 0; i < size; i++) {
		if (strcmp(extensions[i].name, name) == 0)
			return i;
	}
	return (uint32_t)-1;
}

uint32_t
mail_index_map_register_ext(struct mail_index *index,
			    struct mail_index_map *map, const char *name,
			    uint32_t hdr_offset, uint32_t hdr_size,
			    uint32_t record_offset, uint32_t record_size,
			    uint32_t record_align, uint32_t reset_id)
{
	struct mail_index_ext *ext;
	uint32_t idx, empty_idx = (uint32_t)-1;

	if (!array_is_created(&map->extensions)) {
                mail_index_map_init_extbufs(map, 5);
		idx = 0;
	} else {
		idx = array_count(&map->extensions);
	}
	i_assert(mail_index_map_lookup_ext(map, name) == (uint32_t)-1);

	ext = array_append_space(&map->extensions);
	ext->name = p_strdup(map->extension_pool, name);
	ext->hdr_offset = hdr_offset;
	ext->hdr_size = hdr_size;
	ext->record_offset = record_offset;
	ext->record_size = record_size;
	ext->record_align = record_align;
	ext->reset_id = reset_id;

	ext->index_idx = mail_index_ext_register(index, name, hdr_size,
						 record_size, record_align);

	/* Update index ext_id -> map ext_id mapping. Fill non-used
	   ext_ids with (uint32_t)-1 */
	while (array_count(&map->ext_id_map) < ext->index_idx)
		array_append(&map->ext_id_map, &empty_idx, 1);
	array_idx_set(&map->ext_id_map, ext->index_idx, &idx);
	return idx;
}

static bool size_check(size_t *size_left, size_t size)
{
	if (size > *size_left)
		return FALSE;
	*size_left -= size;
	return TRUE;
}

static size_t get_align(size_t name_len)
{
	size_t size = sizeof(struct mail_index_ext_header) + name_len;
	return MAIL_INDEX_HEADER_SIZE_ALIGN(size) - size;
}

static int mail_index_parse_extensions(struct mail_index *index,
                                       struct mail_index_map *map)
{
	const struct mail_index_ext_header *ext_hdr;
	unsigned int i, old_count;
	const char *name;
	uint32_t ext_id, offset, name_offset;
	size_t size_left;

	/* extension headers always start from 64bit offsets, so if base header
	   doesn't happen to be 64bit aligned we'll skip some bytes */
	offset = MAIL_INDEX_HEADER_SIZE_ALIGN(map->hdr.base_header_size);
	if (offset >= map->hdr.header_size && map->extension_pool == NULL) {
		/* nothing to do, skip allocatations and all */
		return 1;
	}

	old_count = array_count(&index->extensions);
	mail_index_map_init_extbufs(map, old_count + 5);

	ext_id = (uint32_t)-1;
	for (i = 0; i < old_count; i++)
		array_append(&map->ext_id_map, &ext_id, 1);

	while (offset < map->hdr.header_size) {
		ext_hdr = CONST_PTR_OFFSET(map->hdr_base, offset);

		/* Extension header contains:
		   - struct mail_index_ext_header
		   - name (not 0-terminated)
		   - 64bit alignment padding
		   - extension header contents
		   - 64bit alignment padding
		*/
		size_left = map->hdr.header_size - offset;
		if (!size_check(&size_left, sizeof(*ext_hdr)) ||
		    !size_check(&size_left, ext_hdr->name_size) ||
		    !size_check(&size_left, get_align(ext_hdr->name_size)) ||
		    !size_check(&size_left, ext_hdr->hdr_size)) {
			mail_index_set_error(index, "Corrupted index file %s: "
				"Header extension goes outside header",
				index->filepath);
			return -1;
		}

		offset += sizeof(*ext_hdr);
		name_offset = offset;
		offset += ext_hdr->name_size + get_align(ext_hdr->name_size);

		t_push();
		name = t_strndup(CONST_PTR_OFFSET(map->hdr_base, name_offset),
				 ext_hdr->name_size);

		if (mail_index_map_lookup_ext(map, name) != (uint32_t)-1) {
			mail_index_set_error(index, "Corrupted index file %s: "
				"Duplicate header extension %s",
				index->filepath, name);
			t_pop();
			return -1;
		}

		if (map->hdr.record_size <
		    ext_hdr->record_offset + ext_hdr->record_size) {
			mail_index_set_error(index, "Corrupted index file %s: "
				"Record field %s points outside record size "
				"(%u < %u+%u)", index->filepath, name,
				map->hdr.record_size,
				ext_hdr->record_offset, ext_hdr->record_size);
			t_pop();
			return -1;
		}

		if ((ext_hdr->record_offset % ext_hdr->record_align) != 0 ||
		    (map->hdr.record_size % ext_hdr->record_align) != 0) {
			mail_index_set_error(index, "Corrupted index file %s: "
				"Record field %s alignmentation %u not used",
				index->filepath, name, ext_hdr->record_align);
			t_pop();
			return -1;
		}
		mail_index_map_register_ext(index, map, name,
					    offset, ext_hdr->hdr_size,
					    ext_hdr->record_offset,
					    ext_hdr->record_size,
					    ext_hdr->record_align,
					    ext_hdr->reset_id);
		t_pop();

		offset += MAIL_INDEX_HEADER_SIZE_ALIGN(ext_hdr->hdr_size);
	}
	return 1;
}

bool mail_index_keyword_lookup(struct mail_index *index,
			       const char *keyword, bool autocreate,
			       unsigned int *idx_r)
{
	char *keyword_dup;
	void *value;

	/* keywords_hash keeps a name => index mapping of keywords.
	   Keywords are never removed from it, so the index values are valid
	   for the lifetime of the mail_index. */
	if (hash_lookup_full(index->keywords_hash, keyword, NULL, &value)) {
		*idx_r = POINTER_CAST_TO(value, unsigned int);
		return TRUE;
	}

	if (!autocreate) {
		*idx_r = (unsigned int)-1;
		return FALSE;
	}

	keyword = keyword_dup = p_strdup(index->keywords_pool, keyword);
	*idx_r = array_count(&index->keywords);

	hash_insert(index->keywords_hash, keyword_dup, POINTER_CAST(*idx_r));
	array_append(&index->keywords, &keyword, 1);
	return TRUE;
}

int mail_index_map_parse_keywords(struct mail_index *index,
                                  struct mail_index_map *map)
{
	const struct mail_index_ext *ext;
	const struct mail_index_keyword_header *kw_hdr;
	const struct mail_index_keyword_header_rec *kw_rec;
	const char *name;
	unsigned int i, name_area_end_offset, old_count;
	uint32_t ext_id;

	map->keywords_read = TRUE;

	ext_id = mail_index_map_lookup_ext(map, "keywords");
	if (ext_id == (uint32_t)-1) {
		if (array_is_created(&map->keyword_idx_map))
			array_clear(&map->keyword_idx_map);
		return 0;
	}

	ext = array_idx(&map->extensions, ext_id);

	/* Extension header contains:
	   - struct mail_index_keyword_header
	   - struct mail_index_keyword_header_rec * keywords_count
	   - const char names[] * keywords_count
	*/
	i_assert(ext->hdr_offset < map->hdr.header_size);
	kw_hdr = CONST_PTR_OFFSET(map->hdr_base, ext->hdr_offset);
	kw_rec = (const void *)(kw_hdr + 1);
	name = (const char *)(kw_rec + kw_hdr->keywords_count);

	old_count = !array_is_created(&map->keyword_idx_map) ? 0 :
		array_count(&map->keyword_idx_map);

	/* Keywords can only be added into same mapping. Removing requires a
	   new mapping (recreating the index file) */
	if (kw_hdr->keywords_count == old_count) {
		/* nothing changed */
		return 0;
	}

	/* make sure the header is valid */
	if (kw_hdr->keywords_count < old_count) {
		mail_index_set_error(index, "Corrupted index file %s: "
				     "Keywords removed unexpectedly",
				     index->filepath);
		return -1;
	}

	if ((size_t)(name - (const char *)kw_hdr) > ext->hdr_size) {
		mail_index_set_error(index, "Corrupted index file %s: "
				     "keywords_count larger than header size",
				     index->filepath);
		return -1;
	}

	name_area_end_offset = (const char *)kw_hdr + ext->hdr_size - name;
	for (i = 0; i < kw_hdr->keywords_count; i++) {
		if (kw_rec[i].name_offset > name_area_end_offset) {
			mail_index_set_error(index, "Corrupted index file %s: "
				"name_offset points outside allocated header",
				index->filepath);
			return -1;
		}
	}
	if (name[name_area_end_offset-1] != '\0') {
		mail_index_set_error(index, "Corrupted index file %s: "
				     "Keyword header doesn't end with NUL",
				     index->filepath);
		return -1;
	}

	/* create file -> index mapping */
	if (!array_is_created(&map->keyword_idx_map)) 
		i_array_init(&map->keyword_idx_map, kw_hdr->keywords_count);

#ifdef DEBUG
	/* Check that existing headers are still the same. It's behind DEBUG
	   since it's pretty useless waste of CPU normally. */
	for (i = 0; i < array_count(&map->keyword_idx_map); i++) {
		const char *keyword = name + kw_rec[i].name_offset;
		const unsigned int *old_idx;
		unsigned int idx;

		old_idx = array_idx(&map->keyword_idx_map, i);
		if (!mail_index_keyword_lookup(index, keyword, FALSE, &idx) ||
		    idx != *old_idx) {
			mail_index_set_error(index, "Corrupted index file %s: "
					     "Keywords changed unexpectedly",
					     index->filepath);
			return -1;
		}
	}
#endif
	/* Register the newly seen keywords */
	i = array_count(&map->keyword_idx_map);
	for (; i < kw_hdr->keywords_count; i++) {
		const char *keyword = name + kw_rec[i].name_offset;
		unsigned int idx;

		(void)mail_index_keyword_lookup(index, keyword, TRUE, &idx);
		array_append(&map->keyword_idx_map, &idx, 1);
	}
	return 0;
}

const ARRAY_TYPE(keywords) *mail_index_get_keywords(struct mail_index *index)
{
	/* Make sure all the keywords are in index->keywords. It's quick to do
	   if nothing has changed. */
	(void)mail_index_map_parse_keywords(index, index->map);

	return &index->keywords;
}

static bool mail_index_check_header_compat(const struct mail_index_header *hdr)
{
        enum mail_index_header_compat_flags compat_flags = 0;

#ifndef WORDS_BIGENDIAN
	compat_flags |= MAIL_INDEX_COMPAT_LITTLE_ENDIAN;
#endif

	if (hdr->major_version != MAIL_INDEX_MAJOR_VERSION) {
		/* major version change - handle silently(?) */
		return FALSE;
	}
	if (hdr->compat_flags != compat_flags) {
		/* architecture change - handle silently(?) */
		return FALSE;
	}

	if ((hdr->flags & MAIL_INDEX_HDR_FLAG_CORRUPTED) != 0) {
		/* we've already complained about it */
		return FALSE;
	}

	return TRUE;
}

static int mail_index_check_header(struct mail_index *index,
				   struct mail_index_map *map)
{
	const struct mail_index_header *hdr = &map->hdr;

	if (!mail_index_check_header_compat(hdr))
		return -1;

	/* following some extra checks that only take a bit of CPU */
	if (hdr->uid_validity == 0 && hdr->next_uid != 1) {
		mail_index_set_error(index, "Corrupted index file %s: "
				     "uid_validity = 0, next_uid = %u",
				     index->filepath, hdr->next_uid);
		return -1;
	}

	if (hdr->record_size < sizeof(struct mail_index_record)) {
		mail_index_set_error(index, "Corrupted index file %s: "
				     "record_size too small: %u < %"PRIuSIZE_T,
				     index->filepath, hdr->record_size,
				     sizeof(struct mail_index_record));
		return -1;
	}

	if ((hdr->flags & MAIL_INDEX_HDR_FLAG_FSCK) != 0)
		return 0;

	if (hdr->next_uid == 0)
		return 0;

	if (hdr->recent_messages_count > hdr->messages_count ||
	    hdr->seen_messages_count > hdr->messages_count ||
	    hdr->deleted_messages_count > hdr->messages_count)
		return 0;
	if (hdr->first_recent_uid_lowwater > hdr->next_uid ||
	    hdr->first_unseen_uid_lowwater > hdr->next_uid ||
	    hdr->first_deleted_uid_lowwater > hdr->next_uid)
		return 0;

	if (map->records_count > 0) {
		/* last message's UID must be smaller than next_uid.
		   also make sure it's not zero. */
		const struct mail_index_record *rec;

		rec = MAIL_INDEX_MAP_IDX(map, map->records_count-1);
		if (rec->uid == 0 || rec->uid >= hdr->next_uid)
			return 0;
	}

	return mail_index_parse_extensions(index, map);
}

static void mail_index_map_clear(struct mail_index *index,
				 struct mail_index_map *map)
{
	if (map->buffer != NULL) {
		i_assert(map->mmap_base == NULL);
		buffer_free(map->buffer);
		map->buffer = NULL;
	} else if (map->mmap_base != NULL) {
		i_assert(map->buffer == NULL);
		if (munmap(map->mmap_base, map->mmap_size) < 0)
			mail_index_set_syscall_error(index, "munmap()");
		map->mmap_base = NULL;
	}

	if (map->refcount > 0) {
		memset(&map->hdr, 0, sizeof(map->hdr));
		map->mmap_size = 0;
		map->mmap_used_size = 0;
		map->records = NULL;
		map->records_count = 0;
	}
}

void mail_index_unmap(struct mail_index *index, struct mail_index_map **_map)
{
	struct mail_index_map *map = *_map;

	*_map = NULL;
	if (--map->refcount > 0)
		return;

	i_assert(map->refcount == 0);
	mail_index_map_clear(index, map);
	if (map->extension_pool != NULL)
		pool_unref(map->extension_pool);
	if (array_is_created(&map->keyword_idx_map))
		array_free(&map->keyword_idx_map);
	buffer_free(map->hdr_copy_buf);
	i_free(map);
}

static void mail_index_map_copy_hdr(struct mail_index_map *map,
				    const struct mail_index_header *hdr)
{
	if (hdr->base_header_size < sizeof(map->hdr)) {
		/* header smaller than ours, make a copy so our newer headers
		   won't have garbage in them */
		memset(&map->hdr, 0, sizeof(map->hdr));
		memcpy(&map->hdr, hdr, hdr->base_header_size);
	} else {
		map->hdr = *hdr;
	}
}

static int mail_index_mmap(struct mail_index *index, struct mail_index_map *map)
{
	const struct mail_index_header *hdr;
	unsigned int records_count;

	i_assert(!map->write_to_disk);

	if (map->buffer != NULL) {
		/* we had temporarily used a buffer, eg. for updating index */
		buffer_free(map->buffer);
		map->buffer = NULL;
	}

	map->mmap_base = index->readonly ?
		mmap_ro_file(index->fd, &map->mmap_size) :
		mmap_rw_file(index->fd, &map->mmap_size);
	if (map->mmap_base == MAP_FAILED) {
		map->mmap_base = NULL;
		mail_index_set_syscall_error(index, "mmap()");
		return -1;
	}

	hdr = map->mmap_base;
	if (map->mmap_size >
	    offsetof(struct mail_index_header, major_version) &&
	    hdr->major_version != MAIL_INDEX_MAJOR_VERSION) {
		/* major version change - handle silently */
		return 0;
	}

	if (map->mmap_size < MAIL_INDEX_HEADER_MIN_SIZE) {
		mail_index_set_error(index, "Corrupted index file %s: "
				     "File too small (%"PRIuSIZE_T")",
				     index->filepath, map->mmap_size);
		return 0;
	}

	if (!mail_index_check_header_compat(hdr)) {
		/* Can't use this file */
		return 0;
	}

	map->mmap_used_size = hdr->header_size +
		hdr->messages_count * hdr->record_size;

	if (map->mmap_used_size > map->mmap_size) {
		records_count = (map->mmap_size - hdr->header_size) /
			hdr->record_size;
		mail_index_set_error(index, "Corrupted index file %s: "
				     "messages_count too large (%u > %u)",
				     index->filepath, hdr->messages_count,
				     records_count);
		return 0;
	}

	mail_index_map_copy_hdr(map, hdr);

	map->hdr_base = map->mmap_base;
	map->records = PTR_OFFSET(map->mmap_base, map->hdr.header_size);
	map->records_count = map->hdr.messages_count;
	return 1;
}

static int mail_index_read_header(struct mail_index *index,
				  void *buf, size_t buf_size, size_t *pos_r)
{
	size_t pos;
	int ret;

	memset(buf, 0, sizeof(struct mail_index_header));

        /* try to read the whole header, but it's not necessarily an error to
	   read less since the older versions of the index format could be
	   smaller. Request reading up to buf_size, but accept if we only got
	   the header. */
        pos = 0;
	do {
		ret = pread(index->fd, PTR_OFFSET(buf, pos),
			    buf_size - pos, pos);
		if (ret > 0)
			pos += ret;
	} while (ret > 0 && pos < sizeof(struct mail_index_header));

	*pos_r = pos;
	return ret;
}

static int
mail_index_read_map(struct mail_index *index, struct mail_index_map *map,
		    bool *retry_r, bool try_retry)
{
	const struct mail_index_header *hdr;
	struct stat st;
	unsigned char buf[512];
	void *data = NULL;
	ssize_t ret;
	size_t pos, records_size;
	unsigned int records_count;

	i_assert(map->mmap_base == NULL);

	*retry_r = FALSE;
	ret = mail_index_read_header(index, buf, sizeof(buf), &pos);
	hdr = (const struct mail_index_header *)buf;

	if (pos > (ssize_t)offsetof(struct mail_index_header, major_version) &&
	    hdr->major_version != MAIL_INDEX_MAJOR_VERSION) {
		/* major version change - handle silently */
		return 0;
	}

	if (fstat(index->fd, &st) < 0) {
		mail_index_set_syscall_error(index, "fstat()");
		return -1;
	}

	if (ret >= 0 && pos >= MAIL_INDEX_HEADER_MIN_SIZE &&
	    (ret > 0 || pos >= hdr->base_header_size)) {
		if (!mail_index_check_header_compat(hdr)) {
			/* Can't use this file */
			return 0;
		}

		if (hdr->base_header_size < MAIL_INDEX_HEADER_MIN_SIZE ||
		    hdr->header_size < hdr->base_header_size) {
			mail_index_set_error(index, "Corrupted index file %s: "
				"Corrupted header sizes (base %u, full %u)",
				index->filepath, hdr->base_header_size,
				hdr->header_size);
			return 0;
		}
		if (hdr->header_size > (uoff_t)st.st_size) {
			mail_index_set_error(index, "Corrupted index file %s: "
				"Corrupted header size (%u > %"PRIuUOFF_T")",
				index->filepath, hdr->header_size,
				st.st_size);
			return 0;
		}

		if (pos > hdr->header_size)
			pos = hdr->header_size;

		/* place the base header into memory. */
		buffer_reset(map->hdr_copy_buf);
		buffer_append(map->hdr_copy_buf, buf, pos);

		if (pos != hdr->header_size) {
			/* @UNSAFE: read the rest of the header into memory */
			data = buffer_append_space_unsafe(map->hdr_copy_buf,
							  hdr->header_size -
							  pos);
			ret = pread_full(index->fd, data,
					 hdr->header_size - pos, pos);
		}
	}

	if (ret > 0) {
		/* header read, read the records now. */
		records_size = (size_t)hdr->messages_count * hdr->record_size;

		if ((uoff_t)st.st_size - hdr->header_size < records_size ||
		    (hdr->record_size != 0 &&
		     records_size / hdr->record_size != hdr->messages_count)) {
			records_count = (st.st_size - hdr->header_size) /
				hdr->record_size;
			mail_index_set_error(index, "Corrupted index file %s: "
				"messages_count too large (%u > %u)",
				index->filepath, hdr->messages_count,
				records_count);
			return 0;
		}

		if (map->buffer == NULL) {
			map->buffer = buffer_create_dynamic(default_pool,
							    records_size);
		}

		/* @UNSAFE */
		buffer_set_used_size(map->buffer, 0);
		data = buffer_append_space_unsafe(map->buffer, records_size);

		ret = pread_full(index->fd, data, records_size,
				 hdr->header_size);
	}

	if (ret < 0) {
		if (errno == ESTALE && try_retry) {
			/* a new index file was renamed over this one. */
			*retry_r = TRUE;
			return 0;
		}
		mail_index_set_syscall_error(index, "pread_full()");
		return -1;
	}
	if (ret == 0) {
		mail_index_set_error(index,
			"Corrupted index file %s: File too small",
			index->filepath);
		return 0;
	}

	map->records = data;
	map->records_count = hdr->messages_count;

	mail_index_map_copy_hdr(map, hdr);
	map->hdr_base = map->hdr_copy_buf->data;

	index->sync_log_file_seq = hdr->log_file_seq;
	index->sync_log_file_offset = hdr->log_file_int_offset;
	return 1;
}

bool mail_index_is_ext_synced(struct mail_transaction_log_view *log_view,
			      struct mail_index_map *map)
{
	uint32_t prev_seq;
	uoff_t prev_offset;

	mail_transaction_log_view_get_prev_pos(log_view, &prev_seq,
					       &prev_offset);
	return prev_seq < map->hdr.log_file_seq ||
		(prev_seq == map->hdr.log_file_seq &&
		 prev_offset < map->hdr.log_file_ext_offset);
}

static int mail_index_sync_from_transactions(struct mail_index *index,
					     struct mail_index_map **map,
					     bool sync_to_index)
{
	const struct mail_index_header *map_hdr = &(*map)->hdr;
	struct mail_index_view *view;
	struct mail_index_sync_map_ctx sync_map_ctx;
	struct mail_index_header hdr;
	const struct mail_transaction_header *thdr;
	const void *tdata;
	uint32_t prev_seq, max_seq;
	uoff_t prev_offset, max_offset;
	size_t pos;
	int ret;
	bool skipped, check_ext_offsets, broken;

	if (sync_to_index) {
		/* read the real log position where we are supposed to be
		   synced */
		ret = mail_index_read_header(index, &hdr, sizeof(hdr), &pos);
		if (ret < 0 && errno != ESTALE) {
			mail_index_set_syscall_error(index, "pread()");
			return -1;
		}
		if (pos < MAIL_INDEX_HEADER_MIN_SIZE)
			return 0;

		if (map_hdr->log_file_seq == hdr.log_file_seq &&
		    map_hdr->log_file_int_offset == hdr.log_file_int_offset) {
			/* nothing to do */
			return 1;
		}

		if (map_hdr->log_file_seq > hdr.log_file_seq ||
		    (map_hdr->log_file_seq == hdr.log_file_seq &&
		     map_hdr->log_file_int_offset > hdr.log_file_int_offset)) {
			/* we went too far, have to re-read the file */
			return 0;
		}
		if (map_hdr->log_file_ext_offset !=
		    map_hdr->log_file_int_offset ||
		    hdr.log_file_ext_offset != hdr.log_file_int_offset) {
			/* too much trouble to get this right. */
			return 0;
		}
		max_seq = hdr.log_file_seq;
		max_offset = hdr.log_file_int_offset;
	} else {
		/* sync everything there is */
		max_seq = (uint32_t)-1;
		max_offset = (uoff_t)-1;
	}

	index->map = *map;

	view = mail_index_view_open(index);
	if (mail_transaction_log_view_set(view->log_view,
					  map_hdr->log_file_seq,
					  map_hdr->log_file_int_offset,
					  max_seq, max_offset,
					  MAIL_TRANSACTION_TYPE_MASK) <= 0) {
		/* can't use it. sync by re-reading index. */
		mail_index_view_close(&view);
		return 0;
	}

	mail_index_sync_map_init(&sync_map_ctx, view,
				 MAIL_INDEX_SYNC_HANDLER_HEAD);

	check_ext_offsets = TRUE; broken = FALSE;
	while ((ret = mail_transaction_log_view_next(view->log_view, &thdr,
						     &tdata, &skipped)) > 0) {
		if ((thdr->type & MAIL_TRANSACTION_EXTERNAL) != 0 &&
		    check_ext_offsets) {
			if (mail_index_is_ext_synced(view->log_view,
						     index->map))
				continue;
			check_ext_offsets = FALSE;
		}

		if (mail_index_sync_record(&sync_map_ctx, thdr, tdata) < 0) {
			ret = 0;
			broken = TRUE;
			break;
		}
	}
	if (ret == 0 && !broken)
		ret = 1;

	mail_transaction_log_view_get_prev_pos(view->log_view, &prev_seq,
					       &prev_offset);
	i_assert(prev_seq <= max_seq &&
		 (prev_seq != max_seq || prev_offset <= max_offset));

	index->map->hdr.log_file_seq = prev_seq;
	index->map->hdr.log_file_int_offset =
		index->map->hdr.log_file_ext_offset = prev_offset;

	mail_index_sync_map_deinit(&sync_map_ctx);
	mail_index_view_close(&view);

	*map = index->map;
	index->map = NULL;

	if (sync_to_index && ret > 0) {
		/* make sure we did everything right. note that although the
		   message counts should be equal, the flag counters may not */
		i_assert(hdr.messages_count == (*map)->hdr.messages_count);
		i_assert(hdr.log_file_seq == (*map)->hdr.log_file_seq);
		i_assert(hdr.log_file_int_offset == (*map)->hdr.log_file_int_offset);
		i_assert(hdr.log_file_ext_offset == (*map)->hdr.log_file_ext_offset);
	}

	return ret;
}

static int mail_index_read_map_with_retry(struct mail_index *index,
					  struct mail_index_map **map,
					  bool sync_to_index)
{
	mail_index_sync_lost_handler_t *const *handlers;
	unsigned int i, count;
	int ret;
	bool retry;

	if (index->log_locked) {
		/* we're most likely syncing the index and we really don't
		   want to read more than what was synced last time. */
		sync_to_index = TRUE;
	}

	if ((*map)->hdr.indexid != 0 && index->log != NULL) {
		/* we're not creating the index, or opening transaction log.
		   sync this as a view from transaction log. */
		index->sync_update = TRUE;
		ret = mail_index_sync_from_transactions(index, map,
							sync_to_index);
		index->sync_update = FALSE;
		if (ret != 0)
			return ret;

		/* transaction log lost/broken, fallback to re-reading it */
	}

	/* notify all "sync lost" handlers */
	handlers = array_get(&index->sync_lost_handlers, &count);
	for (i = 0; i < count; i++)
		(*handlers[i])(index);

	for (i = 0;; i++) {
		ret = mail_index_read_map(index, *map, &retry,
					  i < MAIL_INDEX_ESTALE_RETRY_COUNT);
		if (ret != 0 || !retry)
			return ret;

		/* ESTALE - reopen index file */
                if (close(index->fd) < 0)
			mail_index_set_syscall_error(index, "close()");
		index->fd = -1;

                ret = mail_index_try_open_only(index);
		if (ret <= 0) {
			if (ret == 0) {
				/* the file was lost */
				errno = ENOENT;
				mail_index_set_syscall_error(index, "open()");
			}
			return -1;
		}
	}
}

static int mail_index_map_try_existing(struct mail_index *index)
{
	struct mail_index_map *map = index->map;
	const struct mail_index_header *hdr;
	size_t used_size;
	int ret;

	if (MAIL_INDEX_MAP_IS_IN_MEMORY(map))
		return 0;

	hdr = map->mmap_base;

	/* always check corrupted-flag to avoid errors later */
	if ((hdr->flags & MAIL_INDEX_HDR_FLAG_CORRUPTED) != 0)
		return -1;

	used_size = hdr->header_size + hdr->messages_count * hdr->record_size;
	if (map->mmap_size >= used_size && map->hdr_base == hdr) {
		map->records_count = hdr->messages_count;
		mail_index_map_copy_hdr(map, hdr);

		/* make sure the header is still valid. it also re-parses
		   extensions although they shouldn't change without the whole
		   index being recreated */
		ret = mail_index_check_header(index, map);
		if (ret > 0)
			return 1;
		/* broken. fallback to re-mmaping which will catch it */
	}
	return 0;
}

int mail_index_map(struct mail_index *index, bool force)
{
	struct mail_index_map *map;
	int ret;

	i_assert(!index->mapping);
	i_assert(index->map == NULL || index->map->refcount > 0);
	i_assert(index->lock_type != F_UNLCK);

	if (MAIL_INDEX_IS_IN_MEMORY(index)) {
		if (index->map == NULL)
			mail_index_create_in_memory(index, NULL);
		return 1;
	}

	index->mapping = TRUE;

	if (!force && index->map != NULL) {
		i_assert(index->hdr != NULL);
		ret = mail_index_map_try_existing(index);
		if (ret != 0) {
			index->mapping = FALSE;
			return ret;
		}

		if (index->lock_type == F_WRLCK) {
			/* we're syncing, don't break the mapping */
			index->mapping = FALSE;
			return 1;
		}
	}

	if (index->map != NULL && index->map->refcount > 1) {
		/* this map is already used by some views and they may have
		   pointers into it. leave them and create a new mapping. */
		if (!index->mmap_disable) {
			map = NULL;
		} else {
			/* create a copy of the mapping instead so we don't
			   have to re-read it */
			map = mail_index_map_clone(index->map,
						   index->map->hdr.record_size);
		}
		index->map->refcount--;
		index->map = NULL;
	} else {
		map = index->map;
	}

	if (map == NULL) {
		map = i_new(struct mail_index_map, 1);
		map->refcount = 1;
		map->hdr_copy_buf =
			buffer_create_dynamic(default_pool, sizeof(map->hdr));
	} else if (MAIL_INDEX_MAP_IS_IN_MEMORY(map)) {
		i_assert(!map->write_to_disk);
	} else if (map->mmap_base != NULL) {
		i_assert(map->buffer == NULL);
		if (munmap(map->mmap_base, map->mmap_size) < 0)
			mail_index_set_syscall_error(index, "munmap()");
		map->mmap_base = NULL;
	}

	index->hdr = NULL;
	index->map = NULL;

	if (!index->mmap_disable)
		ret = mail_index_mmap(index, map);
	else
		ret = mail_index_read_map_with_retry(index, &map, force);
	i_assert(index->map == NULL);

	if (ret > 0) {
		ret = mail_index_check_header(index, map);
		if (ret < 0)
			ret = 0;
		else if (ret == 0) {
			index->fsck = TRUE;
			ret = 1;
		}
	}

	if (ret <= 0) {
		mail_index_map_clear(index, map);
		mail_index_unmap(index, &map);
		index->mapping = FALSE;
		return ret;
	}

	index->hdr = &map->hdr;
	index->map = map;
	i_assert(map->hdr.messages_count == map->records_count);
	index->mapping = FALSE;
	return 1;
}

int mail_index_get_latest_header(struct mail_index *index,
				 struct mail_index_header *hdr_r)
{
	size_t pos;
	unsigned int i;
	int ret;

	if (MAIL_INDEX_IS_IN_MEMORY(index)) {
		*hdr_r = *index->hdr;
		return TRUE;
	}

	if (!index->mmap_disable) {
		ret = mail_index_map(index, FALSE);
		if (ret > 0)
			*hdr_r = *index->hdr;
		else
			memset(hdr_r, 0, sizeof(*hdr_r));
		return ret;
	}

	for (i = 0;; i++) {
		ret = mail_index_read_header(index, hdr_r, sizeof(*hdr_r),
					     &pos);
		if (ret <= 0 || errno != ESTALE ||
		    i == MAIL_INDEX_ESTALE_RETRY_COUNT)
			break;

		/* ESTALE - reopen index file */
                if (close(index->fd) < 0)
			mail_index_set_syscall_error(index, "close()");
		index->fd = -1;

		ret = mail_index_try_open_only(index);
		if (ret <= 0) {
			if (ret == 0) {
				/* the file was lost */
				errno = ENOENT;
				mail_index_set_syscall_error(index, "open()");
			}
			return -1;
		}
	}

	if (ret < 0)
		mail_index_set_syscall_error(index, "pread_full()");
	return ret;
}

struct mail_index_map *
mail_index_map_clone(const struct mail_index_map *map, uint32_t new_record_size)
{
	struct mail_index_map *mem_map;
	struct mail_index_header *hdr;
	struct mail_index_ext *extensions;
	void *src, *dest;
	size_t size, copy_size;
	unsigned int i, count;

        size = map->records_count * new_record_size;

	mem_map = i_new(struct mail_index_map, 1);
	mem_map->refcount = 1;
	mem_map->buffer = buffer_create_dynamic(default_pool, size);
	if (map->hdr.record_size == new_record_size)
		buffer_append(mem_map->buffer, map->records, size);
	else {
		copy_size = I_MIN(map->hdr.record_size, new_record_size);
		src = map->records;
		for (i = 0; i < map->records_count; i++) {
			dest = buffer_append_space_unsafe(mem_map->buffer,
							  new_record_size);
			memcpy(dest, src, copy_size);
			src = PTR_OFFSET(src, map->hdr.record_size);
		}
	}

	mem_map->records = buffer_get_modifiable_data(mem_map->buffer, NULL);
	mem_map->records_count = map->records_count;

	mem_map->hdr_copy_buf =
		buffer_create_dynamic(default_pool, map->hdr.header_size);
	if (map->hdr.base_header_size < sizeof(*hdr))
		buffer_append_zero(mem_map->hdr_copy_buf, sizeof(*hdr));
	buffer_write(mem_map->hdr_copy_buf, 0,
		     &map->hdr, map->hdr.base_header_size);
	buffer_append(mem_map->hdr_copy_buf,
		      CONST_PTR_OFFSET(map->hdr_base,
				       map->hdr.base_header_size),
		      map->hdr.header_size - map->hdr.base_header_size);

	hdr = buffer_get_modifiable_data(mem_map->hdr_copy_buf, NULL);
	if (hdr->base_header_size < sizeof(*hdr))
		hdr->base_header_size = sizeof(*hdr);
	hdr->record_size = new_record_size;
	mem_map->hdr = *hdr;
	mem_map->hdr_base = hdr;

	/* if we're syncing transaction log into memory and later use the
	   mapping for updating the index, we need to remember what has
	   changed */
	mem_map->write_atomic = map->write_atomic;
	if (map->write_to_disk) {
		mem_map->write_seq_first = map->write_seq_first;
		mem_map->write_seq_last = map->write_seq_last;
	}

	/* copy extensions */
	if (array_is_created(&map->ext_id_map)) {
		count = array_count(&map->ext_id_map);
		mail_index_map_init_extbufs(mem_map, count + 2);

		array_append_array(&mem_map->extensions, &map->extensions);
		array_append_array(&mem_map->ext_id_map, &map->ext_id_map);

		/* fix the name pointers to use our own pool */
		extensions = array_get_modifiable(&mem_map->extensions, &count);
		for (i = 0; i < count; i++) {
			i_assert(extensions[i].record_offset +
				 extensions[i].record_size <= hdr->record_size);
			extensions[i].name = p_strdup(mem_map->extension_pool,
						      extensions[i].name);
		}
	}

	return mem_map;
}

int mail_index_map_get_ext_idx(struct mail_index_map *map,
			       uint32_t ext_id, uint32_t *idx_r)
{
	const uint32_t *id;

	if (!array_is_created(&map->ext_id_map) ||
	    ext_id >= array_count(&map->ext_id_map))
		return 0;

	id = array_idx(&map->ext_id_map, ext_id);
	*idx_r = *id;
	return *idx_r != (uint32_t)-1;
}

static int mail_index_try_open_only(struct mail_index *index)
{
	i_assert(!MAIL_INDEX_IS_IN_MEMORY(index));

        /* Note that our caller must close index->fd by itself.
           mail_index_reopen() for example wants to revert back to old
           index file if opening the new one fails. */
	index->fd = nfs_safe_open(index->filepath, O_RDWR);
	index->readonly = FALSE;

	if (index->fd == -1 && errno == EACCES) {
		index->fd = open(index->filepath, O_RDONLY);
		index->readonly = TRUE;
	}

	if (index->fd == -1) {
		if (errno != ENOENT)
			return mail_index_set_syscall_error(index, "open()");

		/* have to create it */
		return 0;
	}
	return 1;
}

static int
mail_index_try_open(struct mail_index *index, unsigned int *lock_id_r)
{
	unsigned int lock_id;
	int ret;

        i_assert(index->fd == -1);
	i_assert(index->lock_type == F_UNLCK);

	if (lock_id_r != NULL)
		*lock_id_r = 0;

	if (MAIL_INDEX_IS_IN_MEMORY(index))
		return 0;

	ret = mail_index_try_open_only(index);
	if (ret <= 0)
		return ret;

	if (mail_index_lock_shared(index, FALSE, &lock_id) < 0) {
		(void)close(index->fd);
		index->fd = -1;
		return -1;
	}
	ret = mail_index_map(index, FALSE);
	if (ret == 0) {
		/* it's corrupted - recreate it */
		mail_index_unlock(index, lock_id);
		if (lock_id_r != NULL)
			*lock_id_r = 0;

		i_assert(index->file_lock == NULL);
		(void)close(index->fd);
		index->fd = -1;
	} else {
		if (lock_id_r != NULL)
			*lock_id_r = lock_id;
		else
			mail_index_unlock(index, lock_id);
	}
	return ret;
}

int mail_index_write_base_header(struct mail_index *index,
				 const struct mail_index_header *hdr)
{
	size_t hdr_size;

	hdr_size = I_MIN(sizeof(*hdr), hdr->base_header_size);

	if (!MAIL_INDEX_MAP_IS_IN_MEMORY(index->map)) {
		memcpy(index->map->mmap_base, hdr, hdr_size);
		if (msync(index->map->mmap_base, hdr_size, MS_SYNC) < 0)
			return mail_index_set_syscall_error(index, "msync()");
		index->map->hdr = *hdr;
	} else {
		if (!MAIL_INDEX_IS_IN_MEMORY(index)) {
			if (pwrite_full(index->fd, hdr, hdr_size, 0) < 0) {
				mail_index_set_syscall_error(index,
							     "pwrite_full()");
				return -1;
			}
		}

		index->map->hdr = *hdr;
		buffer_write(index->map->hdr_copy_buf, 0, hdr, hdr_size);
	}

	return 0;
}

int mail_index_create_tmp_file(struct mail_index *index, const char **path_r)
{
        mode_t old_mask;
	const char *path;
	int fd;

	i_assert(!MAIL_INDEX_IS_IN_MEMORY(index));

	path = *path_r = t_strconcat(index->filepath, ".tmp", NULL);
	old_mask = umask(0);
	fd = open(path, O_RDWR|O_CREAT|O_TRUNC, index->mode);
	umask(old_mask);
	if (fd == -1)
		return mail_index_file_set_syscall_error(index, path, "open()");

	if (index->gid != (gid_t)-1 && fchown(fd, (uid_t)-1, index->gid) < 0) {
		mail_index_file_set_syscall_error(index, path, "fchown()");
		return -1;
	}

	return fd;
}

static int mail_index_create(struct mail_index *index,
			     struct mail_index_header *hdr)
{
	const char *path;
	uint32_t seq;
	uoff_t offset;
	int ret;

	i_assert(!MAIL_INDEX_IS_IN_MEMORY(index));
	i_assert(index->lock_type == F_UNLCK);

	/* log file lock protects index creation */
	if (mail_transaction_log_sync_lock(index->log, &seq, &offset) < 0)
		return -1;

	ret = mail_index_try_open(index, NULL);
	if (ret != 0) {
		mail_transaction_log_sync_unlock(index->log);
		return ret < 0 ? -1 : 0;
	}

	/* mark the existing log file as synced */
	hdr->log_file_seq = seq;
	hdr->log_file_int_offset = offset;
	hdr->log_file_ext_offset = offset;

	/* create it fully in index.tmp first */
	index->fd = mail_index_create_tmp_file(index, &path);
	if (index->fd == -1)
		ret = -1;
	else if (write_full(index->fd, hdr, sizeof(*hdr)) < 0) {
		mail_index_file_set_syscall_error(index, path, "write_full()");
		ret = -1;
	} else {
		index->lock_type = F_WRLCK;
		ret = mail_index_map(index, FALSE);
		index->lock_type = F_UNLCK;
	}

	if (ret == 0) {
		/* it's corrupted even while we just created it,
		   should never happen unless someone pokes the file directly */
		mail_index_set_error(index,
			"Newly created index file is corrupted: %s", path);
		ret = -1;
	}

	if (ret < 0) {
		if (unlink(path) < 0 && errno != ENOENT) {
			mail_index_file_set_syscall_error(index, path,
							  "unlink()");
		}
	} else {
		/* make it visible to others */
		if (rename(path, index->filepath) < 0) {
			mail_index_set_error(index, "rename(%s, %s) failed: %m",
					     path, index->filepath);
			ret = -1;
		}
	}

	mail_transaction_log_sync_unlock(index->log);
	return ret;
}

static void mail_index_header_init(struct mail_index_header *hdr)
{
	time_t now = time(NULL);

	i_assert((sizeof(*hdr) % sizeof(uint64_t)) == 0);

	memset(hdr, 0, sizeof(*hdr));

	hdr->major_version = MAIL_INDEX_MAJOR_VERSION;
	hdr->minor_version = MAIL_INDEX_MINOR_VERSION;
	hdr->base_header_size = sizeof(*hdr);
	hdr->header_size = sizeof(*hdr);
	hdr->record_size = sizeof(struct mail_index_record);

#ifndef WORDS_BIGENDIAN
	hdr->compat_flags |= MAIL_INDEX_COMPAT_LITTLE_ENDIAN;
#endif

	hdr->indexid = now;

	hdr->next_uid = 1;
}

static void mail_index_create_in_memory(struct mail_index *index,
					const struct mail_index_header *hdr)
{
        struct mail_index_header tmp_hdr;
	struct mail_index_map tmp_map;

	if (hdr == NULL) {
		mail_index_header_init(&tmp_hdr);
		hdr = &tmp_hdr;
	}

	memset(&tmp_map, 0, sizeof(tmp_map));
	tmp_map.hdr = *hdr;
	tmp_map.hdr_base = hdr;

	/* a bit kludgy way to do this, but it initializes everything
	   nicely and correctly */
	index->map = mail_index_map_clone(&tmp_map, hdr->record_size);
	index->hdr = &index->map->hdr;
}

/* returns -1 = error, 0 = won't create, 1 = ok */
static int mail_index_open_files(struct mail_index *index,
				 enum mail_index_open_flags flags)
{
	struct mail_index_header hdr;
	unsigned int lock_id = 0;
	int ret;
	bool create = FALSE, created = FALSE;

	ret = mail_index_try_open(index, &lock_id);
	if (ret > 0)
		hdr = *index->hdr;
	else if (ret == 0) {
		/* doesn't exist, or corrupted */
		if ((flags & MAIL_INDEX_OPEN_FLAG_CREATE) == 0 &&
		    !MAIL_INDEX_IS_IN_MEMORY(index))
			return 0;
		mail_index_header_init(&hdr);
		index->hdr = &hdr;
		create = TRUE;
	} else if (ret < 0)
		return -1;

	index->indexid = hdr.indexid;

	index->log = create ?
		mail_transaction_log_create(index) :
		mail_transaction_log_open_or_create(index);
	if (index->log == NULL) {
		if (ret == 0)
			index->hdr = NULL;
		return -1;
	}

	if (index->fd == -1) {
		mail_index_header_init(&hdr);
		index->hdr = &hdr;

		/* index->indexid may be updated by transaction log opening,
		   in case someone else had already created a new log file */
		hdr.indexid = index->indexid;

		if (lock_id != 0) {
			mail_index_unlock(index, lock_id);
			lock_id = 0;
		}

		if (!MAIL_INDEX_IS_IN_MEMORY(index)) {
			if (mail_index_create(index, &hdr) < 0) {
				/* fallback to in-memory index */
				mail_index_move_to_memory(index);
				mail_index_create_in_memory(index, &hdr);
			}
		} else {
			mail_index_create_in_memory(index, &hdr);
		}
		created = TRUE;
	}
	i_assert(index->hdr != &hdr);

	if (lock_id == 0) {
		if (mail_index_lock_shared(index, FALSE, &lock_id) < 0)
			return -1;

	}

	index->cache = created ? mail_cache_create(index) :
		mail_cache_open_or_create(index);

	mail_index_unlock(index, lock_id);
	return 1;
}

int mail_index_open(struct mail_index *index, enum mail_index_open_flags flags,
		    enum file_lock_method lock_method)
{
	int i = 0, ret;

	if (index->opened) {
		if (index->hdr != NULL &&
		    (index->hdr->flags & MAIL_INDEX_HDR_FLAG_CORRUPTED) != 0) {
			/* corrupted, reopen files */
                        mail_index_close(index);
		} else {
			return 1;
		}
	}

	index->filepath = MAIL_INDEX_IS_IN_MEMORY(index) ?
		i_strdup("(in-memory index)") :
		i_strconcat(index->dir, "/", index->prefix, NULL);

	for (;;) {
		index->shared_lock_count = 0;
		index->excl_lock_count = 0;
		index->lock_type = F_UNLCK;
		index->lock_id = 2;

		index->readonly = FALSE;
		index->nodiskspace = FALSE;
		index->index_lock_timeout = FALSE;
		index->log_locked = FALSE;
		index->mmap_disable =
			(flags & MAIL_INDEX_OPEN_FLAG_MMAP_DISABLE) != 0;
		index->mmap_no_write =
			(flags & MAIL_INDEX_OPEN_FLAG_MMAP_NO_WRITE) != 0;
		index->use_excl_dotlocks =
			(flags & MAIL_INDEX_OPEN_FLAG_DOTLOCK_USE_EXCL) != 0;
		index->fsync_disable =
			(flags & MAIL_INDEX_OPEN_FLAG_FSYNC_DISABLE) != 0;
		index->lock_method = lock_method;

		/* don't even bother to handle dotlocking without mmap being
		   disabled. that combination simply doesn't make any sense */
		if (lock_method == FILE_LOCK_METHOD_DOTLOCK &&
		    !index->mmap_disable) {
			i_fatal("lock_method=dotlock and mmap_disable=no "
				"combination isn't supported. "
				"You don't _really_ want it anyway.");
		}

		ret = mail_index_open_files(index, flags);
		if (ret <= 0)
			break;

		index->opened = TRUE;
		if (index->fsck) {
			index->fsck = FALSE;
			ret = mail_index_fsck(index);
			if (ret == 0) {
				/* completely broken, reopen */
				if (i++ < 3)
					continue;
				/* too many tries */
				ret = -1;
			}
		}
		break;
	}

	if (ret <= 0)
		mail_index_close(index);

	return ret;
}

void mail_index_close(struct mail_index *index)
{
	if (index->log != NULL)
		mail_transaction_log_close(&index->log);
	if (index->map != NULL)
		mail_index_unmap(index, &index->map);
	if (index->cache != NULL)
		mail_cache_free(&index->cache);
	if (index->file_lock != NULL)
		file_lock_free(&index->file_lock);

	if (index->fd != -1) {
		if (close(index->fd) < 0)
			mail_index_set_syscall_error(index, "close()");
		index->fd = -1;
	}

	i_free_and_null(index->copy_lock_path);
	i_free_and_null(index->filepath);

	index->indexid = 0;
	index->opened = FALSE;
}

int mail_index_reopen(struct mail_index *index, int fd)
{
	struct mail_index_map *old_map;
	struct file_lock *old_file_lock;
	unsigned int old_shared_locks, old_lock_id, lock_id = 0;
	int ret, old_fd, old_lock_type;

	i_assert(!MAIL_INDEX_IS_IN_MEMORY(index));
	i_assert(index->excl_lock_count == 0);

	old_map = index->map;
	old_fd = index->fd;
	old_map->refcount++;

	/* new file, new locks. the old fd can keep its locks, they don't
	   matter anymore as no-one's going to modify the file. */
	old_lock_type = index->lock_type;
	old_lock_id = index->lock_id;
	old_shared_locks = index->shared_lock_count;
	old_file_lock = index->file_lock;

	if (index->lock_type == F_RDLCK)
		index->lock_type = F_UNLCK;
	index->lock_id += 2;
	index->shared_lock_count = 0;
	index->file_lock = NULL;

	if (fd != -1) {
		index->fd = fd;
		ret = 0;
	} else {
		ret = mail_index_try_open_only(index);
		if (ret > 0)
			ret = mail_index_lock_shared(index, FALSE, &lock_id);
		else if (ret == 0) {
			/* index file is lost */
			ret = -1;
		}
	}

	if (ret == 0) {
		/* read the new mapping. note that with mmap_disable we want
		   to keep the old mapping in index->map so we can update it
		   by reading transaction log. */
		if (mail_index_map(index, TRUE) <= 0)
			ret = -1;
	}

	if (lock_id != 0)
		mail_index_unlock(index, lock_id);

	if (ret == 0) {
		mail_index_unmap(index, &old_map);
		if (old_file_lock != NULL)
			file_lock_free(&old_file_lock);
		if (close(old_fd) < 0)
			mail_index_set_syscall_error(index, "close()");
	} else {
		if (index->map != NULL)
			mail_index_unmap(index, &index->map);

		if (index->fd != -1) {
			if (close(index->fd) < 0)
				mail_index_set_syscall_error(index, "close()");
		}

		index->map = old_map;
		index->hdr = &index->map->hdr;
		index->fd = old_fd;
		index->file_lock = old_file_lock;
		index->lock_type = old_lock_type;
		index->lock_id = old_lock_id;
		index->shared_lock_count = old_shared_locks;
	}
	return ret;
}

int mail_index_reopen_if_needed(struct mail_index *index)
{
	struct stat st1, st2;

        i_assert(index->copy_lock_path == NULL);

	if (MAIL_INDEX_IS_IN_MEMORY(index))
		return 0;

	if (fstat(index->fd, &st1) < 0) {
		if (errno == ESTALE) {
			/* deleted, reopen */
			if (mail_index_reopen(index, -1) < 0)
				return -1;
			return 1;
		}
		return mail_index_set_syscall_error(index, "fstat()");
	}
	if (nfs_safe_stat(index->filepath, &st2) < 0) {
		mail_index_set_syscall_error(index, "stat()");
		if (errno != ENOENT)
			return -1;

		/* lost it? recreate later */
		mail_index_mark_corrupted(index);
		return -1;
	}

	if (st1.st_ino != st2.st_ino ||
	    !CMP_DEV_T(st1.st_dev, st2.st_dev)) {
		if (mail_index_reopen(index, -1) < 0)
			return -1;
		return 1;
	} else {
		return 0;
	}
}

int mail_index_refresh(struct mail_index *index)
{
	unsigned int lock_id;
	int ret;

	if (MAIL_INDEX_IS_IN_MEMORY(index))
		return 0;

	if (index->excl_lock_count > 0) {
		/* we have index exclusively locked, nothing could
		   have changed. */
		return 0;
	}

	if (!index->mmap_disable) {
		/* reopening is all we need */
		return mail_index_reopen_if_needed(index);
	}

	i_assert(!index->mapping);

	/* mail_index_map() simply reads latest changes from transaction log,
	   which makes us fully refreshed. */
	if (mail_index_lock_shared(index, TRUE, &lock_id) < 0)
		return -1;

	ret = mail_index_map(index, FALSE);
	mail_index_unlock(index, lock_id);
	return ret <= 0 ? -1 : 0;
}

struct mail_cache *mail_index_get_cache(struct mail_index *index)
{
	return index->cache;
}

int mail_index_set_error(struct mail_index *index, const char *fmt, ...)
{
	va_list va;

	i_free(index->error);

	if (fmt == NULL)
		index->error = NULL;
	else {
		va_start(va, fmt);
		index->error = i_strdup_vprintf(fmt, va);
		va_end(va);

		i_error("%s", index->error);
	}

	return -1;
}

void mail_index_set_inconsistent(struct mail_index *index)
{
	index->indexid = 0;
}

int mail_index_move_to_memory(struct mail_index *index)
{
	struct mail_index_map *map;
	int ret = 0;

	if (MAIL_INDEX_IS_IN_MEMORY(index))
		return 0;

	/* set the index as being into memory */
	i_free_and_null(index->dir);

	if (index->map == NULL) {
		/* index was never even opened. just mark it as being in
		   memory and let the caller re-open the index. */
		i_assert(index->fd == -1);
		return -1;
	}

	/* move index map to memory */
	map = mail_index_map_clone(index->map, index->map->hdr.record_size);
	mail_index_unmap(index, &index->map);
	index->map = map;
	index->hdr = &map->hdr;

	if (index->log != NULL) {
		/* move transaction log to memory */
		if (mail_transaction_log_move_to_memory(index->log) < 0)
			ret = -1;
	}

	if (index->file_lock != NULL)
		file_lock_free(&index->file_lock);

	/* close the index file. */
	if (close(index->fd) < 0)
		mail_index_set_syscall_error(index, "close()");
	index->fd = -1;

	return ret;
}

void mail_index_mark_corrupted(struct mail_index *index)
{
	struct mail_index_header hdr;

	mail_index_set_inconsistent(index);

	if (index->readonly || index->map == NULL)
		return;

	hdr = *index->hdr;
	hdr.flags |= MAIL_INDEX_HDR_FLAG_CORRUPTED;
	if (mail_index_write_base_header(index, &hdr) == 0) {
		if (!MAIL_INDEX_IS_IN_MEMORY(index) && fsync(index->fd) < 0)
			mail_index_set_syscall_error(index, "fsync()");
	}
}

int mail_index_set_syscall_error(struct mail_index *index,
				 const char *function)
{
	i_assert(function != NULL);

	if (ENOSPACE(errno)) {
		index->nodiskspace = TRUE;
		return -1;
	}

	return mail_index_set_error(index, "%s failed with index file %s: %m",
				    function, index->filepath);
}

int mail_index_file_set_syscall_error(struct mail_index *index,
				      const char *filepath,
				      const char *function)
{
	i_assert(filepath != NULL);
	i_assert(function != NULL);

	if (ENOSPACE(errno)) {
		index->nodiskspace = TRUE;
		return -1;
	}

	return mail_index_set_error(index, "%s failed with file %s: %m",
				    function, filepath);
}

enum mail_index_error mail_index_get_last_error(struct mail_index *index)
{
	if (index->nodiskspace)
		return MAIL_INDEX_ERROR_DISKSPACE;
	if (index->error != NULL)
		return MAIL_INDEX_ERROR_INTERNAL;

	return MAIL_INDEX_ERROR_NONE;
}

const char *mail_index_get_error_message(struct mail_index *index)
{
	return index->error;
}

void mail_index_reset_error(struct mail_index *index)
{
	if (index->error != NULL) {
		i_free(index->error);
		index->error = NULL;
	}

	index->nodiskspace = FALSE;
        index->index_lock_timeout = FALSE;
}

uint32_t mail_index_uint32_to_offset(uint32_t offset)
{
	unsigned char buf[4];

	i_assert(offset < 0x40000000);
	i_assert((offset & 3) == 0);

	offset >>= 2;
	buf[0] = 0x80 | ((offset & 0x0fe00000) >> 21);
	buf[1] = 0x80 | ((offset & 0x001fc000) >> 14);
	buf[2] = 0x80 | ((offset & 0x00003f80) >> 7);
	buf[3] = 0x80 |  (offset & 0x0000007f);
	return *((uint32_t *) buf);
}

uint32_t mail_index_offset_to_uint32(uint32_t offset)
{
	const unsigned char *buf = (const unsigned char *) &offset;

	if ((offset & 0x80808080) != 0x80808080)
		return 0;

	return (((uint32_t)buf[3] & 0x7f) << 2) |
		(((uint32_t)buf[2] & 0x7f) << 9) |
		(((uint32_t)buf[1] & 0x7f) << 16) |
		(((uint32_t)buf[0] & 0x7f) << 23);
}
