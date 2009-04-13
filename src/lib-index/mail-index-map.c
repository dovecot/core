/* Copyright (c) 2003-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str-sanitize.h"
#include "nfs-workarounds.h"
#include "mmap-util.h"
#include "read-full.h"
#include "mail-index-private.h"
#include "mail-index-sync-private.h"
#include "mail-index-modseq.h"
#include "mail-transaction-log-private.h"

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
			pool_alloconly_create(MEMPOOL_GROWING"map extensions",
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

bool mail_index_map_lookup_ext(struct mail_index_map *map, const char *name,
			       uint32_t *idx_r)
{
	const struct mail_index_ext *extensions;
	unsigned int i, size;

	if (array_is_created(&map->extensions)) {
		extensions = array_get(&map->extensions, &size);
		for (i = 0; i < size; i++) {
			if (strcmp(extensions[i].name, name) == 0) {
				if (idx_r != NULL)
					*idx_r = i;
				return TRUE;
			}
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
	uint32_t idx, empty_idx = (uint32_t)-1;

	if (!array_is_created(&map->extensions)) {
                mail_index_map_init_extbufs(map, 5);
		idx = 0;
	} else {
		idx = array_count(&map->extensions);
	}
	i_assert(!mail_index_map_lookup_ext(map, name, NULL));

	ext = array_append_space(&map->extensions);
	ext->name = p_strdup(map->extension_pool, name);
	ext->ext_offset = ext_offset;
	ext->hdr_offset = ext_offset +
		mail_index_map_ext_hdr_offset(strlen(name));
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
		array_append(&map->ext_id_map, &empty_idx, 1);
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

int mail_index_map_ext_hdr_check(const struct mail_index_header *hdr,
				 const struct mail_index_ext_header *ext_hdr,
				 const char *name, const char **error_r)
{
	if ((ext_hdr->record_size == 0 && ext_hdr->hdr_size == 0) ||
	    (ext_hdr->record_align == 0 && ext_hdr->record_size != 0)) {
		*error_r = "Invalid field values";
		return -1;
	}
	if (*name == '\0') {
		*error_r = "Broken name";
		return -1;
	}

	/* if we get here from extension introduction, record_offset=0 and
	   hdr->record_size hasn't been updated yet */
	if (ext_hdr->record_offset != 0 &&
	    ext_hdr->record_offset + ext_hdr->record_size > hdr->record_size) {
		*error_r = t_strdup_printf("Record field points "
					   "outside record size (%u+%u > %u)",
					   ext_hdr->record_offset,
					   ext_hdr->record_size,
					   hdr->record_size);
		return -1;
	}

	if (ext_hdr->record_size > 0 &&
	    (ext_hdr->record_offset % ext_hdr->record_align) != 0) {
		*error_r = t_strdup_printf("Record field alignment %u "
					   "not used", ext_hdr->record_align);
		return -1;
	}
	if (ext_hdr->record_offset != 0 &&
	    (hdr->record_size % ext_hdr->record_align) != 0) {
		*error_r = t_strdup_printf("Record size not aligned by %u "
					   "as required by extension",
					   ext_hdr->record_align);
		return -1;
	}
	if (ext_hdr->hdr_size > MAIL_INDEX_EXT_HEADER_MAX_SIZE) {
		*error_r = t_strdup_printf("Headersize too large (%u)",
					   ext_hdr->hdr_size);
		return -1;
	}
	return 0;
}

static int mail_index_map_parse_extensions(struct mail_index_map *map)
{
	struct mail_index *index = map->index;
	const struct mail_index_ext_header *ext_hdr;
	unsigned int i, old_count, offset;
	const char *name, *error;
	uint32_t ext_id, ext_offset;

	/* extension headers always start from 64bit offsets, so if base header
	   doesn't happen to be 64bit aligned we'll skip some bytes */
	offset = MAIL_INDEX_HEADER_SIZE_ALIGN(map->hdr.base_header_size);
	if (offset >= map->hdr.header_size && map->extension_pool == NULL) {
		/* nothing to do, skip allocatations and all */
		return 0;
	}

	old_count = array_count(&index->extensions);
	mail_index_map_init_extbufs(map, old_count + 5);

	ext_id = (uint32_t)-1;
	for (i = 0; i < old_count; i++)
		array_append(&map->ext_id_map, &ext_id, 1);

	for (i = 0; offset < map->hdr.header_size; i++) {
		ext_offset = offset;

		if (mail_index_map_ext_get_next(map, &offset,
						&ext_hdr, &name) < 0) {
			mail_index_set_error(index, "Corrupted index file %s: "
				"Header extension #%d (%s) goes outside header",
				index->filepath, i, name);
			return -1;
		}

		if (mail_index_map_ext_hdr_check(&map->hdr, ext_hdr,
						 name, &error) < 0) {
			mail_index_set_error(index, "Corrupted index file %s: "
					     "Broken extension #%d (%s): %s",
					     index->filepath, i, name, error);
			return -1;
		}
		if (mail_index_map_lookup_ext(map, name, NULL)) {
			mail_index_set_error(index, "Corrupted index file %s: "
				"Duplicate header extension %s",
				index->filepath, name);
			return -1;
		}

		mail_index_map_register_ext(map, name, ext_offset, ext_hdr);
	}
	return 0;
}

int mail_index_map_parse_keywords(struct mail_index_map *map)
{
	struct mail_index *index = map->index;
	const struct mail_index_ext *ext;
	const struct mail_index_keyword_header *kw_hdr;
	const struct mail_index_keyword_header_rec *kw_rec;
	const char *name;
	unsigned int i, name_area_end_offset, old_count;
	uint32_t idx;

	if (!mail_index_map_lookup_ext(map, MAIL_INDEX_EXT_KEYWORDS, &idx)) {
		if (array_is_created(&map->keyword_idx_map))
			array_clear(&map->keyword_idx_map);
		return 0;
	}
	ext = array_idx(&map->extensions, idx);

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
		unsigned int kw_idx;

		old_idx = array_idx(&map->keyword_idx_map, i);
		if (!mail_index_keyword_lookup(index, keyword, &kw_idx) ||
		    kw_idx != *old_idx) {
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
		unsigned int kw_idx;

		if (*keyword == '\0') {
			mail_index_set_error(index, "Corrupted index file %s: "
				"Empty keyword name in header",
				index->filepath);
			return -1;
		}
		mail_index_keyword_lookup_or_create(index, keyword, &kw_idx);
		array_append(&map->keyword_idx_map, &kw_idx, 1);
	}
	return 0;
}

static bool mail_index_check_header_compat(struct mail_index *index,
					   const struct mail_index_header *hdr,
					   uoff_t file_size)
{
        enum mail_index_header_compat_flags compat_flags = 0;

#if !WORDS_BIGENDIAN
	compat_flags |= MAIL_INDEX_COMPAT_LITTLE_ENDIAN;
#endif

	if (hdr->major_version != MAIL_INDEX_MAJOR_VERSION) {
		/* major version change - handle silently(?) */
		return FALSE;
	}
	if ((hdr->flags & MAIL_INDEX_HDR_FLAG_CORRUPTED) != 0) {
		/* we've already complained about it */
		return FALSE;
	}

	if (hdr->compat_flags != compat_flags) {
		/* architecture change */
		mail_index_set_error(index, "Rebuilding index file %s: "
				     "CPU architecture changed",
				     index->filepath);
		return FALSE;
	}

	if (hdr->base_header_size < MAIL_INDEX_HEADER_MIN_SIZE ||
	    hdr->header_size < hdr->base_header_size) {
		mail_index_set_error(index, "Corrupted index file %s: "
				     "Corrupted header sizes (base %u, full %u)",
				     index->filepath, hdr->base_header_size,
				     hdr->header_size);
		return FALSE;
	}
	if (hdr->header_size > file_size) {
		mail_index_set_error(index, "Corrupted index file %s: "
				     "Corrupted header size (%u > %"PRIuUOFF_T")",
				     index->filepath, hdr->header_size,
				     file_size);
		return FALSE;
	}

	if (hdr->indexid != index->indexid) {
		if (index->indexid != 0) {
			mail_index_set_error(index, "Index file %s: "
					     "indexid changed: %u -> %u",
					     index->filepath, index->indexid,
					     hdr->indexid);
		}
		index->indexid = hdr->indexid;
		mail_transaction_log_indexid_changed(index->log);
	}

	return TRUE;
}

static void mail_index_map_clear_recent_flags(struct mail_index_map *map)
{
	struct mail_index_record *rec;
	unsigned int i;

	for (i = 0; i < map->hdr.messages_count; i++) {
		rec = MAIL_INDEX_MAP_IDX(map, i);
		rec->flags &= ~MAIL_RECENT;
	}
}

int mail_index_map_check_header(struct mail_index_map *map)
{
	struct mail_index *index = map->index;
	const struct mail_index_header *hdr = &map->hdr;

	if (!mail_index_check_header_compat(index, hdr, (uoff_t)-1))
		return -1;

	/* following some extra checks that only take a bit of CPU */
	if (hdr->record_size < sizeof(struct mail_index_record)) {
		mail_index_set_error(index, "Corrupted index file %s: "
				     "record_size too small: %u < %"PRIuSIZE_T,
				     index->filepath, hdr->record_size,
				     sizeof(struct mail_index_record));
		return -1;
	}

	if (hdr->uid_validity == 0 && hdr->next_uid != 1)
		return 0;
	if (hdr->next_uid == 0)
		return 0;
	if (hdr->messages_count > map->rec_map->records_count)
		return 0;

	if (hdr->seen_messages_count > hdr->messages_count ||
	    hdr->deleted_messages_count > hdr->messages_count)
		return 0;
	switch (hdr->minor_version) {
	case 0:
		/* upgrade silently from v1.0 */
		map->hdr.unused_old_recent_messages_count = 0;
		if (hdr->first_recent_uid == 0)
			map->hdr.first_recent_uid = 1;
		index->need_recreate = TRUE;
		/* fall through */
	case 1:
		/* pre-v1.1.rc6: make sure the \Recent flags are gone */
		mail_index_map_clear_recent_flags(map);
		map->hdr.minor_version = MAIL_INDEX_MINOR_VERSION;
	}
	if (hdr->first_recent_uid == 0 ||
	    hdr->first_recent_uid > hdr->next_uid ||
	    hdr->first_unseen_uid_lowwater > hdr->next_uid ||
	    hdr->first_deleted_uid_lowwater > hdr->next_uid)
		return 0;

	if (hdr->messages_count > 0) {
		/* last message's UID must be smaller than next_uid.
		   also make sure it's not zero. */
		const struct mail_index_record *rec;

		rec = MAIL_INDEX_MAP_IDX(map, hdr->messages_count-1);
		if (rec->uid == 0 || rec->uid >= hdr->next_uid)
			return 0;
	}

	return 1;
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

	/* FIXME: backwards compatibility, remove later. In case this index is
	   accessed with Dovecot v1.0, avoid recent message counter errors. */
	map->hdr.unused_old_recent_messages_count = 0;
}

static int mail_index_mmap(struct mail_index_map *map, uoff_t file_size)
{
	struct mail_index *index = map->index;
	struct mail_index_record_map *rec_map = map->rec_map;
	const struct mail_index_header *hdr;

	i_assert(rec_map->mmap_base == NULL);

	buffer_free(&rec_map->buffer);
	if (file_size > SSIZE_T_MAX) {
		/* too large file to map into memory */
		mail_index_set_error(index, "Index file too large: %s",
				     index->filepath);
		return -1;
	}

	rec_map->mmap_base = mmap(NULL, file_size, PROT_READ | PROT_WRITE,
				  MAP_PRIVATE, index->fd, 0);
	if (rec_map->mmap_base == MAP_FAILED) {
		rec_map->mmap_base = NULL;
		mail_index_set_syscall_error(index, "mmap()");
		return -1;
	}
	rec_map->mmap_size = file_size;

	hdr = rec_map->mmap_base;
	if (rec_map->mmap_size >
	    offsetof(struct mail_index_header, major_version) &&
	    hdr->major_version != MAIL_INDEX_MAJOR_VERSION) {
		/* major version change - handle silently */
		return 0;
	}

	if (rec_map->mmap_size < MAIL_INDEX_HEADER_MIN_SIZE) {
		mail_index_set_error(index, "Corrupted index file %s: "
				     "File too small (%"PRIuSIZE_T")",
				     index->filepath, rec_map->mmap_size);
		return 0;
	}

	if (!mail_index_check_header_compat(index, hdr, rec_map->mmap_size)) {
		/* Can't use this file */
		return 0;
	}

	rec_map->mmap_used_size = hdr->header_size +
		hdr->messages_count * hdr->record_size;

	if (rec_map->mmap_used_size <= rec_map->mmap_size)
		rec_map->records_count = hdr->messages_count;
	else {
		rec_map->records_count =
			(rec_map->mmap_size - hdr->header_size) /
			hdr->record_size;
		rec_map->mmap_used_size = hdr->header_size +
			rec_map->records_count * hdr->record_size;
		mail_index_set_error(index, "Corrupted index file %s: "
				     "messages_count too large (%u > %u)",
				     index->filepath, hdr->messages_count,
				     rec_map->records_count);
	}

	mail_index_map_copy_hdr(map, hdr);

	map->hdr_base = rec_map->mmap_base;
	rec_map->records = PTR_OFFSET(rec_map->mmap_base, map->hdr.header_size);
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
mail_index_try_read_map(struct mail_index_map *map,
			uoff_t file_size, bool *retry_r, bool try_retry)
{
	struct mail_index *index = map->index;
	const struct mail_index_header *hdr;
	unsigned char read_buf[4096];
	const void *buf;
	void *data = NULL;
	ssize_t ret;
	size_t pos, records_size, initial_buf_pos = 0;
	unsigned int records_count = 0, extra;

	i_assert(map->rec_map->mmap_base == NULL);

	*retry_r = FALSE;
	ret = mail_index_read_header(index, read_buf, sizeof(read_buf), &pos);
	buf = read_buf; hdr = buf;

	if (pos > (ssize_t)offsetof(struct mail_index_header, major_version) &&
	    hdr->major_version != MAIL_INDEX_MAJOR_VERSION) {
		/* major version change - handle silently */
		return 0;
	}

	if (ret >= 0 && pos >= MAIL_INDEX_HEADER_MIN_SIZE &&
	    (ret > 0 || pos >= hdr->base_header_size)) {
		if (!mail_index_check_header_compat(index, hdr, file_size)) {
			/* Can't use this file */
			return 0;
		}

		initial_buf_pos = pos;
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
		records_count = hdr->messages_count;

		if (file_size - hdr->header_size < records_size ||
		    (hdr->record_size != 0 &&
		     records_size / hdr->record_size != hdr->messages_count)) {
			records_count = (file_size - hdr->header_size) /
				hdr->record_size;
			records_size = (size_t)records_count * hdr->record_size;
			mail_index_set_error(index, "Corrupted index file %s: "
				"messages_count too large (%u > %u)",
				index->filepath, hdr->messages_count,
				records_count);
		}

		if (map->rec_map->buffer == NULL) {
			map->rec_map->buffer =
				buffer_create_dynamic(default_pool,
						      records_size);
		}

		/* @UNSAFE */
		buffer_set_used_size(map->rec_map->buffer, 0);
		if (initial_buf_pos <= hdr->header_size)
			extra = 0;
		else {
			extra = initial_buf_pos - hdr->header_size;
			buffer_append(map->rec_map->buffer,
				      CONST_PTR_OFFSET(buf, hdr->header_size),
				      extra);
		}
		if (records_size > extra) {
			data = buffer_append_space_unsafe(map->rec_map->buffer,
							  records_size - extra);
			ret = pread_full(index->fd, data, records_size - extra,
					 hdr->header_size + extra);
		}
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

	map->rec_map->records =
		buffer_get_modifiable_data(map->rec_map->buffer, NULL);
	map->rec_map->records_count = records_count;

	mail_index_map_copy_hdr(map, hdr);
	map->hdr_base = map->hdr_copy_buf->data;
	return 1;
}

static int mail_index_read_map(struct mail_index_map *map, uoff_t file_size,
			       unsigned int *lock_id)
{
	struct mail_index *index = map->index;
	mail_index_sync_lost_handler_t *const *handlers;
	struct stat st;
	unsigned int i, count;
	int ret;
	bool try_retry, retry;

	/* notify all "sync lost" handlers */
	handlers = array_get(&index->sync_lost_handlers, &count);
	for (i = 0; i < count; i++)
		(*handlers[i])(index);

	for (i = 0;; i++) {
		try_retry = i < MAIL_INDEX_ESTALE_RETRY_COUNT;
		if (file_size == (uoff_t)-1) {
			/* fstat() below failed */
			ret = 0;
			retry = try_retry;
		} else {
			ret = mail_index_try_read_map(map, file_size,
						      &retry, try_retry);
		}
		if (ret != 0 || !retry)
			break;

		/* ESTALE - reopen index file */
		mail_index_close_file(index);
		*lock_id = 0;

                ret = mail_index_try_open_only(index);
		if (ret <= 0) {
			if (ret == 0) {
				/* the file was lost */
				errno = ENOENT;
				mail_index_set_syscall_error(index, "open()");
			}
			return -1;
		}
		if (mail_index_lock_shared(index, lock_id) < 0)
			return -1;

		if (fstat(index->fd, &st) == 0)
			file_size = st.st_size;
		else {
			if (errno != ESTALE) {
				mail_index_set_syscall_error(index, "fstat()");
				return -1;
			}
			file_size = (uoff_t)-1;
		}
	}
	return ret;
}

static void mail_index_header_init(struct mail_index *index,
				   struct mail_index_header *hdr)
{
	i_assert((sizeof(*hdr) % sizeof(uint64_t)) == 0);

	memset(hdr, 0, sizeof(*hdr));

	hdr->major_version = MAIL_INDEX_MAJOR_VERSION;
	hdr->minor_version = MAIL_INDEX_MINOR_VERSION;
	hdr->base_header_size = sizeof(*hdr);
	hdr->header_size = sizeof(*hdr);
	hdr->record_size = sizeof(struct mail_index_record);

#if !WORDS_BIGENDIAN
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

	memset(&tmp_map, 0, sizeof(tmp_map));
	mail_index_header_init(index, &tmp_map.hdr);
	tmp_map.index = index;
	tmp_map.hdr_base = &tmp_map.hdr;

	/* a bit kludgy way to do this, but it initializes everything
	   nicely and correctly */
	return mail_index_map_clone(&tmp_map);
}

/* returns -1 = error, 0 = index files are unusable,
   1 = index files are usable or at least repairable */
static int mail_index_map_latest_file(struct mail_index *index)
{
	struct mail_index_map *old_map, *new_map;
	struct stat st;
	unsigned int lock_id;
	uoff_t file_size;
	bool use_mmap, unusable = FALSE;
	int ret, try;

	ret = mail_index_reopen_if_changed(index);
	if (ret <= 0) {
		if (ret < 0)
			return -1;

		/* the index file is lost/broken. let's hope that we can
		   build it from the transaction log. */
		return 1;
	}

	/* the index file is still open, lock it */
	if (mail_index_lock_shared(index, &lock_id) < 0)
		return -1;

	if (index->nfs_flush)
		nfs_flush_attr_cache_fd_locked(index->filepath, index->fd);

	if (fstat(index->fd, &st) == 0)
		file_size = st.st_size;
	else {
		if (errno != ESTALE) {
			mail_index_set_syscall_error(index, "fstat()");
			mail_index_unlock(index, &lock_id);
			return -1;
		}
		file_size = (uoff_t)-1;
	}

	/* mmaping seems to be slower than just reading the file, so even if
	   mmap isn't disabled don't use it unless the file is large enough */
	use_mmap = !index->mmap_disable && file_size != (uoff_t)-1 &&
		file_size > MAIL_INDEX_MMAP_MIN_SIZE;

	new_map = mail_index_map_alloc(index);
	if (use_mmap) {
		new_map->rec_map->lock_id = lock_id;
		ret = mail_index_mmap(new_map, file_size);
	} else {
		ret = mail_index_read_map(new_map, file_size, &lock_id);
		mail_index_unlock(index, &lock_id);
	}
	if (ret == 0) {
		/* the index files are unusable */
		unusable = TRUE;
	}

	for (try = 0; ret > 0; try++) {
		/* make sure the header is ok before using this mapping */
		ret = mail_index_map_check_header(new_map);
		if (ret > 0) T_BEGIN {
			if (mail_index_map_parse_extensions(new_map) < 0)
				ret = 0;
			else if (mail_index_map_parse_keywords(new_map) < 0)
				ret = 0;
		} T_END;
		if (ret != 0 || try == 2) {
			if (ret < 0) {
				unusable = TRUE;
				ret = 0;
			}
			break;
		}

		/* fsck and try again */
		old_map = index->map;
		index->map = new_map;
		if (mail_index_fsck(index) < 0) {
			ret = -1;
			break;
		}

		/* fsck replaced the map */
		new_map = index->map;
		index->map = old_map;
	}
	if (ret <= 0) {
		mail_index_unmap(&new_map);
		return ret < 0 ? -1 : (unusable ? 0 : 1);
	}
	i_assert(new_map->rec_map->records != NULL);

	index->last_read_log_file_seq = new_map->hdr.log_file_seq;
	index->last_read_log_file_head_offset =
		new_map->hdr.log_file_head_offset;
	index->last_read_log_file_tail_offset =
		new_map->hdr.log_file_tail_offset;
	index->last_read_stat = st;

	mail_index_unmap(&index->map);
	index->map = new_map;
	return 1;
}

int mail_index_map(struct mail_index *index,
		   enum mail_index_sync_handler_type type)
{
	int ret;

	i_assert(index->lock_type != F_WRLCK);
	i_assert(!index->mapping);

	index->mapping = TRUE;

	if (index->map == NULL)
		index->map = mail_index_map_alloc(index);

	/* first try updating the existing mapping from transaction log. */
	if (index->initial_mapped) {
		/* we're not creating/opening the index.
		   sync this as a view from transaction log. */
		ret = mail_index_sync_map(&index->map, type, FALSE);
	} else {
		ret = 0;
	}

	if (ret == 0) {
		/* try to open and read the latest index. if it fails, we'll
		   fallback to updating the existing mapping from transaction
		   logs (which we'll also do even if the reopening succeeds).
		   if index files are unusable (e.g. major version change)
		   don't even try to use the transaction log. */
		ret = mail_index_map_latest_file(index);
		if (ret > 0) {
			/* if we're creating the index file, we don't have any
			   logs yet */
			if (index->log->head != NULL && index->indexid != 0) {
				/* and update the map with the latest changes
				   from transaction log */
				ret = mail_index_sync_map(&index->map, type,
							  TRUE);
			}
		} else if (ret == 0) {
			/* make sure we don't try to open the file again */
			if (unlink(index->filepath) < 0 && errno != ENOENT)
				mail_index_set_syscall_error(index, "unlink()");
		}
	}

	if (ret >= 0)
		index->initial_mapped = TRUE;
	index->mapping = FALSE;
	return ret;
}

static void mail_index_record_map_free(struct mail_index_map *map,
				       struct mail_index_record_map *rec_map)
{
	if (rec_map->lock_id != 0)
		mail_index_unlock(map->index, &rec_map->lock_id);

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
	unsigned int i, count;

	maps = array_get(&map->rec_map->maps, &count);
	for (i = 0; i < count; i++) {
		if (maps[i] == map) {
			array_delete(&map->rec_map->maps, i, 1);
			if (i == 0 && count == 1) {
				mail_index_record_map_free(map, map->rec_map);
				map->rec_map = NULL;
			}
			return;
		}
	}
	i_unreached();
}

void mail_index_unmap(struct mail_index_map **_map)
{
	struct mail_index_map *map = *_map;

	*_map = NULL;
	if (--map->refcount > 0)
		return;

	i_assert(map->refcount == 0);
	mail_index_record_map_unlink(map);

	if (map->extension_pool != NULL)
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
	dest->buffer = buffer_create_dynamic(default_pool, I_MIN(size, 1024));
	buffer_append(dest->buffer, src->records, size);

	dest->records = buffer_get_modifiable_data(dest->buffer, NULL);
	dest->records_count = src->records_count;

	/* if the map is ever written back to disk, we need to keep track of
	   what has changed. */
	dest->write_seq_first = src->write_seq_first;
	dest->write_seq_last = src->write_seq_last;
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
	array_append(&rec_map->maps, &map, 1);
	return rec_map;
}

struct mail_index_map *mail_index_map_clone(const struct mail_index_map *map)
{
	struct mail_index_map *mem_map;
	struct mail_index_ext *extensions;
	unsigned int i, count;

	mem_map = i_new(struct mail_index_map, 1);
	mem_map->index = map->index;
	mem_map->refcount = 1;
	if (map->rec_map == NULL) {
		mem_map->rec_map = mail_index_record_map_alloc(mem_map);
		mem_map->rec_map->buffer =
			buffer_create_dynamic(default_pool, 1024);
	} else {
		mem_map->rec_map = map->rec_map;
		array_append(&mem_map->rec_map->maps, &mem_map, 1);
	}

	mail_index_map_copy_header(mem_map, map);

	mem_map->write_atomic = map->write_atomic;
	mem_map->write_base_header = map->write_base_header;
	mem_map->write_ext_header = map->write_ext_header;

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
				 extensions[i].record_size <=
				 mem_map->hdr.record_size);
			extensions[i].name = p_strdup(mem_map->extension_pool,
						      extensions[i].name);
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
			rec = MAIL_INDEX_MAP_IDX(map, new_map->records_count-1);
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

	i_assert(map->rec_map->lock_id != 0);

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
		mail_index_unlock(map->index, &new_map->lock_id);
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
