/* Copyright (C) 2003-2007 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "nfs-workarounds.h"
#include "mmap-util.h"
#include "read-full.h"
#include "mail-index-private.h"
#include "mail-index-sync-private.h"
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
mail_index_map_register_ext(struct mail_index_map *map, const char *name,
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

	ext->index_idx = mail_index_ext_register(map->index, name, hdr_size,
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

static int mail_index_parse_extensions(struct mail_index_map *map)
{
	struct mail_index *index = map->index;
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

	for (i = 0; offset < map->hdr.header_size; i++) {
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

		if ((ext_hdr->record_size == 0 && ext_hdr->hdr_size == 0) ||
		    ext_hdr->record_align == 0 || *name == '\0') {
			mail_index_set_error(index, "Corrupted index file %s: "
					     "Broken header extension %s",
					     index->filepath, *name == '\0' ?
					     t_strdup_printf("#%d", i) : name);
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

		mail_index_map_register_ext(map, name,
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

static bool mail_index_check_header_compat(struct mail_index *index,
					   const struct mail_index_header *hdr,
					   uoff_t file_size)
{
        enum mail_index_header_compat_flags compat_flags = 0;

#ifndef WORDS_BIGENDIAN
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

static int mail_index_check_header(struct mail_index_map *map)
{
	struct mail_index *index = map->index;
	const struct mail_index_header *hdr = &map->hdr;

	if (!mail_index_check_header_compat(index, hdr, (uoff_t)-1))
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

	return 1;
}

static void mail_index_map_clear(struct mail_index_map *map)
{
	if (map->buffer != NULL) {
		i_assert(map->mmap_base == NULL);
		buffer_free(map->buffer);
		map->buffer = NULL;
	} else if (map->mmap_base != NULL) {
		i_assert(map->buffer == NULL);
		if (munmap(map->mmap_base, map->mmap_size) < 0)
			mail_index_set_syscall_error(map->index, "munmap()");
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

static int mail_index_mmap(struct mail_index_map *map, uoff_t file_size)
{
	struct mail_index *index = map->index;
	const struct mail_index_header *hdr;
	unsigned int records_count;

	if (map->buffer != NULL) {
		/* we had temporarily used a buffer, eg. for updating index */
		buffer_free(map->buffer);
		map->buffer = NULL;
	}

	if (file_size > SSIZE_T_MAX) {
		/* too large file to map into memory */
		mail_index_set_error(index, "Index file too large: %s",
				     index->filepath);
		return -1;
	}

	map->mmap_base = mmap(NULL, file_size, PROT_READ | PROT_WRITE,
			      MAP_PRIVATE, index->fd, 0);
	if (map->mmap_base == MAP_FAILED) {
		map->mmap_base = NULL;
		mail_index_set_syscall_error(index, "mmap()");
		return -1;
	}
	map->mmap_size = file_size;

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

	if (!mail_index_check_header_compat(index, hdr, map->mmap_size)) {
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
	unsigned int records_count, extra;

	i_assert(map->mmap_base == NULL);

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

		if (file_size - hdr->header_size < records_size ||
		    (hdr->record_size != 0 &&
		     records_size / hdr->record_size != hdr->messages_count)) {
			records_count = (file_size - hdr->header_size) /
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
		if (initial_buf_pos <= hdr->header_size)
			extra = 0;
		else {
			extra = initial_buf_pos - hdr->header_size;
			buffer_append(map->buffer,
				      CONST_PTR_OFFSET(buf, hdr->header_size),
				      extra);
		}
		if (records_size > extra) {
			data = buffer_append_space_unsafe(map->buffer,
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

	map->records = buffer_get_modifiable_data(map->buffer, NULL);
	map->records_count = hdr->messages_count;

	mail_index_map_copy_hdr(map, hdr);
	map->hdr_base = map->hdr_copy_buf->data;
	return 1;
}

static int mail_index_read_map(struct mail_index_map *map, uoff_t file_size)
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

#ifndef WORDS_BIGENDIAN
	hdr->compat_flags |= MAIL_INDEX_COMPAT_LITTLE_ENDIAN;
#endif

	hdr->indexid = index->indexid;
	hdr->log_file_seq = 1;
	hdr->next_uid = 1;
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

static int mail_index_map_latest_file(struct mail_index *index,
				      struct mail_index_map **map)
{
	struct mail_index_map *new_map;
	struct stat st;
	unsigned int lock_id;
	uoff_t file_size;
	bool use_mmap;
	int ret;

	ret = mail_index_reopen_if_changed(index);
	if (ret <= 0) {
		if (ret < 0)
			return -1;

		/* the index file is lost/broken. let's hope that we can
		   build it from the transaction log. */
		return 0;
	}

	/* the index file is still open, lock it */
	if (mail_index_lock_shared(index, &lock_id) < 0)
		return -1;

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
		new_map->lock_id = lock_id;
		ret = mail_index_mmap(new_map, file_size);
	} else {
		ret = mail_index_read_map(new_map, file_size);
		mail_index_unlock(index, &lock_id);
	}
	if (ret > 0) {
		/* make sure the header is ok before using this mapping */
		ret = mail_index_check_header(new_map);
		if (ret >= 0)
			ret = mail_index_parse_extensions(new_map);
		if (ret++ == 0)
			index->fsck = TRUE;
	}
	if (ret <= 0) {
		mail_index_unmap(&new_map);
		return ret;
	}

	index->last_read_log_file_seq = new_map->hdr.log_file_seq;
	index->last_read_log_file_head_offset =
		new_map->hdr.log_file_head_offset;
	index->last_read_log_file_tail_offset =
		new_map->hdr.log_file_tail_offset;
	index->last_read_stat = st;

	mail_index_unmap(map);
	*map = new_map;
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
	if (index->map->hdr.indexid != 0) {
		/* we're not creating the index, or opening transaction log.
		   sync this as a view from transaction log. */
		ret = mail_index_sync_map(&index->map, type, FALSE);
	} else {
		ret = 0;
	}

	if (ret == 0) {
		/* try to open and read the latest index. if it fails for
		   any reason, we'll fallback to updating the existing mapping
		   from transaction logs (which we'll also do even if the
		   reopening succeeds) */
		(void)mail_index_map_latest_file(index, &index->map);

		/* if we're creating the index file, we don't have any
		   logs yet */
		if (index->log->head != NULL) {
			/* and update the map with the latest changes from
			   transaction log */
			ret = mail_index_sync_map(&index->map, type, TRUE);
		}
	}

	index->mapping = FALSE;
	return ret;
}

void mail_index_unmap(struct mail_index_map **_map)
{
	struct mail_index_map *map = *_map;

	*_map = NULL;
	if (--map->refcount > 0)
		return;

	i_assert(map->refcount == 0);
	mail_index_map_clear(map);
	mail_index_map_unlock(map);

	if (map->extension_pool != NULL)
		pool_unref(map->extension_pool);
	if (array_is_created(&map->keyword_idx_map))
		array_free(&map->keyword_idx_map);
	buffer_free(map->hdr_copy_buf);
	i_free(map);
}

int mail_index_map_lock(struct mail_index_map *map)
{
	if (map->lock_id != 0 || MAIL_INDEX_MAP_IS_IN_MEMORY(map))
		return 0;

	if (mail_index_lock_shared(map->index, &map->lock_id) < 0)
		return -1;

	mail_index_map_copy_hdr(map, map->mmap_base);
	return 0;
}

void mail_index_map_unlock(struct mail_index_map *map)
{
	mail_index_unlock(map->index, &map->lock_id);
}

static void mail_index_map_copy(struct mail_index_map *dest,
				const struct mail_index_map *src)
{
	size_t size;

	/* copy records */
	size = src->records_count * src->hdr.record_size;
	dest->buffer = buffer_create_dynamic(default_pool, size);
	buffer_append(dest->buffer, src->records, size);

	dest->records = buffer_get_modifiable_data(dest->buffer, NULL);
	dest->records_count = src->records_count;

	/* copy header. use src->hdr copy directly, because if we got here
	   from syncing it has the latest changes. */
	dest->hdr = src->hdr;
	if (dest->hdr_copy_buf != NULL)
		buffer_set_used_size(dest->hdr_copy_buf, 0);
	else {
		dest->hdr_copy_buf =
			buffer_create_dynamic(default_pool,
					      dest->hdr.header_size);
	}
	buffer_append(dest->hdr_copy_buf, &dest->hdr,
		      I_MIN(sizeof(dest->hdr), src->hdr.base_header_size));
	buffer_write(dest->hdr_copy_buf, src->hdr.base_header_size,
		     CONST_PTR_OFFSET(src->hdr_base, src->hdr.base_header_size),
		     src->hdr.header_size - src->hdr.base_header_size);
	dest->hdr_base = buffer_get_modifiable_data(dest->hdr_copy_buf, NULL);
}

struct mail_index_map *mail_index_map_clone(const struct mail_index_map *map)
{
	struct mail_index_map *mem_map;
	struct mail_index_ext *extensions;
	unsigned int i, count;

	mem_map = i_new(struct mail_index_map, 1);
	mem_map->index = map->index;
	mem_map->refcount = 1;

	mail_index_map_copy(mem_map, map);

	/* if the map is ever written back to disk, we need to keep track of
	   what has changed. */
	if (map->write_atomic)
		mem_map->write_atomic = TRUE;
	else {
		mem_map->write_seq_first = map->write_seq_first;
		mem_map->write_seq_last = map->write_seq_last;
		mem_map->write_base_header = map->write_base_header;
		mem_map->write_ext_header = map->write_ext_header;
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
				 extensions[i].record_size <=
				 mem_map->hdr.record_size);
			extensions[i].name = p_strdup(mem_map->extension_pool,
						      extensions[i].name);
		}
	}

	return mem_map;
}

void mail_index_map_move_to_memory(struct mail_index_map *map)
{
	if (map->mmap_base == NULL)
		return;

	i_assert(map->lock_id != 0);

	mail_index_map_copy(map, map);
	mail_index_map_unlock(map);

	if (munmap(map->mmap_base, map->mmap_size) < 0)
		i_error("munmap(index map) failed: %m");
	map->mmap_base = NULL;
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
