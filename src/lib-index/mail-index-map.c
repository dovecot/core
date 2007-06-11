/* Copyright (C) 2003-2007 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "nfs-workarounds.h"
#include "mmap-util.h"
#include "read-full.h"
#include "mail-index-private.h"
#include "mail-index-sync-private.h"

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
		index->map = NULL;
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
