/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "file-lock.h"
#include "mmap-util.h"
#include "read-full.h"
#include "write-full.h"
#include "mail-index-private.h"
#include "mail-transaction-log.h"
#include "mail-cache.h"

#include <stdio.h>
#include <stddef.h>
#include <time.h>
#include <sys/stat.h>

static int mail_index_try_open_only(struct mail_index *index);

struct mail_index *mail_index_alloc(const char *dir, const char *prefix)
{
	struct mail_index *index;

	index = i_new(struct mail_index, 1);
	index->dir = i_strdup(dir);
	index->prefix = i_strdup(prefix);
	index->fd = -1;

	index->extra_infos_pool =
		pool_alloconly_create("extra_infos_pool", 256);
	index->extra_infos =
		buffer_create_dynamic(index->extra_infos_pool,
				      64, (size_t)-1);

	index->mode = 0600;
	index->gid = (gid_t)-1;
	return index;
}

void mail_index_free(struct mail_index *index)
{
	mail_index_close(index);
	pool_unref(index->extra_infos_pool);

	i_free(index->error);
	i_free(index->dir);
	i_free(index->prefix);
	i_free(index);
}

uint32_t mail_index_register_record_extra(struct mail_index *index,
					  const char *name, uint32_t hdr_size,
					  uint16_t record_size)
{
        const struct mail_index_extra_record_info *einfos;
	struct mail_index_extra_record_info info;
	size_t extra_count;
	unsigned int i;

	einfos = buffer_get_data(index->extra_infos, &extra_count);
	extra_count /= sizeof(*einfos);

	/* see if it's there already */
	for (i = 0; i < extra_count; i++) {
		if (strcmp(einfos[i].name, name) == 0) {
			i_assert(einfos[i].hdr_size == hdr_size);
			i_assert(einfos[i].record_size == record_size);
			return i;
		}
	}

	i_assert(hdr_size % 4 == 0);
	i_assert(record_size % 4 == 0);

	memset(&info, 0, sizeof(info));
	info.name = p_strdup(index->extra_infos_pool, name);
	info.hdr_size = hdr_size;
	info.record_size = record_size;

	buffer_append(index->extra_infos, &info, sizeof(info));
	return extra_count;
}

static void mail_index_map_create_extra_infos(struct mail_index_map *map,
					      unsigned int initial_count)
{
	size_t extra_infos_size, extra_infos_id_map_size, size;

	extra_infos_size = initial_count *
		sizeof(struct mail_index_extra_record_info);
	extra_infos_id_map_size = initial_count * sizeof(uint32_t);
	if (map->extra_records_pool == NULL) {
		size = extra_infos_size + extra_infos_id_map_size +
			initial_count * 20;
		map->extra_records_pool =
			pool_alloconly_create("extra_infos",
					      nearest_power(size));
	}

	map->extra_infos = buffer_create_dynamic(map->extra_records_pool,
						 extra_infos_size, (size_t)-1);
	map->extra_infos_id_map = buffer_create_dynamic(map->extra_records_pool,
							extra_infos_id_map_size,
							(size_t)-1);
}

uint32_t mail_index_map_register_extra_info(struct mail_index *index,
					    struct mail_index_map *map,
					    const char *name,
					    uint32_t hdr_offset,
					    uint32_t hdr_size,
					    uint32_t record_size)
{
	const struct mail_index_extra_record_info *last_einfo;
	struct mail_index_extra_record_info *einfo;
	size_t size;
	uint32_t idx, data_id;

	if (map->extra_infos == NULL) {
                mail_index_map_create_extra_infos(map, 5);
		last_einfo = NULL;
		idx = 0;
	} else {
		last_einfo = buffer_get_data(map->extra_infos, &size);
		idx = size / sizeof(*last_einfo);
		if (idx == 0)
			last_einfo = NULL;
		else
			last_einfo += idx - 1;
	}

	einfo = buffer_append_space_unsafe(map->extra_infos, sizeof(*einfo));
	memset(einfo, 0, sizeof(*einfo));

	einfo->name = p_strdup(map->extra_records_pool, name);
	einfo->hdr_offset = hdr_offset;
	einfo->hdr_size = hdr_size;
	einfo->record_size = record_size;

	if (last_einfo != NULL) {
		einfo->record_offset = last_einfo->record_offset +
			last_einfo->record_size;
	} else {
		einfo->record_offset = sizeof(struct mail_index_record);
	}

	data_id = mail_index_register_record_extra(index, name,
						   hdr_size, record_size);
	buffer_write(map->extra_infos_id_map, data_id * sizeof(uint32_t),
		     &idx, sizeof(idx));
	return idx;
}

static int mail_index_read_extra_infos(struct mail_index *index,
				       struct mail_index_map *map)
{
	const struct mail_index_extra_record_info_header *einfo_hdr;
	unsigned int i, old_count;
	const char *name;
	uint32_t data_id, offset, name_offset;

	offset = map->hdr->base_header_size;
	if (offset == map->hdr->header_size &&
	    map->extra_records_pool == NULL) {
		/* nothing to do, skip allocatations and all */
		return 1;
	}

	old_count = index->extra_infos->used /
		sizeof(struct mail_index_extra_record_info);

	if (map->extra_records_pool != NULL)
		p_clear(map->extra_records_pool);
	mail_index_map_create_extra_infos(map, old_count + 5);
	data_id = (uint32_t)-1;
	for (i = 0; i < old_count; i++) {
		buffer_append(map->extra_infos_id_map,
			      &data_id, sizeof(data_id));
	}

	name = map->hdr_base;
	while (offset < map->hdr->header_size) {
		name_offset = offset;

		while (offset < map->hdr->header_size && name[offset] != '\0')
			offset++;
		if (offset == map->hdr->header_size) {
			mail_index_set_error(index, "Corrupted index file %s: "
				"Header extension name doesn't end with NUL",
				index->filepath);
			return -1;
		}
		offset++;
		while (offset < map->hdr->header_size && (offset % 4) != 0)
			offset++;

		einfo_hdr = CONST_PTR_OFFSET(map->hdr_base, offset);

		if (offset + sizeof(*einfo_hdr) > map->hdr->header_size ||
		    offset + sizeof(*einfo_hdr) + einfo_hdr->hdr_size >
		    map->hdr->header_size) {
			mail_index_set_error(index, "Corrupted index file %s: "
				"Header extension goes outside header",
				index->filepath);
			return -1;
		}

		mail_index_map_register_extra_info(index, map,
						   name + name_offset,
						   offset + sizeof(*einfo_hdr),
						   einfo_hdr->hdr_size,
						   einfo_hdr->record_size);

		offset += sizeof(*einfo_hdr) + einfo_hdr->hdr_size;
	}
	return 1;
}

static int mail_index_check_header(struct mail_index *index,
				   struct mail_index_map *map)
{
	const struct mail_index_header *hdr = map->hdr;
	unsigned char compat_data[sizeof(hdr->compat_data)];

	memset(compat_data, 0, sizeof(compat_data));
#ifndef WORDS_BIGENDIAN
	compat_data[0] = MAIL_INDEX_COMPAT_LITTLE_ENDIAN;
#endif
	compat_data[1] = sizeof(uoff_t);
	compat_data[2] = sizeof(time_t);

	if (hdr->major_version != MAIL_INDEX_MAJOR_VERSION) {
		/* major version change - handle silently(?) */
		return -1;
	}
	if (memcmp(hdr->compat_data, compat_data, sizeof(compat_data)) != 0) {
		/* architecture change - handle silently(?) */
		return -1;
	}

	if ((map->hdr->flags & MAIL_INDEX_HDR_FLAG_CORRUPTED) != 0) {
		/* we've already complained about it */
		return -1;
	}

	/* following some extra checks that only take a bit of CPU */
	if (hdr->uid_validity == 0 && hdr->next_uid != 1) {
		mail_index_set_error(index, "Corrupted index file %s: "
				     "uid_validity = 0, next_uid = %u",
				     index->filepath, hdr->next_uid);
		return -1;
	}

	if (hdr->keywords_mask_size != sizeof(keywords_mask_t)) {
		mail_index_set_error(index, "Corrupted index file %s: "
				     "keywords_mask_size mismatch: %d != %d",
				     index->filepath, hdr->keywords_mask_size,
				     (int)sizeof(keywords_mask_t));
		return -1;
	}

	if (hdr->record_size < sizeof(struct mail_index_record)) {
		mail_index_set_error(index, "Corrupted index file %s: "
				     "record_size too small: %u < %"PRIuSIZE_T,
				     index->filepath, hdr->record_size,
				     sizeof(struct mail_index_record));
		return -1;
	}

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

	return mail_index_read_extra_infos(index, map);
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
		map->mmap_size = 0;
		map->mmap_used_size = 0;
		map->hdr = NULL;
		map->records = NULL;
		map->records_count = 0;
	}
}

void mail_index_unmap(struct mail_index *index, struct mail_index_map *map)
{
	if (--map->refcount > 0)
		return;

	i_assert(map->refcount == 0);
	mail_index_map_clear(index, map);
	if (map->extra_records_pool != NULL)
		pool_unref(map->extra_records_pool);
	buffer_free(map->hdr_copy_buf);
	i_free(map);
}

static void mail_index_unmap_forced(struct mail_index *index,
				    struct mail_index_map *map)
{
	mail_index_map_clear(index, map);
	mail_index_unmap(index, map);
}

static int mail_index_mmap(struct mail_index *index, struct mail_index_map *map)
{
	const struct mail_index_header *hdr;
	struct mail_index_header *mhdr;
	unsigned int records_count;

	i_assert(!map->write_to_disk);

	if (map->buffer != NULL) {
		/* we had temporarily used a buffer, eg. for updating index */
		buffer_free(map->buffer);
		map->buffer = NULL;
	}

	map->mmap_base = index->lock_type != F_WRLCK ?
		mmap_ro_file(index->fd, &map->mmap_size) :
		mmap_rw_file(index->fd, &map->mmap_size);
	if (map->mmap_base == MAP_FAILED) {
		map->mmap_base = NULL;
		mail_index_set_syscall_error(index, "mmap()");
		return -1;
	}

	if (map->mmap_size < MAIL_INDEX_HEADER_MIN_SIZE) {
		mail_index_set_error(index, "Corrupted index file %s: "
				     "File too small (%"PRIuSIZE_T")",
				     index->filepath, map->mmap_size);
		return 0;
	}

	hdr = map->mmap_base;
	map->hdr = hdr;
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

	if (map->hdr->base_header_size < sizeof(*map->hdr)) {
		/* header smaller than ours, make a copy so our newer headers
		   won't have garbage in them */
		buffer_reset(map->hdr_copy_buf);
		buffer_append(map->hdr_copy_buf,
			      map->hdr, map->hdr->base_header_size);
		buffer_set_used_size(map->hdr_copy_buf, sizeof(*map->hdr));

		mhdr = buffer_get_modifyable_data(map->hdr_copy_buf, NULL);
		mhdr->base_header_size = sizeof(*map->hdr);
		mhdr->header_size = map->hdr_copy_buf->used;

		map->hdr = mhdr;
       }

	map->hdr_base = map->mmap_base;
	map->records = PTR_OFFSET(map->mmap_base, map->hdr->header_size);
	map->records_count = map->hdr->messages_count;
	return 1;
}

static int mail_index_read_map(struct mail_index *index,
			       struct mail_index_map *map, int *retry_r)
{
	struct mail_index_header hdr, *hdrp;
	void *data = NULL;
	ssize_t ret;
	size_t pos, records_size;

	i_assert(map->mmap_base == NULL);

	*retry_r = FALSE;
	memset(&hdr, 0, sizeof(hdr));

	ret = 1;
	for (pos = 0; ret > 0 && pos < sizeof(hdr); ) {
		ret = pread(index->fd, PTR_OFFSET(&hdr, pos),
			    sizeof(hdr) - pos, pos);
		if (ret > 0)
			pos += ret;
	}

	if (ret >= 0 && pos >= MAIL_INDEX_HEADER_MIN_SIZE &&
	    (ret > 0 || pos >= hdr.base_header_size)) {
		if (hdr.base_header_size < MAIL_INDEX_HEADER_MIN_SIZE ||
		    hdr.header_size < hdr.base_header_size) {
			mail_index_set_error(index, "Corrupted index file %s: "
				"Corrupted header sizes (base %u, full %u)",
				index->filepath, hdr.base_header_size,
				hdr.header_size);
			return 0;
		}

		buffer_reset(map->hdr_copy_buf);
		if (hdr.base_header_size < sizeof(hdr)) {
			buffer_append(map->hdr_copy_buf, &hdr,
				      hdr.base_header_size);
			buffer_set_used_size(map->hdr_copy_buf, sizeof(hdr) +
					     hdr.header_size -
					     hdr.base_header_size);

			/* @UNSAFE */
			ret = pread_full(index->fd,
					 PTR_OFFSET(map->hdr_copy_buf->data,
						    sizeof(hdr)),
					 hdr.header_size - hdr.base_header_size,
					 hdr.base_header_size);

			hdrp = buffer_get_modifyable_data(map->hdr_copy_buf,
							  NULL);
			hdrp->base_header_size = sizeof(hdr);
			hdrp->header_size = map->hdr_copy_buf->used;
		} else {
			buffer_append(map->hdr_copy_buf, &hdr, pos);
			buffer_set_used_size(map->hdr_copy_buf,
					     hdr.header_size);
			/* @UNSAFE */
			ret = pread_full(index->fd,
					 PTR_OFFSET(map->hdr_copy_buf->data,
						    pos),
					 hdr.header_size - pos, pos);
		}
	}

	if (ret > 0) {
		records_size = hdr.messages_count * hdr.record_size;

		if (map->buffer == NULL) {
			map->buffer = buffer_create_dynamic(default_pool,
							    records_size,
							    (size_t)-1);
		}

		/* @UNSAFE */
		buffer_set_used_size(map->buffer, 0);
		data = buffer_append_space_unsafe(map->buffer, records_size);

		ret = pread_full(index->fd, data, records_size,
				 hdr.header_size);
	}

	if (ret < 0) {
		if (errno == ESTALE) {
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
		return -1;
	}

	map->records = data;
	map->records_count = hdr.messages_count;

	map->hdr = map->hdr_copy_buf->data;
	map->hdr_base = map->hdr_copy_buf->data;
	return 1;
}

static int mail_index_read_map_with_retry(struct mail_index *index,
					  struct mail_index_map *map)
{
	int i, ret, retry;

	for (i = 0; i < MAIL_INDEX_ESTALE_RETRY_COUNT; i++) {
		ret = mail_index_read_map(index, map, &retry);
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

	/* Too many ESTALE retries */
	mail_index_set_syscall_error(index, "read_map()");
	return -1;
}

static int mail_index_map_try_existing(struct mail_index_map *map)
{
	const struct mail_index_header *hdr;
	size_t used_size;

	if (MAIL_INDEX_MAP_IS_IN_MEMORY(map))
		return 0;

	hdr = map->mmap_base;

	/* always check corrupted-flag to avoid errors later */
	if ((hdr->flags & MAIL_INDEX_HDR_FLAG_CORRUPTED) != 0)
		return -1;

	used_size = hdr->header_size + hdr->messages_count * hdr->record_size;
	if (map->mmap_size >= used_size && map->hdr == hdr) {
		map->records_count = hdr->messages_count;
		return 1;
	}
	return 0;
}

int mail_index_map(struct mail_index *index, int force)
{
	struct mail_index_map *map;
	int ret;

	if (!force && index->map != NULL) {
		ret = mail_index_map_try_existing(index->map);
		if (ret != 0)
			return ret;
	}

	if (index->map != NULL && index->map->refcount > 1) {
		/* this map is already used by some views and they may have
		   pointers into it. leave them and create a new mapping. */
		index->map->refcount--;
		index->map = NULL;
	}

	map = index->map;
	if (map == NULL) {
		map = i_new(struct mail_index_map, 1);
		map->refcount = 1;
		map->hdr_copy_buf =
			buffer_create_dynamic(default_pool,
					      sizeof(*map->hdr), (size_t)-1);
	} else if (MAIL_INDEX_MAP_IS_IN_MEMORY(map)) {
		if (map->write_to_disk) {
			/* we have modified this mapping and it's waiting to
			   be written to disk once we drop exclusive lock.
			   mapping couldn't have changed, so do nothing. */
			return 1;
		}
		/* FIXME: we need to re-read header */
	} else if (map->mmap_base != NULL) {
		i_assert(map->buffer == NULL);
		if (munmap(map->mmap_base, map->mmap_size) < 0)
			mail_index_set_syscall_error(index, "munmap()");
		map->mmap_base = NULL;
	}

	index->hdr = NULL;
	index->map = NULL;

	if (!index->mmap_disable) {
		if ((ret = mail_index_mmap(index, map)) <= 0) {
			mail_index_unmap_forced(index, map);
			return ret;
		}
	} else {
		if (mail_index_read_map_with_retry(index, map) < 0) {
			mail_index_unmap_forced(index, map);
			return -1;
		}
	}

	ret = mail_index_check_header(index, map);
	if (ret < 0) {
		mail_index_unmap_forced(index, map);
		return 0;
	}
	if (ret == 0)
		index->fsck = TRUE;

	map->log_file_seq = map->hdr->log_file_seq;
	map->log_file_offset = map->hdr->log_file_offset;
	map->base_header_size = map->hdr->base_header_size;

	index->hdr = map->hdr;
	index->map = map;
	return 1;
}

struct mail_index_map *
mail_index_map_to_memory(struct mail_index_map *map, uint32_t new_record_size)
{
	struct mail_index_map *mem_map;
	struct mail_index_header *hdr;
	struct mail_index_extra_record_info *einfos;
	void *src, *dest;
	size_t size, copy_size;
	unsigned int i, count;

	if (MAIL_INDEX_MAP_IS_IN_MEMORY(map)) {
		map->refcount++;
		return map;
	}

        size = map->records_count * new_record_size;

	mem_map = i_new(struct mail_index_map, 1);
	mem_map->refcount = 1;
	mem_map->buffer = buffer_create_dynamic(default_pool, size, (size_t)-1);
	if (map->hdr->record_size == new_record_size)
		buffer_append(mem_map->buffer, map->records, size);
	else {
		copy_size = I_MIN(map->hdr->record_size, new_record_size);
		src = map->records;
		for (i = 0; i < map->records_count; i++) {
			dest = buffer_append_space_unsafe(mem_map->buffer,
							  new_record_size);
			memcpy(dest, src, copy_size);
			src = PTR_OFFSET(src, map->hdr->record_size);
		}
	}

	mem_map->records = buffer_get_modifyable_data(mem_map->buffer, NULL);
	mem_map->records_count = map->records_count;

	mem_map->hdr_copy_buf = buffer_create_dynamic(default_pool,
						      map->hdr->header_size,
						      (size_t)-1);
	buffer_append(mem_map->hdr_copy_buf, map->hdr, map->hdr->header_size);

	hdr = buffer_get_modifyable_data(mem_map->hdr_copy_buf, NULL);
	hdr->record_size = new_record_size;
	mem_map->hdr = hdr;

	/* copy extra_infos */
	if (map->extra_infos_id_map != NULL) {
		count = map->extra_infos_id_map->used / sizeof(uint32_t);
		mail_index_map_create_extra_infos(mem_map, count);

		buffer_append_buf(mem_map->extra_infos, map->extra_infos,
				  0, (size_t)-1);
		buffer_append_buf(mem_map->extra_infos_id_map,
				  map->extra_infos_id_map, 0, (size_t)-1);

		/* fix the name pointers to use our own pool */
		einfos = buffer_get_modifyable_data(mem_map->extra_infos, NULL);
		for (i = 0; i < count; i++) {
			einfos[i].name = p_strdup(mem_map->extra_records_pool,
						  einfos[i].name);
		}
	}

	return mem_map;
}

int mail_index_map_get_extra_info_idx(struct mail_index_map *map,
				      uint32_t data_id, uint32_t *idx_r)
{
	const uint32_t *id_map;

	if (map->extra_infos_id_map == NULL ||
	    map->extra_infos_id_map->used / sizeof(*id_map) <= data_id)
		return 0;

	id_map = map->extra_infos_id_map->data;
	*idx_r = id_map[data_id];
	return *idx_r != (uint32_t)-1;
}

static int mail_index_try_open_only(struct mail_index *index)
{
	int i;

	for (i = 0; i < 3; i++) {
		index->fd = open(index->filepath, O_RDWR);
		if (index->fd == -1 && errno == EACCES) {
			index->fd = open(index->filepath, O_RDONLY);
			index->readonly = TRUE;
		}
		if (index->fd != -1 || errno != ESTALE)
			break;

		/* May happen with some OSes with NFS. Try again, although
		   there's still a race condition with another computer
		   creating the index file again. However, we can't try forever
		   as ESTALE happens also if index directory has been deleted
		   from server.. */
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

	if (lock_id_r != NULL)
		*lock_id_r = 0;

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
	} else {
		if (pwrite_full(index->fd, hdr, hdr_size, 0) < 0) {
			mail_index_set_syscall_error(index, "pwrite_full()");
			return -1;
		}

		buffer_write(index->map->hdr_copy_buf, 0, hdr, hdr_size);
		i_assert(index->hdr == index->map->hdr_copy_buf->data);
	}

	return 0;
}

int mail_index_create_tmp_file(struct mail_index *index, const char **path_r)
{
	const char *path;
	int fd;

	path = *path_r = t_strconcat(index->filepath, ".tmp", NULL);
	fd = open(path, O_RDWR|O_CREAT|O_TRUNC, index->mode);
	if (fd == -1)
		return mail_index_file_set_syscall_error(index, path, "open()");

	if (index->gid != (gid_t)-1 &&
	    fchown(index->fd, (uid_t)-1, index->gid) < 0) {
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

	/* log file lock protects index creation */
	if (mail_transaction_log_sync_lock(index->log, &seq, &offset) < 0)
		return -1;

	ret = mail_index_try_open(index, NULL);
	if (ret != 0) {
		mail_transaction_log_sync_unlock(index->log);
		return ret < 0 ? -1 : 0;
	}

	/* create it fully in index.tmp first */
	index->fd = mail_index_create_tmp_file(index, &path);
	if (index->fd == -1)
		ret = -1;
	else if (write_full(index->fd, hdr, sizeof(*hdr)) < 0) {
		mail_index_file_set_syscall_error(index, path, "write_full()");
		ret = -1;
	} else {
		ret = mail_index_map(index, FALSE);
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

	memset(hdr, 0, sizeof(*hdr));

	hdr->major_version = MAIL_INDEX_MAJOR_VERSION;
	hdr->minor_version = MAIL_INDEX_MINOR_VERSION;
	hdr->base_header_size = sizeof(*hdr);
	hdr->header_size = sizeof(*hdr);
	hdr->record_size = sizeof(struct mail_index_record);
	hdr->keywords_mask_size = sizeof(keywords_mask_t);

#ifndef WORDS_BIGENDIAN
	hdr->compat_data[0] = MAIL_INDEX_COMPAT_LITTLE_ENDIAN;
#endif
	hdr->compat_data[1] = sizeof(uoff_t);
	hdr->compat_data[2] = sizeof(time_t);

	hdr->indexid = now;

	hdr->next_uid = 1;
}

/* returns -1 = error, 0 = won't create, 1 = ok */
static int mail_index_open_files(struct mail_index *index,
				 enum mail_index_open_flags flags)
{
	struct mail_index_header hdr;
	unsigned int lock_id = 0;
	int ret;

	ret = mail_index_try_open(index, &lock_id);
	if (ret > 0)
		hdr = *index->hdr;
	else if (ret == 0) {
		/* doesn't exist, or corrupted */
		if ((flags & MAIL_INDEX_OPEN_FLAG_CREATE) == 0)
			return 0;
		mail_index_header_init(&hdr);
		index->hdr = &hdr;
	} else if (ret < 0)
		return -1;

	index->indexid = hdr.indexid;

	index->log = mail_transaction_log_open_or_create(index);
	if (index->log == NULL)
		return -1;

	if (index->fd == -1) {
		if (lock_id != 0) {
			mail_index_unlock(index, lock_id);
			lock_id = 0;
		}
		if (mail_index_create(index, &hdr) < 0)
			return -1;
	}

	if (lock_id == 0) {
		if (mail_index_lock_shared(index, FALSE, &lock_id) < 0)
			return -1;

	}

	index->cache = mail_cache_open_or_create(index);
	if (index->cache == NULL)
		return -1;

	mail_index_unlock(index, lock_id);
	return 1;
}

int mail_index_open(struct mail_index *index, enum mail_index_open_flags flags)
{
	int i = 0, ret;

	if (index->opened)
		return 0;

	index->filepath = i_strconcat(index->dir, "/", index->prefix, NULL);

	do {
		index->shared_lock_count = 0;
		index->excl_lock_count = 0;
		index->lock_type = F_UNLCK;
		index->lock_id = 2;

		index->nodiskspace = FALSE;
		index->index_lock_timeout = FALSE;
		index->log_locked = FALSE;
		index->mmap_disable =
			(flags & MAIL_INDEX_OPEN_FLAG_MMAP_DISABLE) != 0;
		index->mmap_no_write =
			(flags & MAIL_INDEX_OPEN_FLAG_MMAP_NO_WRITE) != 0;
		index->fcntl_locks_disable =
			(flags & MAIL_INDEX_OPEN_FLAG_FCNTL_LOCKS_DISABLE) != 0;
		index->readonly = FALSE;

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
	} while (1);

	if (ret <= 0)
		mail_index_close(index);

	return ret;
}

void mail_index_close(struct mail_index *index)
{
	if (index->log != NULL) {
		mail_transaction_log_close(index->log);
		index->log = NULL;
	}

	if (index->map != NULL) {
		mail_index_unmap(index, index->map);
		index->map = NULL;
	}

	if (index->cache != NULL) {
		mail_cache_free(index->cache);
		index->cache = NULL;
	}

	if (index->fd != -1) {
		if (close(index->fd) < 0)
			mail_index_set_syscall_error(index, "close()");
		index->fd = -1;
	}

	i_free(index->copy_lock_path);
	index->copy_lock_path = NULL;
	i_free(index->filepath);
	index->filepath = NULL;

	index->indexid = 0;
	index->opened = FALSE;
}

int mail_index_reopen(struct mail_index *index, int fd)
{
	struct mail_index_map *old_map;
	unsigned int old_shared_locks, old_lock_id, lock_id = 0;
	int ret, old_fd, old_lock_type;

	old_map = index->map;
	old_fd = index->fd;

	index->map = NULL;
	index->hdr = NULL;

	/* new file, new locks. the old fd can keep it's locks, they don't
	   matter anymore as no-one's going to modify the file. */
	old_lock_type = index->lock_type;
	old_lock_id = index->lock_id;
	old_shared_locks = index->shared_lock_count;
 
	if (index->lock_type == F_RDLCK)
		index->lock_type = F_UNLCK;
	index->lock_id += 2;
	index->shared_lock_count = 0;

	if (fd != -1) {
		index->fd = fd;
		ret = 0;
	} else {
		i_assert(index->excl_lock_count == 0);
		ret = mail_index_try_open_only(index);
		if (ret > 0)
			ret = mail_index_lock_shared(index, FALSE, &lock_id);
		else if (ret == 0) {
			/* index file is lost */
			ret = -1;
		}
	}

	if (ret == 0) {
		if (mail_index_map(index, FALSE) <= 0)
			ret = -1;
	}

	if (lock_id != 0)
		mail_index_unlock(index, lock_id);

	if (ret == 0) {
		mail_index_unmap(index, old_map);
		if (close(old_fd) < 0)
			mail_index_set_syscall_error(index, "close()");
	} else {
		if (index->map != NULL)
			mail_index_unmap(index, index->map);
		if (index->fd != -1) {
			if (close(index->fd) < 0)
				mail_index_set_syscall_error(index, "close()");
		}

		index->map = old_map;
		index->hdr = index->map->hdr;
		index->fd = old_fd;
		index->lock_type = old_lock_type;
		index->lock_id = old_lock_id;
		index->shared_lock_count = old_shared_locks;
	}
	return ret;
}

int mail_index_refresh(struct mail_index *index)
{
	struct stat st1, st2;

	if (fstat(index->fd, &st1) < 0)
		return mail_index_set_syscall_error(index, "fstat()");
	if (stat(index->filepath, &st2) < 0) {
		mail_index_set_syscall_error(index, "stat()");
		if (errno != ENOENT)
			return -1;

		/* lost it? recreate */
		(void)mail_index_mark_corrupted(index);
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

void mail_index_mark_corrupted(struct mail_index *index)
{
	struct mail_index_header hdr;

	mail_index_set_inconsistent(index);

	if (index->readonly)
		return;

	/* make sure we can write the header */
	if (!MAIL_INDEX_MAP_IS_IN_MEMORY(index->map)) {
		if (mprotect(index->map->mmap_base, sizeof(hdr),
			     PROT_READ | PROT_WRITE) < 0) {
			mail_index_set_syscall_error(index, "mprotect()");
			return;
		}
	}

	hdr = *index->hdr;
	hdr.flags |= MAIL_INDEX_HDR_FLAG_CORRUPTED;
	if (mail_index_write_base_header(index, &hdr) == 0) {
		if (fsync(index->fd) < 0)
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
