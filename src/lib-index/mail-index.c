/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "file-lock.h"
#include "mmap-util.h"
#include "write-full.h"
#include "mail-index-private.h"
#include "mail-transaction-log.h"

#include <stdio.h>
#include <stddef.h>
#include <time.h>

struct mail_index *mail_index_alloc(const char *dir, const char *prefix)
{
	struct mail_index *index;

	index = i_new(struct mail_index, 1);
	index->dir = i_strdup(dir);
	index->prefix = i_strdup(prefix);
	index->fd = -1;

	index->mode = 0600;
	index->gid = (gid_t)-1;
	return index;
}

void mail_index_free(struct mail_index *index)
{
	i_free(index->error);
	i_free(index->dir);
	i_free(index->prefix);
	i_free(index);
}

static int mail_index_check_quick_header(struct mail_index *index,
					 struct mail_index_map *map,
					 const struct mail_index_header *hdr)
{
	if ((hdr->flags & MAIL_INDEX_HDR_FLAG_CORRUPTED) != 0) {
		/* either a crash or we've already complained about it */
		return -1;
	}

	if (map->mmap_used_size > map->mmap_size) {
		map->records_count =
			(map->mmap_size - hdr->header_size) /
			sizeof(struct mail_index_record);
		map->mmap_used_size = map->mmap_size;

		mail_index_set_error(index, "Corrupted index file %s: "
				     "messages_count too large (%u > %u)",
				     index->filepath, hdr->messages_count,
				     map->records_count);
		return 0;
	}

	return 1;
}

static int mail_index_check_header(struct mail_index *index,
				   struct mail_index_map *map,
				   const struct mail_index_header *hdr)
{
	unsigned char compat_data[3];
	int ret;

#ifndef WORDS_BIGENDIAN
	compat_data[0] = MAIL_INDEX_COMPAT_LITTLE_ENDIAN;
#else
	compat_data[0] = 0;
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

	if ((ret = mail_index_check_quick_header(index, map, hdr)) <= 0)
		return ret;

	/* following some extra checks that only take a bit of CPU */
	if (hdr->uid_validity == 0) {
		mail_index_set_error(index, "Corrupted index file %s: "
				     "uid_validity = 0", index->filepath);
		return -1;
	}

	if (hdr->next_uid == 0)
		return 0;

	if (hdr->seen_messages_count > hdr->messages_count ||
	    hdr->deleted_messages_count > hdr->messages_count)
		return 0;
	if (hdr->first_recent_uid_lowwater > hdr->next_uid ||
	    hdr->first_unseen_uid_lowwater > hdr->next_uid ||
	    hdr->first_deleted_uid_lowwater > hdr->next_uid)
		return 0;

	return 1;
}

void mail_index_unmap(struct mail_index *index, struct mail_index_map *map)
{
	if (--map->refcount > 0)
		return;

	if (map->buffer != NULL) {
		i_assert(map->mmap_base == NULL);
		buffer_free(map->buffer);
	} else {
		i_assert(map->buffer == NULL);
		if (munmap(map->mmap_base, map->mmap_size) < 0)
			mail_index_set_syscall_error(index, "munmap()");
	}
	i_free(map);
}

int mail_index_map(struct mail_index *index, int force)
{
	const struct mail_index_header *hdr;
	struct mail_index_map *map;
	size_t used_size;
	int ret;

	if (!index->use_mmap) {
		// FIXME
		return -1;
	}

	if (index->map != NULL) {
		map = index->map;

		/* see if re-mmaping is needed (file has grown) */
		hdr = map->mmap_base;
                used_size = hdr->header_size +
			hdr->messages_count * sizeof(struct mail_index_record);
		if (map->mmap_size >= used_size && !force)
			return 1;

		if (munmap(map->mmap_base, map->mmap_size) < 0)
			mail_index_set_syscall_error(index, "munmap()");
		map->mmap_base = NULL;
	} else {
		map = i_new(struct mail_index_map, 1);
		map->refcount = 1;
	}

	index->hdr = NULL;
	index->map = NULL;

	map->mmap_base = mmap_ro_file(index->fd, &map->mmap_size);
	if (map->mmap_base == MAP_FAILED) {
		map->mmap_base = NULL;
		mail_index_set_syscall_error(index, "mmap()");
		mail_index_unmap(index, map);
		return -1;
	}

	if (map->mmap_size < MAIL_INDEX_HEADER_MIN_SIZE) {
		mail_index_set_error(index, "Corrupted index file %s: "
				     "File too small (%"PRIuSIZE_T")",
				     index->filepath, map->mmap_size);
		mail_index_unmap(index, map);
		return 0;
	}

	hdr = map->mmap_base;
	if (hdr->header_size < sizeof(*hdr)) {
		/* header smaller than ours, make a copy so our newer headers
		   won't have garbage in them */
		memcpy(&map->hdr_copy, hdr, hdr->header_size);
		hdr = &map->hdr_copy;
	}

	map->hdr = map->mmap_base;
	map->records = PTR_OFFSET(map->mmap_base, hdr->header_size);
	map->records_count = hdr->messages_count;
	map->mmap_used_size = hdr->header_size +
		map->records_count * sizeof(struct mail_index_record);

	ret = mail_index_check_header(index, map, hdr);
	if (ret < 0) {
		mail_index_unmap(index, map);
		return 0;
	}
	if (ret == 0)
		index->fsck = TRUE;

	index->hdr = map->mmap_base;
	index->map = map;
	return 1;
}

struct mail_index_map *mail_index_map_to_memory(struct mail_index_map *map)
{
	const struct mail_index_header *hdr;
	struct mail_index_map *mem_map;
	size_t size;

	if (MAIL_INDEX_MAP_IS_IN_MEMORY(map)) {
		map->refcount++;
		return map;
	}

        size = map->records_count * sizeof(struct mail_index_record);

	mem_map = i_new(struct mail_index_map, 1);
	mem_map->refcount = 1;
	mem_map->buffer = buffer_create_dynamic(default_pool, size, (size_t)-1);
	buffer_append(mem_map->buffer, map->records, size);

	mem_map->records = buffer_get_modifyable_data(mem_map->buffer, NULL);
	mem_map->records_count = map->records_count;

	hdr = map->mmap_base;
	memcpy(&mem_map->hdr_copy, map->mmap_base,
	       I_MIN(hdr->header_size, sizeof(mem_map->hdr_copy)));
	mem_map->hdr = &mem_map->hdr_copy;
	return mem_map;
}

void mail_index_header_init(struct mail_index_header *hdr)
{
	time_t now = time(NULL);

	memset(hdr, 0, sizeof(*hdr));

	hdr->major_version = MAIL_INDEX_MAJOR_VERSION;
	hdr->minor_version = MAIL_INDEX_MINOR_VERSION;
	hdr->header_size = sizeof(*hdr);

#ifndef WORDS_BIGENDIAN
	hdr->compat_data[0] = MAIL_INDEX_COMPAT_LITTLE_ENDIAN;
#endif
	hdr->compat_data[1] = sizeof(uoff_t);
	hdr->compat_data[2] = sizeof(time_t);

	hdr->indexid = now;

	hdr->uid_validity = now;
	hdr->next_uid = 1;
}

int mail_index_write_header(struct mail_index *index,
			    const struct mail_index_header *hdr)
{
	if (index->use_mmap) {
		if (mprotect(index->map->mmap_base, sizeof(*hdr),
			     PROT_READ | PROT_WRITE) < 0) {
			mail_index_set_syscall_error(index, "mprotect()");
			return -1;
		}

		memcpy(index->map->mmap_base, hdr, sizeof(*hdr));
		if (msync(index->map->mmap_base, sizeof(*hdr), MS_SYNC) < 0)
			return mail_index_set_syscall_error(index, "msync()");

		if (mprotect(index->map->mmap_base, sizeof(*hdr),
			     PROT_READ) < 0) {
			mail_index_set_syscall_error(index, "mprotect()");
			return -1;
		}
	} else {
		if (pwrite_full(index->fd, hdr, sizeof(*hdr), 0) < 0) {
			mail_index_set_syscall_error(index, "pwrite_full()");
			return -1;
		}

		index->map->hdr_copy = *hdr;
		index->hdr = &index->map->hdr_copy;
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

int mail_index_create(struct mail_index *index, struct mail_index_header *hdr)
{
	const char *path;
	uint32_t seq;
	uoff_t offset;
	int ret;

	/* log file lock protects index creation */
	if (mail_transaction_log_sync_lock(index->log, &seq, &offset) < 0)
		return -1;

	hdr->log_file_seq = seq;
	hdr->log_file_offset = offset;

	ret = mail_index_try_open(index);
	if (ret != 0) {
		mail_transaction_log_sync_unlock(index->log);
		return ret;
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
		return -1;
	}

	/* make it visible to others */
	if (rename(path, index->filepath) < 0) {
		mail_index_set_error(index, "rename(%s, %s) failed: %m",
				     path, index->filepath);
		return -1;
	}

	mail_transaction_log_sync_unlock(index->log);
	return 1;
}

int mail_index_try_open(struct mail_index *index)
{
	unsigned int lock_id;
	int ret;

	index->fd = open(index->filepath, O_RDWR);
	if (index->fd == -1 && errno == EACCES) {
		index->fd = open(index->filepath, O_RDONLY);
		index->readonly = TRUE;
	}
	if (index->fd == -1) {
		if (errno != ENOENT)
			return mail_index_set_syscall_error(index, "open()");

		/* have to create it */
		return 0;
	} else {
		if (mail_index_lock_shared(index, FALSE, &lock_id) < 0)
			return -1;
		ret = mail_index_map(index, FALSE);
		mail_index_unlock(index, lock_id);

		if (ret == 0) {
			/* it's corrupted - recreate it */
			(void)close(index->fd);
			index->fd = -1;
		}
		return ret;
	}
}

static int
mail_index_open2(struct mail_index *index, enum mail_index_open_flags flags)
{
        struct mail_index_header hdr;
	int ret;

	ret = mail_index_try_open(index);
	if (ret == 1)
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
	return index->fd != -1 ? 1 : mail_index_create(index, &hdr);
}

int mail_index_open(struct mail_index *index, enum mail_index_open_flags flags)
{
	int i = 0, ret;

	if (index->opened)
		return 0;

	do {
		index->shared_lock_count = 0;
		index->excl_lock_count = 0;
		index->lock_type = F_UNLCK;

		index->nodiskspace = FALSE;
		index->index_lock_timeout = FALSE;
		index->log_locked = FALSE;
		index->use_mmap = (flags & MAIL_INDEX_OPEN_FLAG_NO_MMAP) == 0;
		index->readonly = FALSE;

		index->filepath = i_strconcat(index->dir, "/",
					      index->prefix, NULL);
		ret = mail_index_open2(index, flags);
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

	mail_index_unmap(index, index->map);
	index->map = NULL;

	if (index->fd != -1) {
		if (close(index->fd) < 0)
			mail_index_set_syscall_error(index, "close()");
		index->fd = -1;
	}

	i_free(index->copy_lock_path);
	i_free(index->filepath);
	index->filepath = NULL;

	index->indexid = 0;
	index->opened = FALSE;
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

int mail_index_mark_corrupted(struct mail_index *index)
{
	struct mail_index_header hdr;

	if (index->readonly || index->hdr == NULL ||
	    (index->hdr->flags & MAIL_INDEX_HDR_FLAG_CORRUPTED) != 0)
		return 0;

	hdr = *index->hdr;
	hdr.flags |= MAIL_INDEX_HDR_FLAG_CORRUPTED;
	if (mail_index_write_header(index, &hdr) < 0)
		return -1;

	if (fsync(index->fd) < 0)
		return mail_index_set_syscall_error(index, "fsync()");
	return 0;
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

int mail_index_is_in_memory(struct mail_index *index)
{
	return FALSE; // FIXME
}
