/* Copyright (C) 2003-2004 Timo Sirainen */

/*
   Locking should never fail or timeout. Exclusive locks must be kept as short
   time as possible. Shared locks can be long living, so if we can't get
   exclusive lock directly within 2 seconds, we'll replace the index file with
   a copy of it. That means the shared lock holders can keep using the old file
   while we're modifying the new file.

   lock_id is used to figure out if acquired lock is still valid. When index
   file is reopened, the lock_id can become invalid. It doesn't matter however,
   as no-one's going to modify the old file anymore.

   lock_id also tells if we're referring to shared or exclusive lock. This
   allows us to drop back to shared locking once all exclusive locks are
   dropped. Shared locks have even numbers, exclusive locks have odd numbers.
   The number is increased by two every time the lock is dropped or index file
   is reopened.
*/

#include "lib.h"
#include "buffer.h"
#include "mmap-util.h"
#include "write-full.h"
#include "mail-index-private.h"

#include <stdio.h>
#include <sys/stat.h>

#ifdef HAVE_FLOCK
#  include <sys/file.h>
#endif

int mail_index_lock_fd(struct mail_index *index, const char *path, int fd,
		       int lock_type, unsigned int timeout_secs,
		       struct file_lock **lock_r)
{
	if (fd == -1) {
		i_assert(MAIL_INDEX_IS_IN_MEMORY(index));
		return 1;
	}

	return file_wait_lock(fd, path, lock_type, index->lock_method,
			      timeout_secs, lock_r);
}

static int mail_index_lock(struct mail_index *index, int lock_type,
			   unsigned int timeout_secs, int update_index,
			   unsigned int *lock_id_r)
{
	int ret, ret2;

	i_assert(lock_type == F_RDLCK || lock_type == F_WRLCK);

	if (lock_type == F_RDLCK && index->lock_type != F_UNLCK) {
		index->shared_lock_count++;
		*lock_id_r = index->lock_id;
		ret = 1;
	} else if (lock_type == F_WRLCK && index->lock_type == F_WRLCK) {
		index->excl_lock_count++;
		*lock_id_r = index->lock_id + 1;
		ret = 1;
	} else {
		ret = 0;
	}

	if (update_index && index->excl_lock_count == 0) {
		/* we wish to have the latest available index file. */
		i_assert(index->lock_type != F_WRLCK);
		if ((ret2 = mail_index_reopen_if_needed(index)) < 0)
			return -1;
		if (ret > 0 && ret2 == 0) {
			/* no new file and the old file is already locked */
			i_assert(lock_type == F_RDLCK);
			i_assert(index->lock_type == F_RDLCK);
			return 1;
		}
		ret = 0;
	}

	if (ret > 0) {
		/* file is already locked */
		return 1;
	}

	if (index->lock_method == FILE_LOCK_METHOD_DOTLOCK &&
	    !MAIL_INDEX_IS_IN_MEMORY(index)) {
		/* FIXME: exclusive locking will rewrite the index file every
		   time. shouldn't really be needed.. reading doesn't require
		   locks then, though */
		if (lock_type == F_WRLCK)
			return 0;
		if (update_index && index->lock_type == F_UNLCK) {
			if (mail_index_reopen_if_needed(index) < 0)
				return -1;
		}

		index->shared_lock_count++;
		index->lock_type = F_RDLCK;
		*lock_id_r = index->lock_id;
		return 1;
	}

	if (lock_type == F_RDLCK || !index->log_locked) {
		i_assert(index->file_lock == NULL);
		ret = mail_index_lock_fd(index, index->filepath, index->fd,
					 lock_type, timeout_secs,
					 &index->file_lock);
	} else {
		/* this is kind of kludgy. we wish to avoid deadlocks while
		   trying to lock transaction log, but it can happen if our
		   process is holding transaction log lock and waiting for
		   index write lock, while the other process is holding index
		   read lock and waiting for transaction log lock.

		   we don't have a problem with grabbing read index lock
		   because the only way for it to block is if it's
		   write-locked, which isn't allowed unless transaction log
		   is also locked.

		   so, the workaround for this problem is that we simply try
		   locking once. if it doesn't work, just rewrite the file.
		   hopefully there won't be any other deadlocking issues. :) */
		if (index->file_lock == NULL) {
			ret = mail_index_lock_fd(index, index->filepath,
						 index->fd, lock_type, 0,
						 &index->file_lock);
		} else {
			ret = file_lock_try_update(index->file_lock, lock_type);
		}
	}
	if (ret <= 0)
		return ret;

	if (index->lock_type == F_UNLCK)
		index->lock_id += 2;
	index->lock_type = lock_type;

	if (lock_type == F_RDLCK) {
		index->shared_lock_count++;
		*lock_id_r = index->lock_id;
	} else {
		index->excl_lock_count++;
		*lock_id_r = index->lock_id + 1;
	}

	return 1;
}

int mail_index_lock_shared(struct mail_index *index, bool update_index,
			   unsigned int *lock_id_r)
{
	int ret;

	ret = mail_index_lock(index, F_RDLCK, MAIL_INDEX_LOCK_SECS,
			      update_index, lock_id_r);
	if (ret > 0)
		return 0;
	if (ret < 0)
		return -1;

	mail_index_set_error(index,
		"Timeout while waiting for shared lock for index file %s",
		index->filepath);
	index->index_lock_timeout = TRUE;
	return -1;
}

static int mail_index_copy(struct mail_index *index)
{
	struct mail_index_map *map = index->map;
	unsigned int base_size;
	const char *path;
	int ret, fd;

	i_assert(!MAIL_INDEX_IS_IN_MEMORY(index));

	fd = mail_index_create_tmp_file(index, &path);
	if (fd == -1)
		return -1;

	/* write base header */
	base_size = I_MIN(map->hdr.base_header_size, sizeof(map->hdr));
	ret = write_full(fd, &map->hdr, base_size);
	if (ret == 0) {
		/* write extended headers */
		ret = write_full(fd, CONST_PTR_OFFSET(map->hdr_base, base_size),
				 map->hdr.header_size - base_size);
	}

	if (ret < 0 || write_full(fd, map->records, map->records_count *
				  map->hdr.record_size) < 0) {
		mail_index_file_set_syscall_error(index, path, "write_full()");
		(void)close(fd);
		(void)unlink(path);
		fd = -1;
	} else {
		i_assert(index->copy_lock_path == NULL);
		index->copy_lock_path = i_strdup(path);
	}

	return fd;
}

static int mail_index_lock_exclusive_copy(struct mail_index *index)
{
	int fd, old_lock_type;

	i_assert(index->log_locked);

	if (index->copy_lock_path != NULL) {
		index->excl_lock_count++;
		return 0;
	}

        i_assert(index->excl_lock_count == 0);

	/* copy the index to index.tmp and use it */
	fd = mail_index_copy(index);
	if (fd == -1) {
		if (!index->nodiskspace)
			return -1;

		if (mail_index_move_to_memory(index) < 0)
			return -1;
		index->lock_type = F_WRLCK;
		index->excl_lock_count++;
		return 0;
	}

	old_lock_type = index->lock_type;
	index->lock_type = F_WRLCK;

	if (mail_index_reopen(index, fd) < 0) {
		(void)close(fd);
		if (unlink(index->copy_lock_path) < 0) {
			mail_index_file_set_syscall_error(index,
							  index->copy_lock_path,
							  "unlink()");
		}
		i_free(index->copy_lock_path);
		index->copy_lock_path = NULL;

		index->lock_type = old_lock_type;
		return -1;
	}

	index->excl_lock_count++;
	return 0;
}

int mail_index_lock_exclusive(struct mail_index *index,
			      unsigned int *lock_id_r)
{
	int ret;

	/* exclusive transaction log lock protects exclusive locking
	   for the main index file */
	i_assert(index->log_locked);

	/* if header size is smaller than what we have, we'll have to recreate
	   the index to grow it. so don't even try regular locking. */
	if (index->map->hdr.base_header_size >= sizeof(*index->hdr) ||
	    index->excl_lock_count > 0) {
		/* wait two seconds for exclusive lock */
		ret = mail_index_lock(index, F_WRLCK, 2, TRUE, lock_id_r);
		if (ret > 0)
			return 0;
		if (ret < 0)
			return -1;
	}
	if (mail_index_lock_exclusive_copy(index) < 0)
		return -1;
	*lock_id_r = index->lock_id + 1;
	return 0;
}

static int mail_index_copy_lock_finish(struct mail_index *index)
{
	int ret = 0;

	if (!index->fsync_disable) {
		if (fsync(index->fd) < 0) {
			mail_index_file_set_syscall_error(index,
							  index->copy_lock_path,
							  "fsync()");
			ret = -1;
		}
	}

	if (ret < 0 || MAIL_INDEX_IS_IN_MEMORY(index)) {
		/* fsync() failed / we've since moved to in-memory indexes */
		if (unlink(index->copy_lock_path) < 0) {
			mail_index_set_error(index, "unlink(%s) failed: %m",
					     index->copy_lock_path);
		}
	} else {
		if (rename(index->copy_lock_path, index->filepath) < 0) {
			mail_index_set_error(index, "rename(%s, %s) failed: %m",
					     index->copy_lock_path,
					     index->filepath);
			ret = -1;
		}
	}

	i_free(index->copy_lock_path);
	index->copy_lock_path = NULL;
	return ret;
}

static int mail_index_write_map_over(struct mail_index *index)
{
	struct mail_index_map *map = index->map;
	unsigned int base_size;

	if (MAIL_INDEX_IS_IN_MEMORY(index))
		return 0;

	/* write records. */
	if (map->write_seq_first != 0) {
		size_t rec_offset =
			(map->write_seq_first-1) * map->hdr.record_size;

		if (pwrite_full(index->fd,
				CONST_PTR_OFFSET(map->records, rec_offset),
				(map->write_seq_last -
				 map->write_seq_first + 1) *
				map->hdr.record_size,
				map->hdr.header_size + rec_offset) < 0)
			return -1;
	}

	/* write base header */
	base_size = I_MIN(map->hdr.base_header_size, sizeof(map->hdr));
	if (pwrite_full(index->fd, &map->hdr, base_size, 0) < 0)
		return -1;

	/* write extended headers */
	if (pwrite_full(index->fd, CONST_PTR_OFFSET(map->hdr_base, base_size),
			map->hdr.header_size - base_size, base_size) < 0)
		return -1;
	return 0;
}

static int mail_index_copy_and_reopen(struct mail_index *index)
{
	int fd;

	fd = mail_index_copy(index);
	if (fd == -1) {
		if (!index->nodiskspace)
			return -1;
		return mail_index_move_to_memory(index);
	}

	if (mail_index_reopen(index, fd) < 0) {
		(void)close(fd);
		return -1;
	}
	return 0;
}

static void mail_index_write_map(struct mail_index *index)
{
	struct mail_index_map *map = index->map;

	if (map->write_atomic || index->copy_lock_path != NULL ||
	    index->fd == -1) {
		/* write by recreating the index */
		i_assert(index->log_locked);

		if (index->copy_lock_path != NULL) {
			/* new mapping replaces the old */
			(void)unlink(index->copy_lock_path);
			i_free(index->copy_lock_path);
			index->copy_lock_path = NULL;
		}

		if (!MAIL_INDEX_IS_IN_MEMORY(index)) {
			if (mail_index_copy_and_reopen(index) < 0)
				mail_index_set_inconsistent(index);
		}

	} else {
		/* write the modified parts. header is small enough to be
		   always written, write_seq_* specifies the record range. */
                if (mail_index_write_map_over(index) < 0)
			mail_index_set_inconsistent(index);
	}

	map->write_to_disk = FALSE;
	map->write_atomic = FALSE;
	map->write_seq_first = map->write_seq_last = 0;
}

static bool mail_index_excl_unlock_finish(struct mail_index *index)
{
	if (index->map != NULL && index->map->write_to_disk)
		mail_index_write_map(index);

	if (index->shared_lock_count > 0 &&
	    index->lock_method != FILE_LOCK_METHOD_DOTLOCK) {
		/* leave ourself shared locked. */
		i_assert(index->lock_type == F_WRLCK);
		index->lock_type = F_RDLCK;

		if (!MAIL_INDEX_IS_IN_MEMORY(index))
			(void)file_lock_try_update(index->file_lock, F_RDLCK);
	}

	if (index->copy_lock_path != NULL) {
		i_assert(index->log_locked);

		if (mail_index_copy_lock_finish(index) < 0)
			mail_index_set_inconsistent(index);

		/* We may still have shared locks for the old file, but they
		   don't matter. They're invalidated when we re-open the new
		   index file. */
		return FALSE;
	}
	return TRUE;
}

void mail_index_unlock(struct mail_index *index, unsigned int lock_id)
{
	bool unlock = TRUE;

	if ((lock_id & 1) == 0) {
		/* shared lock */
		if (!mail_index_is_locked(index, lock_id)) {
			/* unlocking some older generation of the index file.
			   we've already closed the file so just ignore this. */
			return;
		}

		i_assert(index->shared_lock_count > 0);
		index->shared_lock_count--;
	} else {
		/* exclusive lock */
		i_assert(lock_id == index->lock_id + 1);
		i_assert(index->excl_lock_count > 0);
		if (--index->excl_lock_count == 0)
			unlock = mail_index_excl_unlock_finish(index);
	}

	if (index->shared_lock_count == 0 && index->excl_lock_count == 0) {
		index->lock_id += 2;
		index->lock_type = F_UNLCK;
		if (index->lock_method != FILE_LOCK_METHOD_DOTLOCK) {
			if (unlock && !MAIL_INDEX_IS_IN_MEMORY(index))
				file_unlock(&index->file_lock);
		}
		i_assert(index->file_lock == NULL);
	}
}

bool mail_index_is_locked(struct mail_index *index, unsigned int lock_id)
{
	if ((index->lock_id ^ lock_id) <= 1) {
		i_assert(index->lock_type != F_UNLCK);
		return TRUE;
	}

	return FALSE;
}
