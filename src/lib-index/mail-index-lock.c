/* Copyright (C) 2003-2004 Timo Sirainen */

/*
   Locking is meant to be as transparent as possible. Anything that locks
   the index must either keep it only a short time, or be prepared that the
   lock is lost.

   Lock is lost in only one situation: when we try to get an exclusive lock
   but we already have a shared lock. Then we'll drop all shared locks and
   get the exclusive lock.

   Locking should never fail or timeout. Exclusive locks must be kept as short
   time as possible. Shared locks can be long living, so if can't get exclusive
   lock directly within 2 seconds, we'll replace the index file with a copy of
   it. That means the shared lock holders can keep using the old file while
   we're modifying the new file.

   lock_id is used to figure out if acquired lock is still valid. Shared
   locks have even numbers, exclusive locks have odd numbers. The number is
   increased by two every time the lock is dropped.

   mail_index_lock_shared() -> lock_id=2
   mail_index_lock_shared() -> lock_id=2
   mail_index_lock_exclusive() -> lock_id=5 (had to drop shared locks)
   mail_index_lock_shared() -> lock_id=4

   Only 4 and 5 locks are valid at this time.
*/

#include "lib.h"
#include "mmap-util.h"
#include "file-lock.h"
#include "write-full.h"
#include "mail-index-private.h"

#include <stdio.h>
#include <sys/stat.h>

static int mail_index_reopen(struct mail_index *index, int fd)
{
	int ret;

	mail_index_unmap(index, index->map);
	index->map = NULL;

	if (close(index->fd) < 0)
		mail_index_set_syscall_error(index, "close()");
	index->fd = fd;

	ret = fd < 0 ? mail_index_try_open(index, NULL) :
		mail_index_map(index, FALSE);
	if (ret <= 0) {
		// FIXME: serious problem, we'll just crash later..
		return -1;
	}

	return 0;
}

static int mail_index_has_changed(struct mail_index *index)
{
	struct stat st1, st2;

	if (fstat(index->fd, &st1) < 0)
		return mail_index_set_syscall_error(index, "fstat()");
	if (stat(index->filepath, &st2) < 0)
		return mail_index_set_syscall_error(index, "stat()");

	if (st1.st_ino != st2.st_ino ||
	    !CMP_DEV_T(st1.st_dev, st2.st_dev)) {
		if (mail_index_reopen(index, -1) < 0)
			return -1;
		return 1;
	} else {
		return 0;
	}
}

static int mail_index_lock(struct mail_index *index, int lock_type,
			   unsigned int timeout_secs, int update_index,
			   unsigned int *lock_id_r)
{
	int ret;

	i_assert(lock_type == F_RDLCK || lock_type == F_WRLCK);

	if (lock_type == F_WRLCK && index->lock_type == F_RDLCK) {
		/* drop shared locks */
		i_assert(index->excl_lock_count == 0);

		if (file_wait_lock(index->fd, F_UNLCK) < 0)
			mail_index_set_syscall_error(index, "file_wait_lock()");

		index->shared_lock_count = 0;
		index->lock_type = F_UNLCK;
		index->lock_id += 2; /* make sure failures below work right */
	}

	if (index->excl_lock_count > 0 || index->shared_lock_count > 0) {
		i_assert(lock_type == F_RDLCK || index->excl_lock_count > 0);
		if (lock_type == F_RDLCK) {
			index->shared_lock_count++;
			*lock_id_r = index->lock_id;
		} else {
			index->excl_lock_count++;
			*lock_id_r = index->lock_id + 1;
		}
		return 1;
	}

	i_assert(index->lock_type == F_UNLCK);

	if (update_index && lock_type != F_WRLCK) {
		if (mail_index_has_changed(index) < 0)
			return -1;
	}

	do {
		ret = file_wait_lock_full(index->fd, lock_type, timeout_secs,
					  NULL, NULL);
		if (ret <= 0) {
			if (ret == 0)
				return 0;
			mail_index_set_syscall_error(index, "file_wait_lock()");
			return -1;
		}

		if (lock_type == F_WRLCK) {
			/* we need to have the latest index file locked -
			   check if it's been updated. */
			if ((ret = mail_index_has_changed(index)) < 0) {
				(void)file_wait_lock(index->fd, F_UNLCK);
				return -1;
			}
			if (ret > 0)
				continue;
		}
	} while (0);

	index->lock_type = lock_type;
	index->lock_id += 2;

	if (lock_type == F_RDLCK) {
		index->shared_lock_count++;
		*lock_id_r = index->lock_id;
	} else {
		index->excl_lock_count++;
		*lock_id_r = index->lock_id + 1;
	}

	if (index->map != NULL &&
	    !MAIL_INDEX_MAP_IS_IN_MEMORY(index->map)) {
		int prot = PROT_READ | (lock_type == F_WRLCK ? PROT_WRITE : 0);
		if (mprotect(index->map->mmap_base,
			     index->map->file_size, prot) < 0) {
			mail_index_set_syscall_error(index, "mprotect()");
			return -1;
		}
	}

	return 1;
}

int mail_index_lock_shared(struct mail_index *index, int update_index,
			   unsigned int *lock_id_r)
{
	int ret;

	ret = mail_index_lock(index, F_RDLCK, DEFAULT_LOCK_TIMEOUT,
			      update_index, lock_id_r);
	if (ret > 0)
		return 0;
	if (ret < 0)
		return -1;

	mail_index_set_error(index, "Timeout while waiting for release of "
			     "shared fcntl() lock for index file %s",
			     index->filepath);
	index->index_lock_timeout = TRUE;
	return -1;
}

static int mail_index_copy(struct mail_index *index)
{
	const char *path;
	int ret, fd;

	fd = mail_index_create_tmp_file(index, &path);
	if (fd == -1)
		return -1;

	ret = write_full(fd, index->map->hdr, sizeof(*index->map->hdr));
	if (ret < 0 || write_full(fd, index->map->records,
				  index->map->records_count *
				  sizeof(struct mail_index_record)) < 0) {
		mail_index_file_set_syscall_error(index, path, "write_full()");
		(void)close(fd);
		(void)unlink(path);
		return -1;
	}

	i_assert(index->copy_lock_path == NULL);
	index->copy_lock_path = i_strdup(path);
	return fd;
}

static int mail_index_need_lock(struct mail_index *index,
				uint32_t log_file_seq, uoff_t log_file_offset)
{
	if (mail_index_map(index, FALSE) <= 0)
		return 1;

	if (log_file_seq != 0 &&
	    (index->hdr->log_file_seq > log_file_seq ||
	     (index->hdr->log_file_seq == log_file_seq &&
	      index->hdr->log_file_offset >= log_file_offset))) {
		/* already synced */
		return 0;
	}

	return 1;
}

static int mail_index_lock_exclusive_copy(struct mail_index *index)
{
	int fd;

	i_assert(index->log_locked);

	if (index->copy_lock_path != NULL) {
		index->excl_lock_count++;
		return 1;
	}

	/* copy the index to index.tmp and use it. when */
	fd = mail_index_copy(index);
	if (fd == -1)
		return -1;

	index->lock_type = F_WRLCK;
        index->excl_lock_count++;

	if (mail_index_reopen(index, fd) < 0) {
		/* FIXME: do this without another reopen which drops locks
		   and causes potential crashes */
		i_assert(index->excl_lock_count == 1);
		i_free(index->copy_lock_path);
		index->copy_lock_path = NULL;

		/* go back to old index */
		(void)mail_index_reopen(index, -1);

		index->lock_type = F_UNLCK;
		index->excl_lock_count = 0;
		index->shared_lock_count = 0;
		return -1;
	}

        i_assert(index->excl_lock_count == 1);
	return 1;
}

int mail_index_lock_exclusive(struct mail_index *index,
			      uint32_t log_file_seq, uoff_t log_file_offset,
			      unsigned int *lock_id_r)
{
	unsigned int lock_id;
	int ret;

	/* exclusive transaction log lock protects exclusive locking
	   for the main index file */
	i_assert(index->log_locked);

	/* wait two seconds for exclusive lock */
	ret = mail_index_lock(index, F_WRLCK, 2, TRUE, lock_id_r);
	if (ret > 0) {
		if (mail_index_need_lock(index, log_file_seq, log_file_offset))
			return 1;

		mail_index_unlock(index, *lock_id_r);
		return 0;
	}
	if (ret < 0)
		return -1;

	/* Grab shared lock to make sure it's not already being
	   exclusively locked */
	if (mail_index_lock_shared(index, TRUE, &lock_id) < 0)
		return -1;

	if (log_file_seq != 0) {
		/* check first if we really need to recreate it */
		ret = mail_index_need_lock(index, log_file_seq,
					   log_file_offset);
		if (ret == 0) {
			mail_index_unlock(index, lock_id);
			return 0;
		}
	}

	mail_index_unlock(index, lock_id);

	*lock_id_r = 0;
	return mail_index_lock_exclusive_copy(index);
}

static int mail_index_copy_lock_finish(struct mail_index *index)
{
	if (index->shared_lock_count > 0) {
		/* leave ourself shared locked. */
		if (file_try_lock(index->fd, F_RDLCK) <= 0) {
			mail_index_file_set_syscall_error(index,
							  index->copy_lock_path,
							  "file_try_lock()");
			return -1;
		}
		index->lock_id--;
	}

	if (fsync(index->fd) < 0) {
		mail_index_file_set_syscall_error(index, index->copy_lock_path,
						  "fsync()");
		return -1;
	}

	if (rename(index->copy_lock_path, index->filepath) < 0) {
		mail_index_set_error(index, "rename(%s, %s) failed: %m",
				     index->copy_lock_path, index->filepath);
		return -1;
	}

	i_free(index->copy_lock_path);
	index->copy_lock_path = NULL;
	return 0;
}

static void mail_index_excl_unlock_finish(struct mail_index *index)
{
	if (index->map != NULL && index->map->write_to_disk) {
		i_assert(index->log_locked);

		if (index->copy_lock_path != NULL) {
			/* new mapping replaces the old */
			(void)unlink(index->copy_lock_path);
			i_free(index->copy_lock_path);
			index->copy_lock_path = NULL;
		}
		if (mail_index_copy(index) < 0)
			mail_index_set_inconsistent(index);
	}

	if (index->copy_lock_path != NULL) {
		i_assert(index->log_locked);

		if (mail_index_copy_lock_finish(index) < 0)
			mail_index_set_inconsistent(index);
	}
}

void mail_index_unlock(struct mail_index *index, unsigned int lock_id)
{
	if ((lock_id & 1) == 0) {
		/* shared lock */
		if (mail_index_is_locked(index, lock_id)) {
			i_assert(index->shared_lock_count > 0);
			index->shared_lock_count--;
		}
	} else {
		/* exclusive lock */
		i_assert(lock_id == index->lock_id+1);
		i_assert(index->excl_lock_count > 0);
		if (--index->excl_lock_count == 0)
			mail_index_excl_unlock_finish(index);
	}

	if (index->shared_lock_count == 0 && index->excl_lock_count == 0) {
		index->lock_id += 2;
		index->lock_type = F_UNLCK;
		if (index->map != NULL &&
		    !MAIL_INDEX_MAP_IS_IN_MEMORY(index->map)) {
			if (mprotect(index->map->mmap_base,
				     index->map->file_size, PROT_NONE) < 0)
				mail_index_set_syscall_error(index,
							     "mprotect()");
		}
		if (file_wait_lock(index->fd, F_UNLCK) < 0)
			mail_index_set_syscall_error(index, "file_wait_lock()");
	}
}

int mail_index_is_locked(struct mail_index *index, unsigned int lock_id)
{
	return (index->lock_id ^ lock_id) <= 1;
}
