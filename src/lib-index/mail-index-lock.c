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
#include "mmap-util.h"
#include "file-lock.h"
#include "write-full.h"
#include "mail-index-private.h"

#include <stdio.h>
#include <sys/stat.h>

static int mail_index_reopen(struct mail_index *index, int fd)
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

static int mail_index_lock_mprotect(struct mail_index *index, int lock_type)
{
	int prot;

	if (index->map != NULL &&
	    !MAIL_INDEX_MAP_IS_IN_MEMORY(index->map)) {
		prot = lock_type == F_UNLCK ? PROT_NONE :
			lock_type == F_WRLCK ? (PROT_READ|PROT_WRITE) :
			PROT_READ;
		if (mprotect(index->map->mmap_base,
			     index->map->mmap_size, prot) < 0) {
			mail_index_set_syscall_error(index, "mprotect()");
			return -1;
		}
	}
	return 0;
}

static int mail_index_lock(struct mail_index *index, int lock_type,
			   unsigned int timeout_secs, int update_index,
			   unsigned int *lock_id_r)
{
	int ret;

	i_assert(lock_type == F_RDLCK || lock_type == F_WRLCK);

	if (lock_type == F_RDLCK && index->lock_type != F_UNLCK) {
		index->shared_lock_count++;
		*lock_id_r = index->lock_id;
		return 1;
	}
	if (lock_type == F_WRLCK && index->lock_type == F_WRLCK) {
		index->excl_lock_count++;
		*lock_id_r = index->lock_id + 1;
		return 1;
	}

	if (index->fcntl_locks_disable) {
		/* FIXME: exclusive locking will rewrite the index file every
		   time. shouldn't really be needed.. reading doesn't require
		   locks then, though */
		if (lock_type == F_WRLCK)
			return 0;
		if (update_index && index->lock_type == F_UNLCK) {
			if (mail_index_has_changed(index) < 0)
				return -1;
		}
		if (mail_index_lock_mprotect(index, lock_type) < 0)
			return -1;

		index->shared_lock_count++;
		index->lock_type = F_RDLCK;
		*lock_id_r = index->lock_id;
		return 1;
	}

	if (update_index) {
		if (mail_index_has_changed(index) < 0)
			return -1;
	}

	ret = file_wait_lock_full(index->fd, lock_type, timeout_secs,
				  NULL, NULL);
	if (ret <= 0) {
		if (ret == 0 || errno == EDEADLK) {
			/* deadlock equals to timeout */
			return 0;
		}
		mail_index_set_syscall_error(index, "file_wait_lock()");
		return -1;
	}

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

	if (mail_index_lock_mprotect(index, lock_type) < 0)
		return -1;
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

	if (index->lock_type == F_UNLCK) {
		if (mail_index_lock_mprotect(index, F_RDLCK) < 0)
			return -1;
	}

	ret = write_full(fd, index->map->hdr, sizeof(*index->map->hdr));
	if (ret < 0 || write_full(fd, index->map->records,
				  index->map->records_count *
				  sizeof(struct mail_index_record)) < 0) {
		mail_index_file_set_syscall_error(index, path, "write_full()");
		(void)close(fd);
		(void)unlink(path);
		fd = -1;
	} else {
		i_assert(index->copy_lock_path == NULL);
		index->copy_lock_path = i_strdup(path);
	}

	if (index->lock_type == F_UNLCK)
		(void)mail_index_lock_mprotect(index, F_UNLCK);
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
	if (fd == -1)
		return -1;

	old_lock_type = index->lock_type;
	index->lock_type = F_WRLCK;
        index->excl_lock_count++;

	if (mail_index_reopen(index, fd) < 0) {
		i_assert(index->excl_lock_count == 1);
		if (unlink(index->copy_lock_path) < 0) {
			mail_index_file_set_syscall_error(index,
							  index->copy_lock_path,
							  "unlink()");
		}
		i_free(index->copy_lock_path);
		index->copy_lock_path = NULL;

		index->lock_type = old_lock_type;
		index->excl_lock_count = 0;
		return -1;
	}

	(void)mail_index_lock_mprotect(index, F_WRLCK);
	return 0;
}

int mail_index_lock_exclusive(struct mail_index *index,
			      unsigned int *lock_id_r)
{
	int ret;

	/* exclusive transaction log lock protects exclusive locking
	   for the main index file */
	i_assert(index->log_locked);

	/* wait two seconds for exclusive lock */
	ret = mail_index_lock(index, F_WRLCK, 2, TRUE, lock_id_r);
	if (ret > 0)
		return 0;
	if (ret < 0)
		return -1;

	if (mail_index_lock_exclusive_copy(index) < 0)
		return -1;
	*lock_id_r = index->lock_id + 1;
	return 0;
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
			mail_index_excl_unlock_finish(index);
	}

	if (index->shared_lock_count == 0 && index->excl_lock_count == 0) {
		index->lock_id += 2;
		index->lock_type = F_UNLCK;
		(void)mail_index_lock_mprotect(index, F_UNLCK);
		if (!index->fcntl_locks_disable) {
			if (file_wait_lock(index->fd, F_UNLCK) < 0) {
				mail_index_set_syscall_error(index,
					"file_wait_lock()");
			}
		}
	}
}

int mail_index_is_locked(struct mail_index *index, unsigned int lock_id)
{
	return (index->lock_id ^ lock_id) <= 1;
}
