/* Copyright (c) 2003-2011 Dovecot authors, see the included COPYING file */

/*
   Locking should never fail or timeout. Exclusive locks must be kept as short
   time as possible. Shared locks can be long living, so if we can't get
   exclusive lock directly, we'll recreate the index. That means the shared
   lock holders can keep using the old file.

   lock_id is used to figure out if acquired lock is still valid. When index
   file is reopened, the lock_id can become invalid. It doesn't matter however,
   as no-one's going to modify the old file anymore.

   lock_id also tells us if we're referring to a shared or an exclusive lock.
   This allows us to drop back to shared locking once all exclusive locks
   are dropped. Shared locks have even numbers, exclusive locks have odd numbers.
   The number is increased by two every time the lock is dropped or index file
   is reopened.
*/

#include "lib.h"
#include "nfs-workarounds.h"
#include "mail-index-private.h"

#define MAIL_INDEX_SHARED_LOCK_TIMEOUT 120

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
			   unsigned int timeout_secs, unsigned int *lock_id_r)
{
	int ret;

	i_assert(lock_type == F_RDLCK || lock_type == F_WRLCK);

	if (lock_type == F_RDLCK && index->lock_type != F_UNLCK) {
		index->shared_lock_count++;
		*lock_id_r = index->lock_id_counter;
		ret = 1;
	} else if (lock_type == F_WRLCK && index->lock_type == F_WRLCK) {
		index->excl_lock_count++;
		*lock_id_r = index->lock_id_counter + 1;
		ret = 1;
	} else {
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

		index->shared_lock_count++;
		index->lock_type = F_RDLCK;
		*lock_id_r = index->lock_id_counter;
		return 1;
	}

	if (index->file_lock == NULL) {
		i_assert(index->lock_type == F_UNLCK);
		ret = mail_index_lock_fd(index, index->filepath, index->fd,
					 lock_type, timeout_secs,
					 &index->file_lock);
	} else {
		i_assert(index->lock_type == F_RDLCK && lock_type == F_WRLCK);
		ret = file_lock_try_update(index->file_lock, lock_type);
	}
	if (ret <= 0)
		return ret;

	if (index->lock_type == F_UNLCK)
		index->lock_id_counter += 2;
	index->lock_type = lock_type;

	if (lock_type == F_RDLCK) {
		index->shared_lock_count++;
		*lock_id_r = index->lock_id_counter;
	} else {
		index->excl_lock_count++;
		*lock_id_r = index->lock_id_counter + 1;
	}

	return 1;
}

void mail_index_flush_read_cache(struct mail_index *index, const char *path,
				 int fd, bool locked)
{
	if ((index->flags & MAIL_INDEX_OPEN_FLAG_NFS_FLUSH) == 0)
		return;

	/* Assume flock() is emulated with fcntl(), because that's how most
	   OSes work nowadays. */
	if (locked &&
	    (index->lock_method == FILE_LOCK_METHOD_FCNTL ||
	     index->lock_method == FILE_LOCK_METHOD_FLOCK)) {
		nfs_flush_read_cache_locked(path, fd);
	} else {
		nfs_flush_read_cache_unlocked(path, fd);
	}
}

int mail_index_lock_shared(struct mail_index *index, unsigned int *lock_id_r)
{
	unsigned int timeout_secs;
	int ret;

	timeout_secs = I_MIN(MAIL_INDEX_SHARED_LOCK_TIMEOUT,
			     index->max_lock_timeout_secs);
	ret = mail_index_lock(index, F_RDLCK, timeout_secs, lock_id_r);
	if (ret > 0) {
		mail_index_flush_read_cache(index, index->filepath,
					    index->fd, TRUE);
		return 0;
	}
	if (ret < 0)
		return -1;

	mail_index_set_error(index,
		"Timeout (%us) while waiting for shared lock for index file %s",
		timeout_secs, index->filepath);
	index->index_lock_timeout = TRUE;
	return -1;
}

int mail_index_try_lock_exclusive(struct mail_index *index,
				  unsigned int *lock_id_r)
{
	int ret;

	if ((ret = mail_index_lock(index, F_WRLCK, 0, lock_id_r)) > 0) {
		mail_index_flush_read_cache(index, index->filepath,
					    index->fd, TRUE);
	}
	return ret;
}

void mail_index_unlock(struct mail_index *index, unsigned int *_lock_id)
{
	unsigned int lock_id = *_lock_id;

	*_lock_id = 0;

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
		i_assert(lock_id == index->lock_id_counter + 1);
		i_assert(index->excl_lock_count > 0);
		i_assert(index->lock_type == F_WRLCK);
		if (--index->excl_lock_count == 0 &&
		    index->shared_lock_count > 0) {
			/* drop back to a shared lock. */
			index->lock_type = F_RDLCK;
			(void)file_lock_try_update(index->file_lock, F_RDLCK);
		}
	}

	if (index->shared_lock_count == 0 && index->excl_lock_count == 0) {
		index->lock_id_counter += 2;
		index->lock_type = F_UNLCK;
		if (index->lock_method != FILE_LOCK_METHOD_DOTLOCK) {
			if (!MAIL_INDEX_IS_IN_MEMORY(index))
				file_unlock(&index->file_lock);
		}
		i_assert(index->file_lock == NULL);
	}
}

bool mail_index_is_locked(struct mail_index *index, unsigned int lock_id)
{
	if ((index->lock_id_counter ^ lock_id) <= 1 && lock_id != 0) {
		i_assert(index->lock_type != F_UNLCK);
		return TRUE;
	}

	return FALSE;
}
