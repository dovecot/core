/* Copyright (c) 2003-2013 Dovecot authors, see the included COPYING file */

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
