/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "file-lock.h"
#include "file-set-size.h"
#include "mmap-util.h"
#include "mail-index.h"
#include "mail-index-util.h"
#include "mail-cache.h"
#include "mail-modifylog.h"
#include "mail-custom-flags.h"

#include <unistd.h>
#include <fcntl.h>
#include <utime.h>

static int mmap_verify(struct mail_index *index)
{
	struct mail_index_header *hdr;
	unsigned int extra;

	index->mmap_used_length = 0;

	if (index->mmap_full_length < sizeof(struct mail_index_header)) {
                index_set_corrupted(index, "File too small");
		return FALSE;
	}

	/* keep the header set even if we fail, so we can update the flags */
	hdr = index->mmap_base;
	index->header = hdr;
	index->header_size = hdr->header_size;

	extra = (index->mmap_full_length - index->header_size) %
		sizeof(struct mail_index_record);

	if (extra != 0) {
		/* partial write or corrupted -
		   truncate the file to valid length */
		i_assert(!index->anon_mmap);

		index->mmap_full_length -= extra;
		(void)ftruncate(index->fd, (off_t)index->mmap_full_length);
	}

	if (hdr->used_file_size > index->mmap_full_length) {
		index_set_corrupted(index,
				    "used_file_size larger than real file size "
				    "(%u vs %"PRIuSIZE_T")",
				    hdr->used_file_size,
				    index->mmap_full_length);
		return FALSE;
	}

	if (hdr->used_file_size < index->header_size ||
	    (hdr->used_file_size - index->header_size) %
	    sizeof(struct mail_index_record) != 0) {
		index_set_corrupted(index, "Invalid used_file_size in header "
				    "(%u)", hdr->used_file_size);
		return FALSE;
	}

	if (hdr->messages_count < hdr->seen_messages_count) {
		index_set_corrupted(index, "Invalid seen messages count "
				    "(%u < %u)", hdr->messages_count,
				    hdr->seen_messages_count);
		return FALSE;
	}

	if (hdr->messages_count < hdr->deleted_messages_count) {
		index_set_corrupted(index, "Invalid deleted messages count "
				    "(%u < %u)", hdr->messages_count,
				    hdr->deleted_messages_count);
		return FALSE;
	}

	index->sync_id = hdr->sync_id;
	index->mmap_used_length = hdr->used_file_size;
	return TRUE;
}

int mail_index_mmap_update(struct mail_index *index)
{
	if (index->anon_mmap)
		return mmap_verify(index);

	if (index->mmap_base != NULL) {
		index->header = (struct mail_index_header *) index->mmap_base;

		if (index->mmap_invalidate) {
			if (msync(index->mmap_base,
				  index->mmap_used_length,
				  MS_SYNC | MS_INVALIDATE) < 0) {
				index_set_syscall_error(index, "msync()");
				return FALSE;
			}
		}

		/* make sure file size hasn't changed */
		if (index->header->sync_id == index->sync_id) {
			index->mmap_used_length = index->header->used_file_size;
			if (index->mmap_used_length > index->mmap_full_length) {
				i_panic("Index file size was grown without "
					"updating sync_id");
			}
			return TRUE;
		}

		if (!index->mmap_invalidate) {
			if (msync(index->mmap_base,
				  index->mmap_used_length, MS_SYNC) < 0) {
				index_set_syscall_error(index, "msync()");
				return FALSE;
			}
		}

		if (munmap(index->mmap_base, index->mmap_full_length) < 0)
			return index_set_syscall_error(index, "munmap()");
	}

	index->mmap_base = mmap_rw_file(index->fd, &index->mmap_full_length);
	if (index->mmap_base == MAP_FAILED) {
		index->mmap_base = NULL;
		index->mmap_used_length = 0;
		index_set_syscall_error(index, "mmap()");
		return FALSE;
	}

	return mmap_verify(index);
}

void mail_index_close(struct mail_index *index)
{
	if (index->set_flags != 0) {
		if (index->header != NULL) {
#ifdef DEBUG
			mprotect(index->mmap_base, index->mmap_used_length,
				 PROT_READ|PROT_WRITE);
#endif
			index->header->flags |= index->set_flags;
			(void)msync(index->mmap_base, index->header_size,
				    MS_SYNC);
		}
		index->set_flags = 0;
	}

	index->opened = FALSE;
	index->inconsistent = FALSE;

	index->lock_type = MAIL_LOCK_UNLOCK;
	index->header = NULL;

	if (index->fd != -1) {
		if (close(index->fd) < 0)
			index_set_syscall_error(index, "close()");
		index->fd = -1;
	}

	if (index->filepath != NULL) {
		i_free(index->filepath);
		index->filepath = NULL;
	}

	if (index->anon_mmap) {
		if (munmap_anon(index->mmap_base, index->mmap_full_length) < 0)
			index_set_syscall_error(index, "munmap_anon()");
		index->anon_mmap = FALSE;
	} else if (index->mmap_base != NULL) {
		if (munmap(index->mmap_base, index->mmap_full_length) < 0)
			index_set_syscall_error(index, "munmap()");
	}
	index->mmap_base = NULL;

	if (index->cache != NULL) {
                mail_cache_free(index->cache);
		index->cache = NULL;
	}

	if (index->modifylog != NULL) {
                mail_modifylog_free(index->modifylog);
		index->modifylog = NULL;
	}

	if (index->custom_flags != NULL) {
		mail_custom_flags_free(index->custom_flags);
                index->custom_flags = NULL;
	}

	if (index->error != NULL) {
		i_free(index->error);
		index->error = NULL;
	}
}

static int mail_index_sync_file(struct mail_index *index)
{
	unsigned int i;
	int failed, fsync_fds[3];

	if (index->anon_mmap)
		return TRUE;

	for (i = 0; i < sizeof(fsync_fds)/sizeof(fsync_fds[0]); i++)
		fsync_fds[i] = -1;

	if (msync(index->mmap_base, index->mmap_used_length, MS_SYNC) < 0)
		return index_set_syscall_error(index, "msync()");

	failed = FALSE;

	if (index->modifylog != NULL) {
		if (!mail_modifylog_sync_file(index->modifylog, &fsync_fds[2]))
			failed = TRUE;
	}

	for (i = 0; i < sizeof(fsync_fds)/sizeof(fsync_fds[0]); i++) {
		if (fsync_fds[i] != -1 && fdatasync(fsync_fds[i]) < 0)
			index_set_error(index, "fdatasync(%u) failed: %m", i);
	}

	if (fdatasync(index->fd) < 0)
		return index_set_syscall_error(index, "fdatasync()");

	return !failed;
}

static void mail_index_update_timestamp(struct mail_index *index)
{
	struct utimbuf ut;

	/* keep index's modify stamp same as the sync file's stamp */
	ut.actime = ioloop_time;
	ut.modtime = index->file_sync_stamp;
	if (utime(index->filepath, &ut) < 0)
		index_set_syscall_error(index, "utime()");
}

int mail_index_fmdatasync(struct mail_index *index, size_t size)
{
	i_assert(index->lock_type == MAIL_LOCK_EXCLUSIVE);

	if (!index->anon_mmap) {
		if (msync(index->mmap_base, size, MS_SYNC) < 0)
			return index_set_syscall_error(index, "msync()");
		if (fdatasync(index->fd) < 0)
			return index_set_syscall_error(index, "fdatasync()");
	}

	return TRUE;
}

static void mail_index_update_header_changes(struct mail_index *index)
{
	if (index->set_flags != 0) {
		index->header->flags |= index->set_flags;
		index->set_flags = 0;
	}
}

static int mail_index_write_header_changes(struct mail_index *index)
{
	int failed = FALSE;

	/* use our own locking here so we don't mess up with any other
	   index states, like inconsistency. */
	if (!mail_index_wait_lock(index, F_WRLCK))
		return FALSE;

#ifdef DEBUG
	mprotect(index->mmap_base, index->mmap_used_length,
		 PROT_READ|PROT_WRITE);
#endif

	mail_index_update_header_changes(index);

	if (!index->anon_mmap) {
		if (msync(index->mmap_base, index->header_size, MS_SYNC) < 0) {
			index_set_syscall_error(index, "msync()");
			failed = TRUE;
		}
	}

#ifdef DEBUG
	mprotect(index->mmap_base, index->mmap_used_length, PROT_NONE);
#endif

	if (!mail_index_wait_lock(index, F_UNLCK))
		return FALSE;

	return !failed;
}

static int mail_index_lock_remove(struct mail_index *index)
{
	enum mail_lock_type old_lock_type;
	int ret = TRUE;

	while (index->cache_later_locks > 0) {
		if (!mail_cache_unlock(index->cache))
			ret = FALSE;
		index->cache_later_locks--;
	}

	if (!mail_index_wait_lock(index, F_UNLCK))
		return FALSE;

	old_lock_type = index->lock_type;
	index->lock_type = MAIL_LOCK_UNLOCK;

	if (old_lock_type == MAIL_LOCK_SHARED) {
		/* releasing shared lock. we may need to update some
		   flags in header. */
		unsigned int old_flags;

		old_flags = index->header->flags;

		if ((old_flags | index->set_flags) != old_flags)
			return mail_index_write_header_changes(index);
	}

        debug_mprotect(index->mmap_base, index->mmap_full_length, index);
	return ret;
}

static int mail_index_lock_change(struct mail_index *index,
				  enum mail_lock_type lock_type, int try_lock)
{
	int ret, fd_lock_type;

	/* shared -> exclusive can deadlock */
	i_assert(try_lock || lock_type != MAIL_LOCK_EXCLUSIVE ||
		 index->lock_type != MAIL_LOCK_SHARED);

	/* locking index when cache is locked can deadlock */
	i_assert(try_lock || index->lock_type == MAIL_LOCK_EXCLUSIVE ||
		 !mail_cache_is_locked(index->cache));

	if (index->inconsistent) {
		/* index is in inconsistent state and nothing else than
		   free() is allowed for it. */
		if (index->error == NULL) {
			index->error =
				i_strdup("Index is in inconsistent state");
		}
		return FALSE;
	}

	fd_lock_type = MAIL_LOCK_TO_FLOCK(lock_type);
	if (try_lock) {
		ret = file_try_lock(index->fd, fd_lock_type);
		if (ret < 0)
			index_set_syscall_error(index, "file_try_lock()");
		if (ret <= 0)
			return FALSE;
	} else {
		if (!mail_index_wait_lock(index, fd_lock_type))
			return FALSE;
	}

	index->lock_type = lock_type;
	debug_mprotect(index->mmap_base, index->mmap_full_length, index);

	if (!mail_index_mmap_update(index)) {
		(void)index->set_lock(index, MAIL_LOCK_UNLOCK);
		return FALSE;
	}

	if (index->indexid != index->header->indexid) {
		/* index was rebuilt, there's no way we can maintain
		   consistency */
		index_set_error(index, "Warning: Inconsistency - Index "
				"%s was rebuilt while we had it open",
				index->filepath);
		index->inconsistent = TRUE;
		return FALSE;
	}

	if (index->header->flags & MAIL_INDEX_HDR_FLAG_FSCK) {
		/* someone just partially updated the index, need to fsck it */
		if (lock_type == MAIL_LOCK_SHARED) {
			/* we need exclusive lock so fsck()'s set_lock() won't
			   get us back here */
			if (!mail_index_lock_remove(index))
				return FALSE;

			if (!mail_index_wait_lock(index, F_WRLCK))
				return FALSE;
			index->lock_type = MAIL_LOCK_EXCLUSIVE;

			debug_mprotect(index->mmap_base,
				       index->mmap_full_length, index);
		}

		/* check again, in case it was already fscked while we had
		   it unlocked for a while */
		if (index->header->flags & MAIL_INDEX_HDR_FLAG_FSCK) {
			if (!index->fsck(index))
				return FALSE;
		}

		if (lock_type == MAIL_LOCK_SHARED) {
			/* drop exclusive lock */
			return index->set_lock(index, lock_type);
		}
	}

	if (lock_type == MAIL_LOCK_EXCLUSIVE) {
		/* while holding exclusive lock, keep the FSCK flag on.
		   when the lock is released, the FSCK flag will also be
		   removed. */
		index->excl_lock_counter++;
		index->header->flags |= MAIL_INDEX_HDR_FLAG_FSCK;
		if (!mail_index_fmdatasync(index, index->header_size)) {
			(void)index->set_lock(index, MAIL_LOCK_UNLOCK);
			return FALSE;
		}
	}

	return TRUE;
}

static int mail_index_lock_full(struct mail_index *index,
				enum mail_lock_type lock_type, int try_lock)
{
	int keep_fsck;

	if (index->lock_type == lock_type)
		return TRUE;

	if (index->anon_mmap) {
		/* anonymous mmaps are private and don't need any locking */
#ifdef DEBUG
		mprotect(index->mmap_base, index->mmap_used_length,
			 PROT_READ|PROT_WRITE);
#endif
		mail_index_update_header_changes(index);

		index->lock_type = lock_type;
		debug_mprotect(index->mmap_base, index->mmap_full_length,
			       index);
		return TRUE;
	}

	if (index->lock_type == MAIL_LOCK_EXCLUSIVE) {
		index->excl_lock_counter++;
		if (index->modifylog != NULL)
			mail_modifylog_notify_lock_drop(index->modifylog);

		/* dropping exclusive lock (either unlock or to shared) */
		keep_fsck = (index->set_flags & MAIL_INDEX_HDR_FLAG_FSCK) != 0;
		mail_index_update_header_changes(index);

		/* remove the FSCK flag only after successful fsync() */
		if (mail_index_sync_file(index) && !keep_fsck) {
			index->header->flags &= ~MAIL_INDEX_HDR_FLAG_FSCK;
			if (!index->anon_mmap &&
			    msync(index->mmap_base, index->header_size,
				  MS_SYNC) < 0) {
				/* we only failed to remove the fsck flag,
				   so this isn't fatal. */
				index_set_syscall_error(index, "msync()");
			}
		}

		mail_index_update_timestamp(index);
	}

	if (lock_type == MAIL_LOCK_UNLOCK)
		return mail_index_lock_remove(index);
	else
		return mail_index_lock_change(index, lock_type, try_lock);
}

int mail_index_set_lock(struct mail_index *index, enum mail_lock_type lock_type)
{
	return mail_index_lock_full(index, lock_type, FALSE);
}

int mail_index_try_lock(struct mail_index *index, enum mail_lock_type lock_type)
{
	return mail_index_lock_full(index, lock_type, TRUE);
}

void mail_index_set_lock_notify_callback(struct mail_index *index,
					 mail_lock_notify_callback_t callback,
					 void *context)
{
	index->lock_notify_cb = callback;
	index->lock_notify_context = context;
}

struct mail_index_header *mail_index_get_header(struct mail_index *index)
{
	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);

	return index->header;
}

void mail_index_mark_flag_changes(struct mail_index *index,
				  struct mail_index_record *rec,
				  enum mail_flags old_flags,
				  enum mail_flags new_flags)
{
	if ((old_flags & MAIL_SEEN) == 0 && (new_flags & MAIL_SEEN)) {
		/* unseen -> seen */
		index->header->seen_messages_count++;
	} else if ((old_flags & MAIL_SEEN) && (new_flags & MAIL_SEEN) == 0) {
		/* seen -> unseen */
		if (index->header->seen_messages_count ==
		    index->header->messages_count) {
			/* this is the first unseen message */
                        index->header->first_unseen_uid_lowwater = rec->uid;
		} else if (rec->uid < index->header->first_unseen_uid_lowwater)
			index->header->first_unseen_uid_lowwater = rec->uid;

		if (index->header->seen_messages_count == 0) {
			index_set_corrupted(index,
				"seen_messages_count in header is invalid");
		} else {
			index->header->seen_messages_count--;
		}
	}

	if ((old_flags & MAIL_DELETED) == 0 && (new_flags & MAIL_DELETED)) {
		/* undeleted -> deleted */
		index->header->deleted_messages_count++;

		if (index->header->deleted_messages_count == 1) {
			/* this is the first deleted message */
			index->header->first_deleted_uid_lowwater = rec->uid;
		} else if (rec->uid < index->header->first_deleted_uid_lowwater)
			index->header->first_deleted_uid_lowwater = rec->uid;
	} else if ((old_flags & MAIL_DELETED) &&
		   (new_flags & MAIL_DELETED) == 0) {
		/* deleted -> undeleted */
		if (index->header->deleted_messages_count == 0) {
			index_set_corrupted(index,
				"deleted_messages_count in header is invalid");
		} else {
			index->header->deleted_messages_count--;
		}
	}
}

#define INDEX_NEED_COMPRESS(records, hdr) \
	((records) > INDEX_MIN_RECORDS_COUNT && \
	 (records) * (100-INDEX_COMPRESS_PERCENTAGE) / 100 > \
	 	(hdr)->messages_count)

int mail_index_expunge(struct mail_index *index,
		       struct mail_index_record *first_rec,
		       struct mail_index_record *last_rec,
		       unsigned int first_seq, unsigned int last_seq,
		       int external_change)
{
	unsigned int first_uid, last_uid;

	i_assert(index->lock_type == MAIL_LOCK_EXCLUSIVE);
	i_assert(first_seq != 0);
	i_assert(first_seq <= last_seq);

	index->expunge_counter++;

	first_uid = first_rec->uid;
	last_uid = last_rec->uid;

	if (!mail_index_expunge_record_range(index, first_rec, last_rec))
		return FALSE;

	if (index->modifylog != NULL) {
		if (!mail_modifylog_add_expunges(index->modifylog,
						 first_seq, last_seq,
						 first_uid, last_uid,
						 external_change))
			return FALSE;
	}

	if (index->header->messages_count == 0) {
		/* all mail was deleted, truncate cache file */
		if (!mail_cache_truncate(index->cache))
			return FALSE;
	}

	return TRUE;
}

int mail_index_update_flags(struct mail_index *index,
			    struct mail_index_record *rec,
			    unsigned int seq, enum mail_flags flags,
			    int external_change)
{
	i_assert(index->lock_type == MAIL_LOCK_EXCLUSIVE);
	i_assert(seq != 0);

	if (flags == rec->msg_flags)
		return TRUE; /* no changes */

        mail_index_mark_flag_changes(index, rec, rec->msg_flags, flags);

	rec->msg_flags = flags;
	return index->modifylog == NULL ? TRUE :
		mail_modifylog_add_flags(index->modifylog, seq,
					 rec->uid, external_change);
}

static int mail_index_grow(struct mail_index *index)
{
	uoff_t pos;
	unsigned int grow_count;
	void *base;

	grow_count = index->header->messages_count *
		INDEX_GROW_PERCENTAGE / 100;
	if (grow_count < 16)
		grow_count = 16;

	pos = index->mmap_full_length +
		(grow_count * sizeof(struct mail_index_record));
	i_assert(pos < OFF_T_MAX);

	if (index->anon_mmap) {
		i_assert(pos < SSIZE_T_MAX);

		base = mremap_anon(index->mmap_base, index->mmap_full_length,
				   (size_t)pos, MREMAP_MAYMOVE);
		if (base == MAP_FAILED)
			return index_set_syscall_error(index, "mremap_anon()");

		index->mmap_base = base;
		index->mmap_full_length = (size_t)pos;
		return mmap_verify(index);
	}

	if (file_set_size(index->fd, (off_t)pos) < 0)
		return index_set_syscall_error(index, "file_set_size()");

	/* file size changed, let others know about it too by changing
	   sync_id in header. */
	index->header->sync_id++;

	if (!mail_index_mmap_update(index))
		return FALSE;

	return TRUE;
}

struct mail_index_record *mail_index_append(struct mail_index *index)
{
	struct mail_index_record *rec;

	i_assert(index->lock_type == MAIL_LOCK_EXCLUSIVE);

	if (index->header->next_uid == MAX_ALLOWED_UID) {
		index->set_flags |= MAIL_INDEX_HDR_FLAG_REBUILD;
		index_set_error(index, "Reached maximum UID in mailbox %s, "
				"rebuilding index", index->filepath);
		return NULL;
	}

	if (index->mmap_used_length == index->mmap_full_length) {
		if (!mail_index_grow(index))
			return NULL;
	}

	i_assert(index->header->used_file_size == index->mmap_used_length);
	i_assert(index->mmap_used_length + sizeof(struct mail_index_record) <=
		 index->mmap_full_length);

	index->header->messages_count++;

	rec = (struct mail_index_record *) ((char *) index->mmap_base +
					    index->mmap_used_length);
	rec->uid = index->header->next_uid++;
	rec->msg_flags = 0;

	index->header->used_file_size += sizeof(*rec);
	index->mmap_used_length += sizeof(*rec);

	return rec;
}

enum mail_index_error mail_index_get_last_error(struct mail_index *index)
{
	if (index->inconsistent)
		return MAIL_INDEX_ERROR_INCONSISTENT;
	if (index->nodiskspace)
		return MAIL_INDEX_ERROR_DISKSPACE;
	if (index->index_lock_timeout)
		return MAIL_INDEX_ERROR_INDEX_LOCK_TIMEOUT;
	if (index->mailbox_lock_timeout)
		return MAIL_INDEX_ERROR_MAILBOX_LOCK_TIMEOUT;

	if (index->error != NULL)
		return MAIL_INDEX_ERROR_INTERNAL;

	return MAIL_INDEX_ERROR_NONE;
}

const char *mail_index_get_last_error_text(struct mail_index *index)
{
	return index->error;
}
