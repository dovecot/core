/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "file-lock.h"
#include "file-set-size.h"
#include "mmap-util.h"
#include "mail-index.h"
#include "mail-index-data.h"
#include "mail-index-util.h"
#include "mail-tree.h"
#include "mail-modifylog.h"
#include "mail-custom-flags.h"

#include <unistd.h>
#include <fcntl.h>
#include <utime.h>

static int mmap_verify(MailIndex *index)
{
	MailIndexHeader *hdr;
	unsigned int extra;

	index->mmap_used_length = 0;

	if (index->mmap_full_length < sizeof(MailIndexHeader)) {
                index_set_corrupted(index, "File too small");
		return FALSE;
	}

	extra = (index->mmap_full_length - sizeof(MailIndexHeader)) %
		sizeof(MailIndexRecord);

	if (extra != 0) {
		/* partial write or corrupted -
		   truncate the file to valid length */
		i_assert(!index->anon_mmap);

		index->mmap_full_length -= extra;
		(void)ftruncate(index->fd, (off_t)index->mmap_full_length);
	}

	/* keep the header set even if we fail, so we can update the flags */
	hdr = index->mmap_base;
	index->header = hdr;

	if (hdr->used_file_size > index->mmap_full_length) {
		index_set_corrupted(index, "used_file_size larger than real "
				    "file size (%"PRIuUOFF_T" vs %"PRIuSIZE_T
				    ")", hdr->used_file_size,
				    index->mmap_full_length);
		return FALSE;
	}

	if ((hdr->used_file_size - sizeof(MailIndexHeader)) %
	    sizeof(MailIndexRecord) != 0) {
		index_set_corrupted(index, "Invalid used_file_size in header "
				    "(%"PRIuUOFF_T")",
				    hdr->used_file_size);
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

int mail_index_mmap_update(MailIndex *index)
{
	if (index->anon_mmap)
		return mmap_verify(index);

	if (index->mmap_base != NULL) {
		index->header = (MailIndexHeader *) index->mmap_base;

		/* make sure file size hasn't changed */
		if (index->header->sync_id == index->sync_id) {
			index->mmap_used_length = index->header->used_file_size;
			if (index->mmap_used_length > index->mmap_full_length) {
				i_panic("Index file size was grown without "
					"updating sync_id");
			}
			return TRUE;
		}

		if (msync(index->mmap_base,
			  index->mmap_used_length, MS_SYNC) < 0)
			return index_set_syscall_error(index, "msync()");

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

void mail_index_close(MailIndex *index)
{
	index->set_flags = 0;
	index->set_cache_fields = 0;

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

	if (index->data != NULL) {
                mail_index_data_free(index->data);
		index->data = NULL;
	}

	if (index->tree != NULL) {
                mail_tree_free(index->tree);
		index->tree = NULL;
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

static int mail_index_sync_file(MailIndex *index)
{
	struct utimbuf ut;
	int failed;

	if (index->anon_mmap)
		return TRUE;

	if (!mail_index_data_sync_file(index->data))
		return FALSE;

	if (msync(index->mmap_base, index->mmap_used_length, MS_SYNC) < 0)
		return index_set_syscall_error(index, "msync()");

	failed = FALSE;

	if (index->tree != NULL) {
		if (!mail_tree_sync_file(index->tree))
			failed = TRUE;
	}

	if (index->modifylog != NULL) {
		if (!mail_modifylog_sync_file(index->modifylog))
			failed = TRUE;
	}

	/* keep index's modify stamp same as the sync file's stamp */
	ut.actime = ioloop_time;
	ut.modtime = index->file_sync_stamp;
	if (utime(index->filepath, &ut) < 0)
		return index_set_syscall_error(index, "utime()");

	if (fsync(index->fd) < 0)
		return index_set_syscall_error(index, "fsync()");

	return !failed;
}

int mail_index_fmsync(MailIndex *index, size_t size)
{
	i_assert(index->lock_type == MAIL_LOCK_EXCLUSIVE);

	if (!index->anon_mmap) {
		if (msync(index->mmap_base, size, MS_SYNC) < 0)
			return index_set_syscall_error(index, "msync()");
		if (fsync(index->fd) < 0)
			return index_set_syscall_error(index, "fsync()");
	}

	return TRUE;
}

static void mail_index_update_header_changes(MailIndex *index)
{
	if (index->set_flags != 0) {
		index->header->flags |= index->set_flags;
		index->set_flags = 0;
	}

	if (index->set_cache_fields != 0) {
		index->header->cache_fields = index->set_cache_fields;
		index->set_cache_fields = 0;
	}
}

#define MAIL_LOCK_TO_FLOCK(lock_type) \
        ((lock_type) == MAIL_LOCK_UNLOCK ? F_UNLCK : \
		(lock_type) == MAIL_LOCK_SHARED ? F_RDLCK : F_WRLCK)

int mail_index_try_lock(MailIndex *index, MailLockType lock_type)
{
	int ret;

	if (index->lock_type == lock_type)
		return TRUE;

	if (index->anon_mmap)
		return TRUE;

	ret = file_try_lock(index->fd, MAIL_LOCK_TO_FLOCK(lock_type));
	if (ret < 0)
		index_set_syscall_error(index, "file_try_lock()");

	return ret > 0;
}

static int mail_index_write_header_changes(MailIndex *index)
{
	int failed;

	/* use our own locking here so we don't mess up with any other
	   index states, like inconsistency. */
	if (file_wait_lock(index->fd, F_WRLCK) < 0)
		return index_set_syscall_error(index, "file_wait_lock()");

	mail_index_update_header_changes(index);

	failed = msync(index->mmap_base, sizeof(MailIndexHeader), MS_SYNC) < 0;
	if (failed)
		index_set_syscall_error(index, "msync()");

	if (file_wait_lock(index->fd, F_UNLCK) < 0)
		return index_set_syscall_error(index, "file_wait_lock()");

	return !failed;
}

static int mail_index_lock_remove(MailIndex *index)
{
	MailLockType old_lock_type;

	if (file_wait_lock(index->fd, F_UNLCK) < 0)
		return index_set_syscall_error(index, "file_wait_lock()");

	old_lock_type = index->lock_type;
	index->lock_type = MAIL_LOCK_UNLOCK;

	if (old_lock_type == MAIL_LOCK_SHARED) {
		/* releasing shared lock. we may need to update some
		   flags in header. */
		unsigned int old_flags, old_cache;

		old_flags = index->header->flags;
		old_cache = index->header->cache_fields;

		if ((old_flags | index->set_flags) != old_flags ||
		    (old_cache | index->set_cache_fields) != old_cache)
			return mail_index_write_header_changes(index);
	}

	return TRUE;
}

static int mail_index_lock_change(MailIndex *index, MailLockType lock_type)
{
	/* shared -> exclusive isn't allowed */
	i_assert(lock_type != MAIL_LOCK_EXCLUSIVE ||
		 index->lock_type != MAIL_LOCK_SHARED);

	if (index->inconsistent) {
		/* index is in inconsistent state and nothing else than
		   free() is allowed for it. */
		return FALSE;
	}

	if (file_wait_lock(index->fd, MAIL_LOCK_TO_FLOCK(lock_type)) < 0)
		return index_set_syscall_error(index, "file_wait_lock()");
	index->lock_type = lock_type;

	if (!mail_index_mmap_update(index)) {
		(void)mail_index_set_lock(index, MAIL_LOCK_UNLOCK);
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

	if (index->header->flags & MAIL_INDEX_FLAG_FSCK) {
		/* someone just partially updated the index, need to fsck it */
		if (lock_type == MAIL_LOCK_SHARED) {
			/* we need exclusive lock so fsck()'s set_lock() won't
			   get us back here */
			if (!mail_index_lock_remove(index))
				return FALSE;

			if (file_wait_lock(index->fd, MAIL_LOCK_EXCLUSIVE) < 0)
				return index_set_syscall_error(index,
							"file_wait_lock()");
			index->lock_type = MAIL_LOCK_EXCLUSIVE;
		}

		/* check again, in case it was already fscked while we had
		   it unlocked for a while */
		if (index->header->flags & MAIL_INDEX_FLAG_FSCK) {
			if (!index->fsck(index))
				return FALSE;
		}

		if (lock_type == MAIL_LOCK_SHARED) {
			/* drop exclusive lock */
			return mail_index_set_lock(index, lock_type);
		}
	}

	if (lock_type == MAIL_LOCK_EXCLUSIVE) {
		/* while holding exclusive lock, keep the FSCK flag on.
		   when the lock is released, the FSCK flag will also be
		   removed. */
		index->header->flags |= MAIL_INDEX_FLAG_FSCK;
		if (!mail_index_fmsync(index, sizeof(MailIndexHeader))) {
			(void)mail_index_set_lock(index, MAIL_LOCK_UNLOCK);
			return FALSE;
		}
	}

	return TRUE;
}

int mail_index_set_lock(MailIndex *index, MailLockType lock_type)
{
	int keep_fsck;

	if (index->lock_type == lock_type)
		return TRUE;

	if (index->anon_mmap) {
		/* anonymous mmaps are private and don't need any locking */
		mail_index_update_header_changes(index);
		index->lock_type = lock_type;
		return TRUE;
	}

	if (index->lock_type == MAIL_LOCK_EXCLUSIVE) {
		mail_modifylog_notify_lock_drop(index->modifylog);

		/* dropping exclusive lock (either unlock or to shared) */
		keep_fsck = (index->set_flags & MAIL_INDEX_FLAG_FSCK) != 0;
		mail_index_update_header_changes(index);

		/* remove the FSCK flag only after successful fsync() */
		if (mail_index_sync_file(index) && !keep_fsck) {
			index->header->flags &= ~MAIL_INDEX_FLAG_FSCK;
			if (msync(index->mmap_base, sizeof(MailIndexHeader),
				  MS_SYNC) < 0) {
				/* we only failed to remove the fsck flag,
				   so this isn't fatal. */
				index_set_syscall_error(index, "msync()");
			}
		}
	}

	if (lock_type == MAIL_LOCK_UNLOCK)
		return mail_index_lock_remove(index);
	else
		return mail_index_lock_change(index, lock_type);
}

int mail_index_verify_hole_range(MailIndex *index)
{
	MailIndexHeader *hdr;
	unsigned int max_records;

	hdr = index->header;
	if (hdr->first_hole_records == 0)
		return TRUE;

	max_records = MAIL_INDEX_RECORD_COUNT(index);
	if (hdr->first_hole_index >= max_records) {
		index_set_corrupted(index,
				    "first_hole_index points outside file");
		return FALSE;
	}

	/* check that first_hole_records is in valid range */
	if (max_records - hdr->first_hole_index < hdr->first_hole_records) {
		index_set_corrupted(index,
				    "first_hole_records points outside file");
		return FALSE;
	}

	return TRUE;
}

MailIndexHeader *mail_index_get_header(MailIndex *index)
{
	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);

	return index->header;
}

MailIndexRecord *mail_index_lookup(MailIndex *index, unsigned int seq)
{
	MailIndexHeader *hdr;
	MailIndexRecord *rec;
	const char *format;
	unsigned int idx;

	i_assert(seq > 0);
	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);

	hdr = index->header;
	if (seq > hdr->messages_count) {
		/* out of range */
		return NULL;
	}

	if (!mail_index_verify_hole_range(index))
		return NULL;

	idx = seq-1;
	if (hdr->first_hole_records == 0 || hdr->first_hole_index > idx) {
		/* easy, it's just at the expected index */
		format = "Invalid first_hole_index in header: %"PRIuUOFF_T;
	} else if (hdr->first_hole_records ==
		   MAIL_INDEX_RECORD_COUNT(index) - hdr->messages_count) {
		/* only one hole in file, skip it and we're at
		   correct position */
		idx += hdr->first_hole_records;
		format = "Invalid hole locations in header: %"PRIuUOFF_T;
	} else {
		/* find from binary tree */
		idx = mail_tree_lookup_sequence(index->tree, seq);
		if (idx == (unsigned int)-1) {
			index_set_corrupted(index, "Sequence %u not found from "
					    "binary tree (%u msgs says header)",
					    seq, hdr->messages_count);
			return NULL;
		}
		format = "Invalid offset returned by binary tree: %"PRIuUOFF_T;
	}

	if (idx >= MAIL_INDEX_RECORD_COUNT(index)) {
		index_set_corrupted(index, format, idx);
		return NULL;
	}

	rec = (MailIndexRecord *) ((char *) index->mmap_base +
				   sizeof(MailIndexHeader)) + idx;
	if (rec->uid == 0) {
		index_set_corrupted(index, format, idx);
		return NULL;
	}

	return rec;
}

MailIndexRecord *mail_index_next(MailIndex *index, MailIndexRecord *rec)
{
	MailIndexRecord *end_rec;

	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);
	i_assert(rec >= (MailIndexRecord *) index->mmap_base);

	if (rec == NULL)
		return NULL;

	/* go to the next non-deleted record */
	end_rec = (MailIndexRecord *) ((char *) index->mmap_base +
				       index->mmap_used_length);
	while (++rec < end_rec) {
		if (rec->uid != 0)
			return rec;
	}

	return NULL;
}

MailIndexRecord *mail_index_lookup_uid_range(MailIndex *index,
					     unsigned int first_uid,
					     unsigned int last_uid,
					     unsigned int *seq_r)
{
	MailIndexRecord *rec;
	unsigned int idx;

	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);
	i_assert(first_uid > 0 && last_uid > 0);
	i_assert(first_uid <= last_uid);

	idx = mail_tree_lookup_uid_range(index->tree, seq_r,
					 first_uid, last_uid);
	if (idx == (unsigned int)-1)
		return NULL;

	if (idx >= MAIL_INDEX_RECORD_COUNT(index)) {
		index_set_error(index, "Corrupted binary tree for index %s: "
				"lookup returned index outside range "
				"(%u >= %u)", index->filepath, idx,
				MAIL_INDEX_RECORD_COUNT(index));
		index->set_flags |= MAIL_INDEX_FLAG_REBUILD_TREE;
		return NULL;
	}

	rec = (MailIndexRecord *) ((char *) index->mmap_base +
				   sizeof(MailIndexHeader)) + idx;
	if (rec->uid < first_uid || rec->uid > last_uid) {
		index_set_error(index, "Corrupted binary tree for index %s: "
				"lookup returned offset to wrong UID "
				"(%u vs %u..%u)", index->filepath,
				rec->uid, first_uid, last_uid);
		index->set_flags |= MAIL_INDEX_FLAG_REBUILD_TREE;
		return NULL;
	}

	return rec;
}

const char *mail_index_lookup_field(MailIndex *index, MailIndexRecord *rec,
				    MailField field)
{
	MailIndexDataRecord *datarec;

	datarec = (rec->cached_fields & field) == 0 ? NULL :
		mail_index_data_lookup(index->data, rec, field);
	if (datarec == NULL)
		return NULL;

	if (!mail_index_data_record_verify(index->data, datarec)) {
		/* index is corrupted, it will be rebuilt */
		return NULL;
	}

	return datarec->data;
}

const void *mail_index_lookup_field_raw(MailIndex *index, MailIndexRecord *rec,
					MailField field, size_t *size)
{
	MailIndexDataRecord *datarec;

	datarec = (rec->cached_fields & field) == 0 ? NULL :
		mail_index_data_lookup(index->data, rec, field);
	if (datarec == NULL) {
		*size = 0;
		return NULL;
	}

	*size = datarec->full_field_size;
	return datarec->data;
}

void mail_index_cache_fields_later(MailIndex *index, MailField field)
{
	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);

	field &= ~index->never_cache_fields;

	/* first check if the field even could be in the file */
	if ((index->set_cache_fields & field) != field) {
		if ((index->header->cache_fields & field) == 0) {
			/* no, but make sure the future records will have it.
			   we don't immediately mark the index to cache this
			   field for old messages as some clients never ask
			   the info again */
			index->set_cache_fields |= field;
		} else {
			/* this is at least the second time it's being asked,
			   make sure it'll be cached soon. */
			index->set_flags |= MAIL_INDEX_FLAG_CACHE_FIELDS;
		}
	}
}

void mail_index_mark_flag_changes(MailIndex *index, MailIndexRecord *rec,
				  MailFlags old_flags, MailFlags new_flags)
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
			index_set_corrupted(index, "seen_messages_count in "
					    "header is invalid");
		} else {
			index->header->seen_messages_count--;
		}
	}

	if ((old_flags & MAIL_DELETED) == 0 &&
		   (new_flags & MAIL_DELETED)) {
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
			index_set_corrupted(index, "deleted_messages_count in "
					    "header is invalid");
		} else {
			index->header->deleted_messages_count--;
		}
	}
}

static void update_first_hole_records(MailIndex *index)
{
        MailIndexRecord *rec, *end_rec;

	/* see if first_hole_records can be grown */
	rec = (MailIndexRecord *) ((char *) index->mmap_base +
				   sizeof(MailIndexHeader)) +
		index->header->first_hole_index +
		index->header->first_hole_records;
	end_rec = (MailIndexRecord *) ((char *) index->mmap_base +
				       index->mmap_used_length);
	while (rec < end_rec && rec->uid == 0) {
		index->header->first_hole_records++;
		rec++;
	}
}

static int mail_index_truncate_hole(MailIndex *index)
{
	index->header->used_file_size = sizeof(MailIndexHeader) +
		(uoff_t)index->header->first_hole_index *
		sizeof(MailIndexRecord);
	index->header->first_hole_index = 0;
	index->header->first_hole_records = 0;

	index->mmap_used_length = index->header->used_file_size;
	if (!mail_index_truncate(index))
		return FALSE;

	if (index->header->messages_count == 0) {
		/* all mail was deleted, truncate data file */
		if (!mail_index_data_reset(index->data))
			return FALSE;
	}

	return TRUE;
}

#define INDEX_NEED_COMPRESS(records, hdr) \
	((records) > INDEX_MIN_RECORDS_COUNT && \
	 (records) * (100-INDEX_COMPRESS_PERCENTAGE) / 100 > \
	 	(hdr)->messages_count)

int mail_index_expunge(MailIndex *index, MailIndexRecord *rec,
		       unsigned int seq, int external_change)
{
	MailIndexHeader *hdr;
	unsigned int records, uid, idx;

	i_assert(index->lock_type == MAIL_LOCK_EXCLUSIVE);
	i_assert(seq != 0);
	i_assert(rec->uid != 0);

	if (!mail_index_verify_hole_range(index))
		return FALSE;

	hdr = index->header;

	/* setting UID to 0 is enough for deleting the mail from index */
	uid = rec->uid;
	rec->uid = 0;

	/* update first hole */
	idx = INDEX_RECORD_INDEX(index, rec);
	if (hdr->first_hole_records == 0) {
		/* first deleted message in index */
		hdr->first_hole_index = idx;
		hdr->first_hole_records = 1;
	} else if (idx+1 == hdr->first_hole_index) {
		/* deleted the previous record before hole */
		hdr->first_hole_index--;
		hdr->first_hole_records++;
	} else if (idx == hdr->first_hole_index + hdr->first_hole_records) {
		/* deleted the next record after hole */
		hdr->first_hole_records++;
		update_first_hole_records(index);
	} else {
		/* second hole coming to index file */
		if (idx < hdr->first_hole_index) {
			/* new hole before the old hole */
			hdr->first_hole_index = idx;
			hdr->first_hole_records = 1;
		}
	}

	/* update message counts */
	if (hdr->messages_count == 0) {
		/* corrupted */
		index_set_corrupted(index, "Header says there's no mail "
				    "while expunging");
		return FALSE;
	}

	hdr->messages_count--;
	mail_index_mark_flag_changes(index, rec, rec->msg_flags, 0);

	(void)mail_index_data_add_deleted_space(index->data, rec->data_size);

	records = MAIL_INDEX_RECORD_COUNT(index);
	if (hdr->first_hole_index + hdr->first_hole_records == records) {
		/* the hole reaches end of file, truncate it */
		(void)mail_index_truncate_hole(index);
	} else {
		if (INDEX_NEED_COMPRESS(records, hdr))
			hdr->flags |= MAIL_INDEX_FLAG_COMPRESS;
	}

	/* expunge() may be called while index is being rebuilt and when
	   tree file hasn't been opened yet */
	if (index->tree != NULL)
		mail_tree_delete(index->tree, uid);
	else {
		/* make sure it also gets updated */
		index->header->flags |= MAIL_INDEX_FLAG_REBUILD_TREE;
	}

	if (seq != 0 && index->modifylog != NULL) {
		if (!mail_modifylog_add_expunge(index->modifylog, seq,
						uid, external_change))
			return FALSE;
	}

	return TRUE;
}

int mail_index_update_flags(MailIndex *index, MailIndexRecord *rec,
			    unsigned int seq, MailFlags flags,
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

static int mail_index_grow(MailIndex *index)
{
	uoff_t pos;
	unsigned int grow_count;
	void *base;

	grow_count = index->header->messages_count *
		INDEX_GROW_PERCENTAGE / 100;
	if (grow_count < 16)
		grow_count = 16;

	pos = index->mmap_full_length + (grow_count * sizeof(MailIndexRecord));
	i_assert(pos < OFF_T_MAX);

	if (index->anon_mmap) {
		i_assert(pos < SSIZE_T_MAX);

		base = mremap_anon(index->mmap_base, index->mmap_full_length,
				   (size_t)pos, MREMAP_MAYMOVE);
		if (base == MAP_FAILED)
			return index_set_syscall_error(index, "mremap_anon()");

		index->mmap_base = base;
		index->mmap_full_length = (size_t)pos;
		return TRUE;
	}

	if (file_set_size(index->fd, (off_t)pos) < 0) {
		if (errno == ENOSPC)
			index->nodiskspace = TRUE;
		return index_set_syscall_error(index, "file_set_size()");
	}

	/* file size changed, let others know about it too by changing
	   sync_id in header. */
	index->header->sync_id++;

	if (!mail_index_mmap_update(index))
		return FALSE;

	return TRUE;
}

int mail_index_append_begin(MailIndex *index, MailIndexRecord **rec)
{
	MailIndexRecord *destrec;

	i_assert(index->lock_type == MAIL_LOCK_EXCLUSIVE);
	i_assert((*rec)->uid == 0);
	i_assert((*rec)->msg_flags == 0);

	if (index->mmap_used_length == index->mmap_full_length) {
		if (!mail_index_grow(index))
			return FALSE;
	}

	i_assert(index->header->used_file_size == index->mmap_used_length);
	i_assert(index->mmap_used_length + sizeof(MailIndexRecord) <=
		 index->mmap_full_length);

	destrec = (MailIndexRecord *) ((char *) index->mmap_base +
				       index->mmap_used_length);
	memcpy(destrec, *rec, sizeof(MailIndexRecord));
	*rec = destrec;

	index->header->used_file_size += sizeof(MailIndexRecord);
	index->mmap_used_length += sizeof(MailIndexRecord);
	return TRUE;
}

int mail_index_append_end(MailIndex *index, MailIndexRecord *rec)
{
	i_assert(rec->uid == 0);

	index->header->messages_count++;
	rec->uid = index->header->next_uid++;

	if (index->tree != NULL) {
		mail_tree_insert(index->tree, rec->uid,
				 INDEX_RECORD_INDEX(index, rec));
	}

	return TRUE;
}

const char *mail_index_get_last_error(MailIndex *index)
{
	return index->error;
}

int mail_index_is_diskspace_error(MailIndex *index)
{
	return !index->inconsistent && index->nodiskspace;
}

int mail_index_is_inconsistency_error(MailIndex *index)
{
	return index->inconsistent;
}
