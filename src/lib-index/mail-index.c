/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "file-lock.h"
#include "file-set-size.h"
#include "mmap-util.h"
#include "mail-index.h"
#include "mail-index-data.h"
#include "mail-index-util.h"
#include "mail-hash.h"
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

	index->last_lookup_seq = 0;
	index->last_lookup = NULL;

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

	if (index->hash != NULL) {
                mail_hash_free(index->hash);
		index->hash = NULL;
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

	if (index->hash != NULL) {
		if (!mail_hash_sync_file(index->hash))
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

	/* reset last_lookup so rebuilds don't try to use it */
	index->last_lookup_seq = 0;
	index->last_lookup = NULL;

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
	unsigned int max_records, first_records;

	hdr = index->header;
	if (hdr->first_hole_position == 0)
		return TRUE;

	/* make sure position is valid */
	if (hdr->first_hole_position < sizeof(MailIndexHeader) ||
	    (hdr->first_hole_position -
	     sizeof(MailIndexHeader)) % sizeof(MailIndexRecord) != 0) {
		index_set_corrupted(index, "first_hole_position contains "
				    "invalid value");
		return FALSE;
	}

	/* make sure position is in range.. */
	if (hdr->first_hole_position >= index->mmap_used_length) {
		index_set_corrupted(index, "first_hole_position points "
				    "outside file");
		return FALSE;
	}

	/* and finally check that first_hole_records is in valid range */
	max_records = MAIL_INDEX_RECORD_COUNT(index);
	first_records = (hdr->first_hole_position -
			 sizeof(MailIndexHeader)) / sizeof(MailIndexRecord);
	if (index->header->first_hole_records > max_records ||
	    first_records + index->header->first_hole_records > max_records) {
		index_set_corrupted(index, "first_hole_records points "
				    "outside file");
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
	MailIndexRecord *rec, *last_rec;
	unsigned int rec_seq;
	uoff_t seekpos;

	i_assert(seq > 0);
	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);

	if (seq == index->last_lookup_seq &&
	    index->last_lookup != NULL && index->last_lookup->uid != 0) {
		/* wanted the same record as last time */
		return index->last_lookup;
	}

	hdr = index->header;
	if (seq > hdr->messages_count) {
		/* out of range */
		return NULL;
	}

	if (!mail_index_verify_hole_range(index))
		return NULL;

	seekpos = sizeof(MailIndexHeader) +
		(uoff_t)(seq-1) * sizeof(MailIndexRecord);
	if (seekpos + sizeof(MailIndexRecord) > index->mmap_used_length) {
		/* minimum file position for wanted sequence would point
		   ouside file, so it can't exist. however, header said it
		   should be found.. */
		i_assert(index->header->used_file_size ==
			 index->mmap_used_length);

		index_set_corrupted(index,
				    "Header contains invalid message count");
		return NULL;
	}

	rec = (MailIndexRecord *) ((char *) index->mmap_base +
				   sizeof(MailIndexHeader));
	last_rec = (MailIndexRecord *) ((char *) index->mmap_base +
					index->mmap_used_length -
					sizeof(MailIndexRecord));

	if (hdr->first_hole_position == 0 ||
	    hdr->first_hole_position > seekpos) {
		/* easy, it's just at the expected index */
		rec += seq-1;
		i_assert(rec <= last_rec);

		if (rec->uid == 0) {
			index_set_corrupted(index, "first_hole_position "
					    "wasn't updated properly");
			return NULL;
		}

		index->last_lookup = rec;
		index->last_lookup_seq = seq;
		return rec;
	}

	/* we need to walk through the index to get to wanted position */

	/* some mails are deleted, jump after the first known hole
	   and start counting non-deleted messages.. */
	rec_seq = INDEX_POSITION_INDEX(hdr->first_hole_position+1) + 1;
	rec += rec_seq-1 + hdr->first_hole_records;

	if (seq > index->last_lookup_seq && index->last_lookup_seq > rec_seq) {
		/* we want to lookup data after last lookup -
		   this helps us some */
		rec = index->last_lookup;
		rec_seq = index->last_lookup_seq;
	}

	i_assert(rec->uid != 0);

	while (rec_seq < seq && rec <= last_rec) {
		rec++;

		if (rec->uid != 0)
			rec_seq++;
	}

	if (rec_seq != seq)
		return NULL;
	else {
		index->last_lookup = rec;
		index->last_lookup_seq = rec_seq;
		return rec;
	}
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
					     unsigned int last_uid)
{
	MailIndexRecord *rec, *end_rec;
	unsigned int uid, last_try_uid;
	uoff_t pos;

	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);
	i_assert(first_uid > 0 && last_uid > 0);
	i_assert(first_uid <= last_uid);

	if (!mail_index_verify_hole_range(index))
		return NULL;

	end_rec = (MailIndexRecord *) ((char *) index->mmap_base +
				       index->mmap_used_length);

	/* check if first_uid is the first UID in the index, or an UID
	   before that. this is quite common and hash lookup would be
	   useless to try with those nonexisting old UIDs */
	if (index->header->first_hole_position != sizeof(MailIndexHeader)) {
		rec = (MailIndexRecord *) ((char *) index->mmap_base +
					   sizeof(MailIndexHeader));
	} else {
		rec = (MailIndexRecord *) ((char *) index->mmap_base +
					   index->header->first_hole_position +
					   index->header->first_hole_records *
					   sizeof(MailIndexRecord));
	}

	if (rec >= end_rec) {
		/* no messages in index */
		return NULL;
	}

	if (first_uid <= rec->uid) {
		/* yes, first_uid pointed to beginning of index.
		   make sure last_uid is in that range too. */
		return last_uid >= rec->uid ? rec : NULL;
	}

	if (first_uid >= index->header->next_uid) {
		/* UID doesn't even exist yet */
		return NULL;
	}

	/* try the few first with hash lookups */
	last_try_uid = last_uid - first_uid < 10 ? last_uid : first_uid + 4;
	for (uid = first_uid; uid <= last_try_uid; uid++) {
		pos = mail_hash_lookup_uid(index->hash, uid);
		if (pos == 0)
			continue;

		rec = (MailIndexRecord *) ((char *) index->mmap_base + pos);
		if (rec->uid != uid) {
			index_set_error(index, "Corrupted hash for index %s: "
					"lookup returned offset to different "
					"UID (%u vs %u)", index->filepath,
					rec->uid, uid);
			index->set_flags |= MAIL_INDEX_FLAG_REBUILD_HASH;
			rec = NULL;
		}
		return rec;
	}

	if (last_try_uid == last_uid)
		return NULL;

	/* fallback to looking through the whole index - this shouldn't be
	   needed often, so don't bother trying anything too fancy. */
	rec = (MailIndexRecord *) ((char *) index->mmap_base +
				   sizeof(MailIndexHeader));
	while (rec < end_rec) {
		if (rec->uid != 0) {
			if (rec->uid > last_uid)
				return NULL;

			if (rec->uid >= first_uid)
				return rec;
		}
		rec++;
	}

	return NULL;
}

static MailIndexDataRecord *
index_lookup_data_field(MailIndex *index, MailIndexRecord *rec, MailField field)
{
	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);

	/* first check if the field even could be in the file */
	if ((rec->cached_fields & field) != field) {
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

		return NULL;
	}

	return mail_index_data_lookup(index->data, rec, field);
}

const char *mail_index_lookup_field(MailIndex *index, MailIndexRecord *rec,
				    MailField field)
{
	MailIndexDataRecord *datarec;

	datarec = index_lookup_data_field(index, rec, field);
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

	datarec = index_lookup_data_field(index, rec, field);
	if (datarec == NULL) {
		*size = 0;
		return NULL;
	}

	*size = datarec->full_field_size;
	return datarec->data;
}

static unsigned int mail_index_get_sequence_real(MailIndex *index,
						 MailIndexRecord *rec)
{
	MailIndexRecord *seekrec;
	unsigned int seq;

	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);

	if (rec == index->last_lookup) {
		/* same as last lookup sequence - too easy */
		return index->last_lookup_seq;
	}

	if (index->header->first_hole_position == 0) {
		/* easy, it's just at the expected index */
		return INDEX_POSITION_INDEX(
			INDEX_FILE_POSITION(index, rec)) + 1;
	}

	if (!mail_index_verify_hole_range(index))
		return 0;

	seekrec = (MailIndexRecord *) ((char *) index->mmap_base +
				       index->header->first_hole_position);
	if (rec < seekrec) {
		/* record before first hole */
		return INDEX_POSITION_INDEX(
			INDEX_FILE_POSITION(index, rec)) + 1;
	}

	/* we know the sequence after the first hole - skip to there and
	   start browsing the records until ours is found */
	seq = INDEX_POSITION_INDEX(INDEX_FILE_POSITION(index, seekrec))+1;
	seekrec += index->header->first_hole_records;

	for (; seekrec < rec; seekrec++) {
		if (seekrec->uid != 0)
			seq++;
	}

	return seq;
}

unsigned int mail_index_get_sequence(MailIndex *index, MailIndexRecord *rec)
{
	unsigned int seq;

	seq = mail_index_get_sequence_real(index, rec);
	if (seq > index->header->messages_count) {
		index_set_corrupted(index, "Too small messages_count in header "
				    "(found %u > %u)", seq,
				    index->header->messages_count);
		return 0;
	}

	return seq;
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
				   index->header->first_hole_position) +
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
	index->header->used_file_size =
		(size_t)index->header->first_hole_position;
	index->header->first_hole_position = 0;
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

int mail_index_expunge(MailIndex *index, MailIndexRecord *rec,
		       unsigned int seq, int external_change)
{
	MailIndexHeader *hdr;
	uoff_t pos;

	i_assert(index->lock_type == MAIL_LOCK_EXCLUSIVE);
	i_assert(seq != 0);
	i_assert(rec->uid != 0);

	if (seq != 0 && index->modifylog != NULL) {
		if (!mail_modifylog_add_expunge(index->modifylog, seq,
						rec->uid, external_change))
			return FALSE;
	}

	/* expunge() may be called while index is being rebuilt and when
	   there's no hash yet */
	if (index->hash != NULL)
		mail_hash_update(index->hash, rec->uid, 0);
	else {
		/* make sure it also gets updated */
		index->header->flags |= MAIL_INDEX_FLAG_REBUILD_HASH;
	}

	/* setting UID to 0 is enough for deleting the mail from index */
	rec->uid = 0;

	/* update last_lookup_seq */
	if (seq != 0) {
		/* note that last_lookup can be left to point to
		   invalid record so that next() works properly */
		if (seq == index->last_lookup_seq)
			index->last_lookup = NULL;
		else if (seq < index->last_lookup_seq)
			index->last_lookup_seq--;
	}

	if (!mail_index_verify_hole_range(index))
		return FALSE;

	hdr = index->header;

	/* update first hole */
	pos = INDEX_FILE_POSITION(index, rec);
	if (hdr->first_hole_position < sizeof(MailIndexRecord)) {
		/* first deleted message in index */
		hdr->first_hole_position = pos;
		hdr->first_hole_records = 1;
	} else if (hdr->first_hole_position - sizeof(MailIndexRecord) == pos) {
		/* deleted the previous record before hole */
		hdr->first_hole_position -= sizeof(MailIndexRecord);
		hdr->first_hole_records++;
	} else if (hdr->first_hole_position +
		   (hdr->first_hole_records * sizeof(MailIndexRecord)) == pos) {
		/* deleted the next record after hole */
		hdr->first_hole_records++;
		update_first_hole_records(index);
	} else {
		/* second hole coming to index file, the index now needs to
		   be compressed to keep high performance */
		index->set_flags |= MAIL_INDEX_FLAG_COMPRESS;

		if (hdr->first_hole_position > pos) {
			/* new hole before the old hole */
			hdr->first_hole_position = pos;
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

	if ((hdr->first_hole_position - sizeof(MailIndexHeader)) /
	    sizeof(MailIndexRecord) == hdr->messages_count) {
		/* the hole reaches end of file, truncate it */
		(void)mail_index_truncate_hole(index);
	} else {
		/* update deleted_space in data file */
		(void)mail_index_data_add_deleted_space(index->data,
							rec->data_size);
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

	if (index->hash != NULL) {
		mail_hash_update(index->hash, rec->uid,
				 INDEX_FILE_POSITION(index, rec));
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
