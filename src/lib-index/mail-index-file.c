/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "file-set-size.h"
#include "mail-index.h"
#include "mail-index-util.h"

#include <unistd.h>

struct mail_index_record *mail_index_next(struct mail_index *index,
					  struct mail_index_record *rec)
{
	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);
	i_assert(rec >= INDEX_RECORD_AT(index, 0));

	return rec+1 == INDEX_END_RECORD(index) ? NULL : rec+1;
}

static int compress(struct mail_index *index, unsigned int remove_first_idx,
		    unsigned int remove_last_idx)
{
	struct mail_index_record *rec = INDEX_RECORD_AT(index, 0);
	unsigned int idx_limit, count;

	idx_limit = MAIL_INDEX_RECORD_COUNT(index);
	count = remove_last_idx - remove_first_idx + 1;

	memmove(rec + remove_first_idx, rec + remove_last_idx + 1,
		(idx_limit - remove_last_idx - 1) * sizeof(*rec));

	index->header->used_file_size -= sizeof(*rec) * count;
	index->mmap_used_length -= sizeof(*rec) * count;

	return mail_index_truncate(index);
}

int mail_index_expunge_record_range(struct mail_index *index,
				    struct mail_index_record *first_rec,
				    struct mail_index_record *last_rec)
{
	struct mail_index_record *rec;
	unsigned int first_idx, last_idx, idx_limit;

        i_assert(index->lock_type == MAIL_LOCK_EXCLUSIVE);

	first_idx = INDEX_RECORD_INDEX(index, first_rec);
	last_idx = INDEX_RECORD_INDEX(index, last_rec);
	idx_limit = MAIL_INDEX_RECORD_COUNT(index);

	i_assert(first_idx <= last_idx);
	i_assert(last_idx < idx_limit);

	index->header->messages_count -= last_idx - first_idx + 1;
	for (rec = first_rec; rec <= last_rec; rec++)
		mail_index_mark_flag_changes(index, rec, rec->msg_flags, 0);

	return compress(index, first_idx, last_idx);
}

struct mail_index_record *mail_index_lookup(struct mail_index *index,
					    unsigned int seq)
{
	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);
	i_assert(seq > 0);

	if (seq > index->header->messages_count)
		return NULL;

	return INDEX_RECORD_AT(index, seq-1);
}

struct mail_index_record *
mail_index_lookup_uid_range(struct mail_index *index, unsigned int first_uid,
			    unsigned int last_uid, unsigned int *seq_r)
{
	struct mail_index_record *rec_p;
	unsigned int idx_limit, idx, left_idx, right_idx;

	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);
	i_assert(first_uid > 0);
	i_assert(first_uid <= last_uid);

	rec_p = INDEX_RECORD_AT(index, 0);
	idx_limit = MAIL_INDEX_RECORD_COUNT(index);

	idx = 0;
	left_idx = 0;
	right_idx = idx_limit;

	while (left_idx < right_idx) {
		idx = (left_idx + right_idx) / 2;

		if (rec_p[idx].uid < first_uid)
			left_idx = idx+1;
		else if (rec_p[idx].uid > first_uid)
			right_idx = idx;
		else
			break;
	}

	if (rec_p[idx].uid < first_uid || rec_p[idx].uid > last_uid) {
		/* could still be the next one */
		idx++;
		if (idx == idx_limit ||
		    rec_p[idx].uid < first_uid || rec_p[idx].uid > last_uid) {
			if (seq_r != NULL) *seq_r = 0;
			return NULL;
		}
	}

	if (seq_r != NULL)
		*seq_r = idx + 1;
	return rec_p + idx;
}

int mail_index_compress(struct mail_index *index)
{
	size_t diff;
	off_t new_file_size;

	if (index->header_size >= sizeof(struct mail_index_header))
		return TRUE;

	if (!index->set_lock(index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	/* make sure the file is large enough */
	diff = sizeof(struct mail_index_header) - index->header_size;
	if (index->mmap_used_length + diff > index->mmap_full_length) {
		/* mmap_update ftruncates the file to multiples of
		   mail_index_record, make sure we grow it enough here. */
		new_file_size = index->mmap_used_length + diff +
			(sizeof(struct mail_index_record) -
			 (diff % sizeof(struct mail_index_record)));
		if (file_set_size(index->fd, new_file_size) < 0) {
			index_set_syscall_error(index, "file_set_size()");
			return FALSE;
		}

		index->header->sync_id++;
		if (!mail_index_mmap_update(index))
			return FALSE;
	}

	/* if we break, we'll have to rebuild it completely */
	index->header->flags |= MAIL_INDEX_HDR_FLAG_REBUILD;
	if (!mail_index_fmdatasync(index, index->header_size))
		return FALSE;

	memmove((char *) index->mmap_base + sizeof(struct mail_index_header),
		(char *) index->mmap_base + index->header_size,
		index->mmap_used_length - index->header_size);
	memset((char *) index->mmap_base + index->header_size, 0, diff);

	index->mmap_used_length += diff;
	index->header_size = sizeof(struct mail_index_header);

	index->header->header_size = sizeof(struct mail_index_header);
	index->header->used_file_size += diff;
	index->header->sync_id++;
 
	if (!mail_index_fmdatasync(index, index->mmap_used_length))
		return FALSE;

	index->header->flags &= ~MAIL_INDEX_HDR_FLAG_REBUILD;
	return mail_index_mmap_update(index);
}

int mail_index_truncate(struct mail_index *index)
{
	uoff_t empty_space, truncate_threshold;

	i_assert(index->lock_type == MAIL_LOCK_EXCLUSIVE);

	if (index->mmap_full_length <= INDEX_FILE_MIN_SIZE(index) ||
	    index->anon_mmap)
		return TRUE;

	/* really truncate the file only when it's almost empty */
	empty_space = index->mmap_full_length - index->mmap_used_length;
	truncate_threshold =
		index->mmap_full_length / 100 * INDEX_TRUNCATE_PERCENTAGE;

	if (empty_space > truncate_threshold) {
		index->mmap_full_length = index->mmap_used_length +
			(empty_space * INDEX_TRUNCATE_KEEP_PERCENTAGE / 100);

		/* keep the size record-aligned */
		index->mmap_full_length -= (index->mmap_full_length -
					    index->header_size) %
			sizeof(struct mail_index_record);

		if (index->mmap_full_length < INDEX_FILE_MIN_SIZE(index))
                        index->mmap_full_length = INDEX_FILE_MIN_SIZE(index);

		if (ftruncate(index->fd, (off_t)index->mmap_full_length) < 0)
			return index_set_syscall_error(index, "ftruncate()");

		index->header->sync_id++;
	}

	return TRUE;
}
