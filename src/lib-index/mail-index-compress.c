/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "write-full.h"
#include "mail-index.h"
#include "mail-index-data.h"
#include "mail-index-util.h"
#include "mail-tree.h"

#include <stdio.h>
#include <unistd.h>

int mail_index_truncate(MailIndex *index)
{
	uoff_t empty_space, truncate_threshold;

	i_assert(index->lock_type == MAIL_LOCK_EXCLUSIVE);

	if (index->mmap_full_length <= INDEX_FILE_MIN_SIZE)
		return TRUE;

	/* really truncate the file only when it's almost empty */
	empty_space = index->mmap_full_length - index->mmap_used_length;
	truncate_threshold =
		index->mmap_full_length / 100 * INDEX_TRUNCATE_PERCENTAGE;

	if (empty_space > truncate_threshold) {
		index->mmap_full_length = index->mmap_used_length +
			(empty_space * INDEX_TRUNCATE_KEEP_PERCENTAGE / 100);

		/* keep the size record-aligned */
		index->mmap_full_length -=
			(index->mmap_full_length - sizeof(MailIndexHeader)) %
			sizeof(MailIndexRecord);

		if (index->mmap_full_length < INDEX_FILE_MIN_SIZE)
                        index->mmap_full_length = INDEX_FILE_MIN_SIZE;

		if (ftruncate(index->fd, (off_t)index->mmap_full_length) < 0)
			return index_set_syscall_error(index, "ftruncate()");

		index->header->sync_id++;
	}

	return TRUE;
}

int mail_index_compress(MailIndex *index)
{
	MailIndexRecord *rec, *hole_rec, *end_rec;
	unsigned int idx;
	int tree_fd;

	if (!index->set_lock(index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	if (index->header->first_hole_records == 0) {
		/* we don't need to compress after all. shouldn't happen.. */
		index->header->flags &= ~MAIL_INDEX_FLAG_COMPRESS;
		return TRUE;
	}

	if (!mail_index_verify_hole_range(index))
		return FALSE;

	/* if we get interrupted, the whole index is probably corrupted.
	   so keep rebuild-flag on while doing this */
	index->header->flags |= MAIL_INDEX_FLAG_REBUILD;
	if (!mail_index_fmdatasync(index, sizeof(MailIndexHeader)))
		return FALSE;

	/* first actually compress the data */
	end_rec = (MailIndexRecord *) ((char *) index->mmap_base +
				       index->mmap_used_length);
	hole_rec = (MailIndexRecord *) ((char *) index->mmap_base +
					sizeof(MailIndexHeader)) +
		index->header->first_hole_index;
	rec = hole_rec + index->header->first_hole_records;
	while (rec < end_rec) {
		if (rec->uid != 0) {
			memcpy(hole_rec, rec, sizeof(MailIndexRecord));
			idx = INDEX_RECORD_INDEX(index, hole_rec);
			if (!mail_tree_update(index->tree, rec->uid, idx))
				return FALSE;
			hole_rec++;
		}
		rec++;
	}

	/* truncate the file to get rid of the extra records */
	index->mmap_used_length = (size_t) ((char *) hole_rec -
					    (char *) index->mmap_base);
	index->header->used_file_size = index->mmap_used_length;

	if (!mail_index_truncate(index))
		return FALSE;

	/* update headers */
	index->header->first_hole_index = 0;
	index->header->first_hole_records = 0;

	/* make sure the whole file is synced before removing rebuild-flag */
	if (!mail_tree_sync_file(index->tree, &tree_fd))
		return FALSE;

	if (fdatasync(tree_fd) < 0) {
		index_file_set_syscall_error(index, index->tree->filepath,
					     "fdatasync()");
		return FALSE;
	}

	if (!mail_index_fmdatasync(index, index->mmap_used_length))
		return FALSE;

	index->header->flags &= ~(MAIL_INDEX_FLAG_COMPRESS |
				  MAIL_INDEX_FLAG_REBUILD);
	return TRUE;
}

static int mail_index_copy_data(MailIndex *index, int fd, const char *path)
{
	MailIndexDataHeader data_hdr;
	MailIndexRecord *rec;
	unsigned char *mmap_data;
	size_t mmap_data_size;
	uoff_t offset;

	mmap_data = mail_index_data_get_mmaped(index->data, &mmap_data_size);
	if (mmap_data == NULL)
		return FALSE;

	/* write data header */
	memset(&data_hdr, 0, sizeof(data_hdr));
	data_hdr.indexid = index->indexid;
	if (write_full(fd, &data_hdr, sizeof(data_hdr)) < 0) {
		if (errno == ENOSPC)
			index->nodiskspace = TRUE;

		index_file_set_syscall_error(index, path, "write_full()");
		return FALSE;
	}

	/* now we'll begin the actual moving. keep rebuild-flag on
	   while doing it. */
	index->header->flags |= MAIL_INDEX_FLAG_REBUILD;
	if (!mail_index_fmdatasync(index, sizeof(MailIndexHeader)))
		return FALSE;

	offset = sizeof(data_hdr);
	rec = index->lookup(index, 1);
	while (rec != NULL) {
		if (rec->data_position + rec->data_size > mmap_data_size) {
			index_set_corrupted(index, "data_position+data_size "
					    "points outside file");
			return FALSE;
		}

		if (write_full(fd, mmap_data + rec->data_position,
			       rec->data_size) < 0) {
			if (errno == ENOSPC)
				index->nodiskspace = TRUE;

			index_file_set_syscall_error(index, path,
						     "write_full()");
			return FALSE;
		}

		rec->data_position = offset;
		offset += rec->data_size;

		rec = index->next(index, rec);
	}

	/* update header */
	data_hdr.used_file_size = offset;

	if (lseek(fd, 0, SEEK_SET) < 0)
		return index_file_set_syscall_error(index, path, "lseek()");

	if (write_full(fd, &data_hdr, sizeof(data_hdr)) < 0) {
		index_file_set_syscall_error(index, path, "write_full()");
		return FALSE;
	}

	return TRUE;
}

int mail_index_compress_data(MailIndex *index)
{
	const char *temppath, *datapath;
	int fd, failed;

	if (index->anon_mmap)
		return TRUE;

	/* write the data into temporary file updating the offsets in index
	   while doing it. if we fail (especially if out of disk space/quota)
	   we'll simply fail and index is rebuilt later */
	if (!index->set_lock(index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	fd = mail_index_create_temp_file(index, &temppath);
	if (fd == -1) {
		if (errno == ENOSPC)
			index->nodiskspace = TRUE;
		return FALSE;
	}

	failed = !mail_index_copy_data(index, fd, temppath);

	if (fdatasync(fd) < 0) {
		index_file_set_syscall_error(index, temppath, "fdatasync()");
		failed = TRUE;
	}

	if (close(fd) < 0) {
		index_file_set_syscall_error(index, temppath, "close()");
		failed = TRUE;
	}

	if (!failed) {
		/* now, rename the temp file to new data file. but before that
		   reset indexid to make sure that other processes know the
		   data file is closed. */
		(void)mail_index_data_mark_deleted(index->data);

		mail_index_data_free(index->data);

		datapath = t_strconcat(index->filepath, DATA_FILE_PREFIX, NULL);
		if (rename(temppath, datapath) < 0) {
			if (errno == ENOSPC)
				index->nodiskspace = TRUE;

			index_set_error(index, "rename(%s, %s) failed: %m",
					temppath, datapath);
			failed = TRUE;
		}
	}

	if (failed) {
		if (unlink(temppath) < 0) {
			index_file_set_syscall_error(index, temppath,
						     "unlink()");
		}
		return FALSE;
	}

	/* make sure the whole file is synced before removing rebuild-flag */
	if (!mail_index_fmdatasync(index, index->mmap_used_length))
		return FALSE;

	index->header->flags &= ~(MAIL_INDEX_FLAG_COMPRESS_DATA |
				  MAIL_INDEX_FLAG_REBUILD);

	return mail_index_data_open(index);
}
