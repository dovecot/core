/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "write-full.h"
#include "mail-index.h"
#include "mail-index-data.h"
#include "mail-index-util.h"

#include <stdio.h>
#include <unistd.h>

int mail_index_compress(MailIndex *index)
{
	MailIndexHeader *hdr;
	MailIndexRecord *rec, *hole_rec, *end_rec;
	off_t fsize;

	if (!index->set_lock(index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	hdr = index->get_header(index);

	if (hdr->first_hole_position == 0) {
		/* we don't need to compress after all. shouldn't happen.. */
		index->header->flags &= ~MAIL_INDEX_FLAG_CACHE_FIELDS;
		return TRUE;
	}

	/* if we get interrupted, the whole index is probably corrupted.
	   so keep rebuild-flag on while doing this */
	hdr->flags |= MAIL_INDEX_FLAG_REBUILD;
	if (!mail_index_fmsync(index, sizeof(MailIndexHeader)))
		return FALSE;

	/* first actually compress the data */
	end_rec = (MailIndexRecord *) ((char *) index->mmap_base +
				       index->mmap_length);
	hole_rec = (MailIndexRecord *) ((char *) index->mmap_base +
					hdr->first_hole_position);
	rec = hole_rec + hdr->first_hole_records;
	while (rec < end_rec) {
		if (rec->uid != 0) {
			memcpy(hole_rec, rec, sizeof(MailIndexRecord));
			hole_rec++;
		}
		rec++;
	}

	/* truncate the file to get rid of the extra records */
	fsize = (char *) hole_rec - (char *) index->mmap_base;
	if (ftruncate(index->fd, fsize) == -1) {
		index_set_error(index, "ftruncate() failed for %s: %m",
				index->filepath);
		return FALSE;
	}

	/* update headers */
	index->header->first_hole_position = 0;
	index->header->first_hole_records = 0;

	/* make sure the whole file is synced before removing rebuild-flag */
	if (!mail_index_fmsync(index, fsize))
		return FALSE;

	index->header->flags &= ~(MAIL_INDEX_FLAG_CACHE_FIELDS |
				  MAIL_INDEX_FLAG_REBUILD);
	return TRUE;
}

int mail_index_compress_data(MailIndex *index)
{
	MailIndexRecord *rec;
	MailIndexDataHeader data_hdr;
	unsigned char *mmap_data;
	size_t mmap_data_size;
	off_t offset;
	const char *temppath, *datapath;
	int fd;

	/* write the data into temporary file updating the offsets in index
	   while doing it. if we fail (especially if out of disk space/quota)
	   we'll simply fail and index is rebuilt later */
	if (!index->set_lock(index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	mmap_data = mail_index_data_get_mmaped(index->data, &mmap_data_size);
	if (mmap_data == NULL)
		return FALSE;

	fd = mail_index_create_temp_file(index, &temppath);
	if (fd == -1)
		return FALSE;

	/* write data header */
	memset(&data_hdr, 0, sizeof(data_hdr));
	data_hdr.indexid = index->indexid;
	if (write_full(fd, &data_hdr, sizeof(data_hdr)) < 0) {
		index_set_error(index, "Error writing to temp index data "
				"%s: %m", temppath);
		(void)close(fd);
		(void)unlink(temppath);
		return FALSE;
	}

	/* no we'll begin the actual moving. keep rebuild-flag on
	   while doing it. */
	index->header->flags |= MAIL_INDEX_FLAG_REBUILD;
	if (!mail_index_fmsync(index, sizeof(MailIndexHeader))) {
		(void)close(fd);
		(void)unlink(temppath);
		return FALSE;
	}

	offset = sizeof(data_hdr);
	rec = index->lookup(index, 1);
	while (rec != NULL) {
		if (write_full(fd, mmap_data + rec->data_position,
			       rec->data_size) < 0) {
			index_set_error(index, "Error writing to temp index "
					"data %s: %m", temppath);
			(void)close(fd);
			(void)unlink(temppath);
			return FALSE;
		}

		rec->data_position = offset;
		offset += rec->data_size;

		rec = index->next(index, rec);
	}

	/* now, close the old data file and rename the temp file into
	   new data file */
	mail_index_data_free(index->data);
	(void)close(fd);

	datapath = t_strconcat(index->filepath, DATA_FILE_PREFIX, NULL);
	if (rename(temppath, datapath) < 0) {
		index_set_error(index, "rename(%s, %s) failed: %m",
				temppath, datapath);
		return FALSE;
	}

	/* make sure the whole file is synced before removing rebuild-flag */
	if (!mail_index_fmsync(index, index->mmap_length))
		return FALSE;

	index->header->flags &= ~(MAIL_INDEX_FLAG_CACHE_FIELDS |
				  MAIL_INDEX_FLAG_REBUILD);

	return mail_index_data_open(index);
}
