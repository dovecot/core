/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "mmap-util.h"
#include "write-full.h"
#include "mail-index.h"
#include "mail-index-data.h"
#include "mail-index-util.h"

#include <stdio.h>
#include <fcntl.h>

#define DATA_FILE_POSITION(data, rec) \
	((uoff_t) ((char *) (rec) - (char *) ((data)->mmap_base)))

/* Never compress the file if it's smaller than this (50kB) */
#define COMPRESS_MIN_SIZE (1024*50)

/* Compress the file when deleted space reaches 20% of total size */
#define COMPRESS_PERCENTAGE 20

struct _MailIndexData {
	MailIndex *index;

	int fd;
	char *filepath;

	void *mmap_base;
	size_t mmap_length;

	unsigned int dirty_mmap:1;
};

static int mmap_update(MailIndexData *data, uoff_t pos, size_t size)
{
	if (!data->dirty_mmap && (size != 0 && pos+size <= data->mmap_length))
		return TRUE;

	if (data->mmap_base != NULL)
		(void)munmap(data->mmap_base, data->mmap_length);

	data->mmap_base = mmap_rw_file(data->fd, &data->mmap_length);
	if (data->mmap_base == MAP_FAILED) {
		data->mmap_base = NULL;
		index_set_error(data->index, "index data: mmap() failed with "
				"file %s: %m", data->filepath);
		return FALSE;
	} else if (data->mmap_length < sizeof(MailIndexDataHeader)) {
                INDEX_MARK_CORRUPTED(data->index);
		index_set_error(data->index, "index data: truncated data "
				"file %s", data->filepath);
		return FALSE;
	} else {
		data->dirty_mmap = FALSE;
		return TRUE;
	}
}

int mail_index_data_open(MailIndex *index)
{
	MailIndexData *data;
        MailIndexDataHeader *hdr;
	const char *path;
	int fd;

	path = t_strconcat(index->filepath, DATA_FILE_PREFIX, NULL);
	fd = open(path, O_RDWR);
	if (fd == -1) {
		if (errno == ENOENT) {
			/* doesn't exist, rebuild the index */
			INDEX_MARK_CORRUPTED(index);
		}
		index_set_error(index, "Can't open index data %s: %m", path);
		return FALSE;
	}

	data = i_new(MailIndexData, 1);
	data->index = index;
	data->fd = fd;
	data->filepath = i_strdup(path);
	data->dirty_mmap = TRUE;

	index->data = data;

	if (!mmap_update(data, 0, sizeof(MailIndexDataHeader))) {
		mail_index_data_free(data);
		return FALSE;
	}

	/* verify that this really is the data file for wanted index */
	hdr = data->mmap_base;
	if (hdr->indexid != index->indexid) {
		INDEX_MARK_CORRUPTED(index);
		index_set_error(index, "IndexID mismatch for data file %s",
				path);
		mail_index_data_free(data);
		return FALSE;
	}

	return TRUE;
}

static const char *init_data_file(MailIndex *index, int fd,
				  const char *temppath)
{
        MailIndexDataHeader hdr;
	const char *realpath;

	/* write header */
	memset(&hdr, 0, sizeof(hdr));
	hdr.indexid = index->indexid;

	if (write_full(fd, &hdr, sizeof(hdr)) < 0) {
		index_set_error(index, "Error writing to temp index data "
				"%s: %m", temppath);
		return NULL;
	}

	/* move temp file into .data file, deleting old one
	   if it already exists */
	realpath = t_strconcat(index->filepath, DATA_FILE_PREFIX, NULL);
	if (rename(temppath, realpath) == -1) {
		index_set_error(index, "rename(%s, %s) failed: %m",
				temppath, realpath);
		(void)unlink(temppath);
		return NULL;
	}

	return realpath;
}

int mail_index_data_create(MailIndex *index)
{
	MailIndexData *data;
	const char *temppath, *realpath;
	int fd;

	fd = mail_index_create_temp_file(index, &temppath);
	if (fd == -1)
		return FALSE;

	realpath = init_data_file(index, fd, temppath);
	if (realpath == NULL) {
		(void)close(fd);
		(void)unlink(temppath);
		return FALSE;
	}

	data = i_new(MailIndexData, 1);
	data->index = index;
	data->fd = fd;
	data->filepath = i_strdup(realpath);
	data->dirty_mmap = TRUE;

	index->data = data;
	return TRUE;
}

void mail_index_data_free(MailIndexData *data)
{
	data->index->data = NULL;

	if (data->mmap_base != NULL) {
		(void)munmap(data->mmap_base, data->mmap_length);
		data->mmap_base = NULL;
	}

	(void)close(data->fd);
	i_free(data->filepath);
	i_free(data);
}

int mail_index_data_reset(MailIndexData *data)
{
	MailIndexDataHeader hdr;

	if (ftruncate(data->fd, sizeof(MailIndexDataHeader)) == -1) {
		index_set_error(data->index, "ftruncate() failed for data file "
				"%s: %m", data->filepath);
		return FALSE;
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.indexid = data->index->indexid;
	hdr.deleted_space = 0;

	if (lseek(data->fd, 0, SEEK_SET) == -1) {
		index_set_error(data->index, "lseek() failed for data file "
				"%s: %m", data->filepath);
		return FALSE;
	}

	if (write_full(data->fd, &hdr, sizeof(hdr)) < 0) {
		index_set_error(data->index, "write() failed for data file "
				"%s: %m", data->filepath);
		return FALSE;
	}

	return TRUE;
}

void mail_index_data_new_data_notify(MailIndexData *data)
{
	data->dirty_mmap = TRUE;
}

uoff_t mail_index_data_append(MailIndexData *data, const void *buffer,
			      size_t size)
{
	off_t pos;

	i_assert((size & (MEM_ALIGN_SIZE-1)) == 0);

	pos = lseek(data->fd, 0, SEEK_END);
	if (pos == -1) {
		index_set_error(data->index, "lseek() failed with file %s: %m",
				data->filepath);
		return 0;
	}

	if (pos < (int)sizeof(MailIndexDataHeader)) {
		index_set_error(data->index, "Header missing from data file %s",
				data->filepath);
		return 0;
	}

	if (write_full(data->fd, buffer, size) < 0) {
		index_set_error(data->index, "Error appending to file %s: %m",
				data->filepath);
		return 0;
	}

	mail_index_data_new_data_notify(data);
	return (uoff_t)pos;
}

int mail_index_data_add_deleted_space(MailIndexData *data, size_t data_size)
{
	MailIndexDataHeader *hdr;
	uoff_t max_del_space;

	i_assert(data->index->lock_type == MAIL_LOCK_EXCLUSIVE);

	/* make sure the whole file is mmaped */
	if (!mmap_update(data, 0, 0))
		return FALSE;

	hdr = data->mmap_base;
	hdr->deleted_space += data_size;

	/* see if we've reached the max. deleted space in file */
	if (data->mmap_length >= COMPRESS_MIN_SIZE) {
		max_del_space = data->mmap_length / 100 * COMPRESS_PERCENTAGE;
		if (hdr->deleted_space >= max_del_space)
			data->index->set_flags |= MAIL_INDEX_FLAG_COMPRESS_DATA;
	}
	return TRUE;
}

int mail_index_data_sync_file(MailIndexData *data)
{
	if (data->mmap_base != NULL) {
		if (msync(data->mmap_base, data->mmap_length, MS_SYNC) == -1) {
			index_set_error(data->index, "msync() failed for "
					"%s: %m", data->filepath);
			return FALSE;
		}
	}

	if (fsync(data->fd) == -1) {
		index_set_error(data->index, "fsync() failed for %s: %m",
				data->filepath);
		return FALSE;
	}

	return TRUE;
}

MailIndexDataRecord *
mail_index_data_lookup(MailIndexData *data, MailIndexRecord *index_rec,
		       MailField field)
{
	MailIndexDataRecord *rec;
	uoff_t pos, max_pos;

	if (index_rec->data_position == 0) {
		/* data not yet written to record */
		index_reset_error(data->index);
		return NULL;
	}

	if (!mmap_update(data, index_rec->data_position, index_rec->data_size))
		return NULL;

	if (index_rec->data_position > data->mmap_length ||
	    (data->mmap_length -
	     index_rec->data_position < index_rec->data_size)) {
		INDEX_MARK_CORRUPTED(data->index);
		index_set_error(data->index, "Error in data file %s: "
				"Given data size larger than file size "
				"(%"PRIuUOFF_T" + %u > %"PRIuSIZE_T") "
				"for record %u",
				data->filepath, index_rec->data_position,
				index_rec->data_size, data->mmap_length,
				index_rec->uid);
		return NULL;
	}

	pos = index_rec->data_position;
	max_pos = pos + index_rec->data_size;

	do {
		rec = (MailIndexDataRecord *) ((char *) data->mmap_base + pos);

		/* pos + DATA_RECORD_SIZE() may actually overflow, but it
		   points to beginning of file then. Don't bother checking
		   this as it won't crash and is quite likely noticed later. */
		if (pos + sizeof(MailIndexDataRecord) > max_pos ||
		    pos + DATA_RECORD_SIZE(rec) > max_pos) {
			INDEX_MARK_CORRUPTED(data->index);
			index_set_error(data->index, "Error in data file %s: "
					"Field size points outside file "
					"(%"PRIuUOFF_T" / %"PRIuUOFF_T")",
					data->filepath, pos, max_pos);
			break;
		}

		if (rec->field == field) {
			/* match */
			return rec;
		} else if (rec->field < field) {
			/* jump to next record */
			pos += DATA_RECORD_SIZE(rec);
		} else {
			/* the fields are sorted by field type, so it's not
			   possible the wanted field could come after this. */
			break;
		}
	} while (pos < max_pos);

	return NULL;
}

MailIndexDataRecord *
mail_index_data_next(MailIndexData *data, MailIndexRecord *index_rec,
		     MailIndexDataRecord *rec)
{
	uoff_t pos, end_pos, max_pos;

	if (rec == NULL)
		return NULL;

	/* get position to next record */
	pos = DATA_FILE_POSITION(data, rec) + DATA_RECORD_SIZE(rec);
	max_pos = index_rec->data_position + index_rec->data_size;

	/* make sure it's within range */
	if (pos >= max_pos)
		return NULL;

	rec = (MailIndexDataRecord *) ((char *) data->mmap_base + pos);
	end_pos = pos + DATA_RECORD_SIZE(rec);
	if (end_pos < pos || end_pos > max_pos) {
		INDEX_MARK_CORRUPTED(data->index);
		index_set_error(data->index, "Error in data file %s: "
				"Field size points outside file "
				"(%"PRIuUOFF_T" + %u > %"PRIuUOFF_T")",
				data->filepath, pos, rec->full_field_size,
				max_pos);
		return NULL;
	}

	return rec;
}

int mail_index_data_record_verify(MailIndexData *data, MailIndexDataRecord *rec)
{
	int i;

	if (rec->full_field_size > INT_MAX) {
		/* we already check that the full_field_size is within file,
		   so this can happen only if the file really is huge.. */
		INDEX_MARK_CORRUPTED(data->index);
		index_set_error(data->index, "Error in data file %s: "
				"full_field_size > INT_MAX", data->filepath);
		return FALSE;
	}

	/* make sure the data actually contains \0 */
	for (i = (int)rec->full_field_size-1; i >= 0; i--) {
		if (rec->data[i] == '\0') {
			/* yes, everything ok */
			return TRUE;
		}
	}

	INDEX_MARK_CORRUPTED(data->index);
	index_set_error(data->index, "Error in data file %s: "
			"Missing \\0 with field %u (%"PRIuUOFF_T")",
			data->filepath, rec->field,
			DATA_FILE_POSITION(data, rec));
	return FALSE;
}

void *mail_index_data_get_mmaped(MailIndexData *data, size_t *size)
{
	if (!mmap_update(data, 0, 0))
		return NULL;

	*size = data->mmap_length;
	return data->mmap_base;
}
