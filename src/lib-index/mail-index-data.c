/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "file-set-size.h"
#include "mmap-util.h"
#include "write-full.h"
#include "mail-index.h"
#include "mail-index-data.h"
#include "mail-index-util.h"

#include <stdio.h>
#include <fcntl.h>

#define DATA_FILE_POSITION(data, rec) \
	((uoff_t) ((char *) (rec) - (char *) ((data)->mmap_base)))

/* Never compress the file if it's smaller than this */
#define COMPRESS_MIN_SIZE (1024*50)

/* Compress the file when deleted space reaches n% of total size */
#define COMPRESS_PERCENTAGE 20

/* Initial size for the file */
#define INDEX_DATA_INITIAL_SIZE (sizeof(MailIndexDataHeader) + 10240)

/* When more space is needed, grow the file n% larger than the previous size */
#define INDEX_DATA_GROW_PERCENTAGE 10

struct _MailIndexData {
	MailIndex *index;

	int fd;
	char *filepath;

	void *mmap_base;
	size_t mmap_full_length;
	size_t mmap_used_length;

	MailIndexDataHeader *header;

	unsigned int anon_mmap:1;
	unsigned int dirty_mmap:1;
};

int index_data_set_corrupted(MailIndexData *data, const char *fmt, ...)
{
	va_list va;

	INDEX_MARK_CORRUPTED(data->index);
	data->index->inconsistent = TRUE;

	va_start(va, fmt);
	t_push();
	index_set_error(data->index, "Corrupted index data file %s: %s",
			data->filepath, t_strdup_vprintf(fmt, va));
	t_pop();
	va_end(va);

	return FALSE;
}

static int index_data_set_syscall_error(MailIndexData *data,
					const char *function)
{
	i_assert(function != NULL);

	index_set_error(data->index, "%s failed with index data file %s: %m",
			function, data->filepath);
	return FALSE;
}

static int data_file_reopen(MailIndexData *data)
{
	int fd;

	i_assert(!data->anon_mmap);

	fd = open(data->filepath, O_RDWR);
	if (fd == -1)
		return index_data_set_syscall_error(data, "open()");

	if (close(data->fd) < 0)
		index_data_set_syscall_error(data, "close()");

	data->fd = fd;
	return TRUE;
}

static int mmap_update(MailIndexData *data, uoff_t pos, size_t size)
{
	MailIndexDataHeader *hdr;

	if (data->header != NULL &&
	    data->header->indexid != data->index->indexid) {
		if (data->header->indexid != 0) {
			/* index was just rebuilt. we should have noticed
			   this before at index->set_lock() though. */
			index_set_error(data->index,
					"Warning: Inconsistency - Index "
					"%s was rebuilt while we had it open",
					data->filepath);
			data->index->inconsistent = TRUE;
			return FALSE;
		}

		/* data file was deleted, reopen it */
		if (!data_file_reopen(data))
			return FALSE;

		size = 0;
	}

	if (size != 0) {
		if (pos + size <= data->mmap_used_length)
			return TRUE;

		if (pos + size <= data->mmap_full_length) {
			data->mmap_used_length = data->header->used_file_size;
			if (data->mmap_used_length <= data->mmap_full_length)
				return TRUE;

			/* file size changed, re-mmap() */
		}
	}

	i_assert(!data->anon_mmap);

	if (data->mmap_base != NULL) {
		if (data->mmap_used_length > 0 &&
		    msync(data->mmap_base, data->mmap_used_length, MS_SYNC) < 0)
			return index_data_set_syscall_error(data, "msync()");

		if (munmap(data->mmap_base, data->mmap_full_length) < 0)
			index_data_set_syscall_error(data, "munmap()");
	}

	data->header = NULL;
	data->mmap_used_length = 0;

	data->mmap_base = mmap_rw_file(data->fd, &data->mmap_full_length);
	if (data->mmap_base == MAP_FAILED) {
		data->mmap_base = NULL;
		return index_data_set_syscall_error(data, "mmap()");
	}

	if (data->mmap_full_length < sizeof(MailIndexDataHeader))
		return index_data_set_corrupted(data, "File too small");

	hdr = data->mmap_base;

	if (hdr->used_file_size < sizeof(MailIndexDataHeader)) {
		index_data_set_corrupted(data, "used_file_size too small ("
					 "%"PRIuUOFF_T")", hdr->used_file_size);
		return FALSE;
	}

	if (hdr->used_file_size > data->mmap_full_length) {
		index_data_set_corrupted(data, "used_file_size larger than "
					 "real file size (%"PRIuUOFF_T
					 " vs %"PRIuSIZE_T")",
					 hdr->used_file_size,
					 data->mmap_full_length);
		return FALSE;
	}

	data->mmap_used_length = hdr->used_file_size;
	data->header = hdr;
	return TRUE;
}

int mail_index_data_open(MailIndex *index)
{
	MailIndexData *data;
	const char *path;
	int fd;

	path = t_strconcat(index->filepath, DATA_FILE_PREFIX, NULL);
	fd = open(path, O_RDWR);
	if (fd == -1) {
		if (errno == ENOENT) {
			/* doesn't exist, rebuild the index */
			INDEX_MARK_CORRUPTED(index);
		}
		return index_file_set_syscall_error(index, path, "open()");
	}

	data = i_new(MailIndexData, 1);
	data->index = index;
	data->fd = fd;
	data->filepath = i_strdup(path);

	index->data = data;

	if (!mmap_update(data, 0, sizeof(MailIndexDataHeader))) {
		mail_index_data_free(data);
		return FALSE;
	}

	/* verify that this really is the data file for wanted index */
	if (data->header->indexid != index->indexid) {
		INDEX_MARK_CORRUPTED(index);
		index_set_error(index, "IndexID mismatch for data file %s",
				path);
		mail_index_data_free(data);
		return FALSE;
	}

	return TRUE;
}

static const char *init_data_file(MailIndex *index, MailIndexDataHeader *hdr,
				  int fd, const char *temppath)
{
	const char *realpath;

	if (write_full(fd, hdr, sizeof(MailIndexDataHeader)) < 0) {
		index_file_set_syscall_error(index, temppath, "write_full()");
		return NULL;
	}

	if (file_set_size(fd, INDEX_DATA_INITIAL_SIZE) < 0) {
		index_file_set_syscall_error(index, temppath,
					     "file_set_size()");
		return NULL;
	}

	/* move temp file into .data file, deleting old one
	   if it already exists */
	realpath = t_strconcat(index->filepath, DATA_FILE_PREFIX, NULL);
	if (rename(temppath, realpath) < 0) {
		index_set_error(index, "rename(%s, %s) failed: %m",
				temppath, realpath);
		return NULL;
	}

	return realpath;
}

int mail_index_data_create(MailIndex *index)
{
        MailIndexDataHeader hdr;
	MailIndexData *data;
	const char *temppath, *realpath;
	int fd;

	memset(&hdr, 0, sizeof(MailIndexDataHeader));
	hdr.indexid = index->indexid;
	hdr.used_file_size = sizeof(MailIndexDataHeader);

	realpath = NULL;

	/* we'll do anon-mmaping only if initially requested. if we fail
	   because of out of disk space, we'll just let the main index code
	   know it and fail. */
	if (index->nodiskspace) {
		fd = -1;
	} else {
		fd = mail_index_create_temp_file(index, &temppath);
		if (fd == -1) {
			if (errno == ENOSPC)
				index->nodiskspace = TRUE;
			return FALSE;
		}

		realpath = init_data_file(index, &hdr, fd, temppath);
		if (realpath == NULL) {
			if (errno == ENOSPC)
				index->nodiskspace = TRUE;

			(void)close(fd);
			(void)unlink(temppath);
			return FALSE;
		}
	}

	data = i_new(MailIndexData, 1);

	if (fd == -1) {
		data->mmap_full_length = INDEX_DATA_INITIAL_SIZE;
		data->mmap_base = mmap_anon(data->mmap_full_length);

		memcpy(data->mmap_base, &hdr, sizeof(MailIndexDataHeader));
		data->header = data->mmap_base;
		data->mmap_used_length = data->header->used_file_size;

		data->anon_mmap = TRUE;
		data->filepath = i_strdup("(in-memory index data)");
	} else {
		data->filepath = i_strdup(realpath);
	}

	data->index = index;
	data->fd = fd;

	if (!mmap_update(data, 0, sizeof(MailIndexDataHeader))) {
		mail_index_data_free(data);
		return FALSE;
	}

	index->data = data;
	return TRUE;
}

void mail_index_data_free(MailIndexData *data)
{
	data->index->data = NULL;

	if (data->anon_mmap) {
		if (munmap_anon(data->mmap_base, data->mmap_full_length) < 0)
			index_data_set_syscall_error(data, "munmap_anon()");
	} else if (data->mmap_base != NULL) {
		if (munmap(data->mmap_base, data->mmap_full_length) < 0)
			index_data_set_syscall_error(data, "munmap()");
	}

	if (data->fd != -1) {
		if (close(data->fd) < 0)
			index_data_set_syscall_error(data, "close()");
	}
	i_free(data->filepath);
	i_free(data);
}

int mail_index_data_reset(MailIndexData *data)
{
	MailIndexDataHeader hdr;

	memset(&hdr, 0, sizeof(MailIndexDataHeader));
	hdr.indexid = data->index->indexid;
	hdr.used_file_size = sizeof(MailIndexDataHeader);

	if (data->anon_mmap) {
		memcpy(data->mmap_base, &hdr, sizeof(MailIndexDataHeader));
		return TRUE;
	}

	if (file_set_size(data->fd, INDEX_DATA_INITIAL_SIZE) < 0) {
		if (errno == ENOSPC)
			data->index->nodiskspace = TRUE;
		return index_data_set_syscall_error(data, "file_set_size()");
	}

	if (lseek(data->fd, 0, SEEK_SET) < 0)
		return index_data_set_syscall_error(data, "lseek()");

	if (write_full(data->fd, &hdr, sizeof(MailIndexDataHeader)) < 0) {
		if (errno == ENOSPC)
			data->index->nodiskspace = TRUE;
		return index_data_set_syscall_error(data, "write_full()");
	}

	return TRUE;
}

int mail_index_data_mark_deleted(MailIndexData *data)
{
	if (data->anon_mmap)
		return TRUE;

	data->header->indexid = 0;
	if (msync(data->mmap_base, 0, sizeof(MailIndexDataHeader)) < 0)
		return index_data_set_syscall_error(data, "msync()");

	return TRUE;
}

static int mail_index_data_grow(MailIndexData *data, size_t size)
{
	void *base;
	uoff_t new_fsize;
	off_t pos;

	new_fsize = data->header->used_file_size + size;
	new_fsize += new_fsize / 100 * INDEX_DATA_GROW_PERCENTAGE;

	if (data->anon_mmap) {
		i_assert(new_fsize < SSIZE_T_MAX);

		base = mremap_anon(data->mmap_base, data->mmap_full_length,
				   (size_t)new_fsize, MREMAP_MAYMOVE);
		if (base == MAP_FAILED) {
			index_data_set_syscall_error(data, "mremap_anon()");
			return FALSE;
		}

		data->mmap_base = base;
		data->mmap_full_length = (size_t)new_fsize;
		return TRUE;
	}

	pos = lseek(data->fd, 0, SEEK_END);
	if (pos < 0)
		return index_data_set_syscall_error(data, "lseek()");

	if (data->header->used_file_size + size <= (uoff_t)pos) {
		/* no need to grow, just update mmap */
		if (!mmap_update(data, 0, 0))
			return FALSE;

		i_assert(data->mmap_full_length >= (uoff_t)pos);
		return TRUE;
	}

	if (pos < (int)sizeof(MailIndexDataHeader))
		return index_data_set_corrupted(data, "Header is missing");

	if (file_set_size(data->fd, new_fsize) < 0) {
		if (errno == ENOSPC)
			data->index->nodiskspace = TRUE;
		return index_data_set_syscall_error(data, "file_set_size()");
	}

	return mmap_update(data, 0, 0);
}

uoff_t mail_index_data_append(MailIndexData *data, const void *buffer,
			      size_t size)
{
	uoff_t offset;

	i_assert((size & (MEM_ALIGN_SIZE-1)) == 0);
	i_assert(data->index->lock_type == MAIL_LOCK_EXCLUSIVE);

	if (size > data->mmap_full_length ||
	    data->mmap_full_length - size < data->header->used_file_size) {
		if (!mail_index_data_grow(data, size))
			return 0;
	}

	offset = data->header->used_file_size;
	i_assert(offset + size <= data->mmap_full_length);

	memcpy((char *) data->mmap_base + offset, buffer, size);
	data->header->used_file_size += size;

	return offset;
}

int mail_index_data_add_deleted_space(MailIndexData *data, size_t data_size)
{
	uoff_t max_del_space;

	i_assert(data->index->lock_type == MAIL_LOCK_EXCLUSIVE);

	data->header->deleted_space += data_size;

	/* see if we've reached the max. deleted space in file */
	if (data->header->used_file_size >= COMPRESS_MIN_SIZE &&
	    (data->index->header->flags & MAIL_INDEX_FLAG_COMPRESS_DATA) == 0) {
		max_del_space = data->header->used_file_size /
			100 * COMPRESS_PERCENTAGE;
		if (data->header->deleted_space >= max_del_space)
			data->index->set_flags |= MAIL_INDEX_FLAG_COMPRESS_DATA;
	}
	return TRUE;
}

int mail_index_data_sync_file(MailIndexData *data)
{
	if (data->anon_mmap)
		return TRUE;

	if (data->mmap_base != NULL) {
		if (msync(data->mmap_base, data->mmap_used_length, MS_SYNC) < 0)
			return index_data_set_syscall_error(data, "msync()");
	}

	if (fsync(data->fd) < 0)
		return index_data_set_syscall_error(data, "fsync()");

	return TRUE;
}

MailIndexDataRecord *
mail_index_data_lookup(MailIndexData *data, MailIndexRecord *index_rec,
		       MailField field)
{
	MailIndexDataRecord *rec;
	uoff_t pos, max_pos;

	if (index_rec->data_position == 0) {
		/* data not yet written to record - FIXME: is this an error? */
		return NULL;
	}

	if (!mmap_update(data, index_rec->data_position, index_rec->data_size))
		return NULL;

	if (index_rec->data_position > data->mmap_used_length ||
	    (data->mmap_used_length -
	     index_rec->data_position < index_rec->data_size)) {
		index_data_set_corrupted(data,
			"Given data size larger than file size "
			"(%"PRIuUOFF_T" + %u > %"PRIuSIZE_T") for record %u",
			index_rec->data_position, index_rec->data_size,
			data->mmap_used_length, index_rec->uid);
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
			index_data_set_corrupted(data,
				"Field %d size points outside file "
				"(%"PRIuUOFF_T" / %"PRIuUOFF_T") for record %u",
				(int)field, pos, max_pos, index_rec->uid);
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
		index_data_set_corrupted(data, "Field size points outside file "
					 "(%"PRIuUOFF_T" + %u > %"PRIuUOFF_T")",
					 pos, rec->full_field_size, max_pos);
		return NULL;
	}

	return rec;
}

int mail_index_data_record_verify(MailIndexData *data, MailIndexDataRecord *rec)
{
	int i;

	if (rec->full_field_size > INT_MAX) {
		/* we already checked that the full_field_size is within file,
		   so this can happen only if the file really is huge.. */
		index_data_set_corrupted(data, "full_field_size (%u) > INT_MAX",
					 rec->full_field_size);
		return FALSE;
	}

	/* make sure the data actually contains \0 */
	for (i = (int)rec->full_field_size-1; i >= 0; i--) {
		if (rec->data[i] == '\0') {
			/* yes, everything ok */
			return TRUE;
		}
	}

	index_data_set_corrupted(data, "Missing \\0 with field %u "
				 "(%"PRIuUOFF_T")", rec->field,
				 DATA_FILE_POSITION(data, rec));
	return FALSE;
}

void *mail_index_data_get_mmaped(MailIndexData *data, size_t *size)
{
	if (!mmap_update(data, 0, 0))
		return NULL;

	*size = data->mmap_used_length;
	return data->mmap_base;
}
