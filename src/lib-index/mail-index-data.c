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
#define INDEX_DATA_INITIAL_SIZE (sizeof(struct mail_index_data_header) + 10240)

/* When more space is needed, grow the file n% larger than the previous size */
#define INDEX_DATA_GROW_PERCENTAGE 10

struct mail_index_data {
	struct mail_index *index;

	int fd;
	char *filepath;

	void *mmap_base;
	size_t mmap_full_length;
	size_t mmap_used_length;

	struct mail_index_data_header *header;

	unsigned int anon_mmap:1;
	unsigned int dirty_mmap:1;
	unsigned int modified:1;
	unsigned int fsynced:1;
};

int index_data_set_corrupted(struct mail_index_data *data, const char *fmt, ...)
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

static int index_data_set_syscall_error(struct mail_index_data *data,
					const char *function)
{
	i_assert(function != NULL);

	if (ENOSPACE(errno)) {
		data->index->nodiskspace = TRUE;
		return FALSE;
	}

	index_set_error(data->index, "%s failed with index data file %s: %m",
			function, data->filepath);
	return FALSE;
}

static int mail_index_data_msync(struct mail_index_data *data)
{
	if (!data->modified)
		return TRUE;

	if (!data->anon_mmap) {
		if (msync(data->mmap_base, data->mmap_used_length, MS_SYNC) < 0)
			return index_data_set_syscall_error(data, "msync()");
	}

	data->modified = FALSE;
	data->fsynced = FALSE;
	return TRUE;
}

static void mail_index_data_file_close(struct mail_index_data *data)
{
	(void)mail_index_data_msync(data);

	if (data->anon_mmap) {
		if (munmap_anon(data->mmap_base, data->mmap_full_length) < 0)
			index_data_set_syscall_error(data, "munmap_anon()");
	} else if (data->mmap_base != NULL) {
		if (munmap(data->mmap_base, data->mmap_full_length) < 0)
			index_data_set_syscall_error(data, "munmap()");
	}
	data->mmap_base = NULL;
	data->mmap_used_length = 0;
	data->mmap_full_length = 0;

	if (data->fd != -1) {
		if (close(data->fd) < 0)
			index_data_set_syscall_error(data, "close()");
		data->fd = -1;
	}
}

static int data_file_reopen(struct mail_index_data *data)
{
	int fd;

	i_assert(!data->anon_mmap);

	fd = open(data->filepath, O_RDWR);
	if (fd == -1)
		return index_data_set_syscall_error(data, "open()");

	mail_index_data_file_close(data);

	data->fd = fd;
	return TRUE;
}

static int mmap_update(struct mail_index_data *data, uoff_t pos, size_t size)
{
	struct mail_index_data_header *hdr;

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

		/* force mmap refresh */
		size = 0;
	}

	if (size != 0) {
		debug_mprotect(data->mmap_base, data->mmap_full_length,
			       data->index);

		if (pos + size <= data->mmap_used_length)
			return TRUE;

		if (pos + size <= data->mmap_full_length) {
			data->mmap_used_length = data->header->used_file_size;
			if (data->mmap_used_length >=
			    sizeof(struct mail_index_data_header) &&
			    data->mmap_used_length <= data->mmap_full_length)
				return TRUE;

			/* file size changed, re-mmap() */
		}
	}

	i_assert(!data->anon_mmap);

	if (data->mmap_base != NULL) {
		if (!mail_index_data_msync(data))
			return FALSE;

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

	if (data->mmap_full_length < sizeof(struct mail_index_data_header))
		return index_data_set_corrupted(data, "File too small");

	hdr = data->mmap_base;

	if (hdr->used_file_size < sizeof(struct mail_index_data_header)) {
		index_data_set_corrupted(data, "used_file_size too small ("
					 "%"PRIuUOFF_T")", hdr->used_file_size);
		return FALSE;
	}

	if (hdr->used_file_size > data->mmap_full_length) {
		index_data_set_corrupted(data,
			"used_file_size larger than real file size "
			"(%"PRIuUOFF_T" vs %"PRIuSIZE_T")",
			hdr->used_file_size, data->mmap_full_length);
		return FALSE;
	}

	data->mmap_used_length = hdr->used_file_size;
	data->header = hdr;
	debug_mprotect(data->mmap_base, data->mmap_full_length, data->index);
	return TRUE;
}

int mail_index_data_open(struct mail_index *index)
{
	struct mail_index_data *data;
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

	data = i_new(struct mail_index_data, 1);
	data->index = index;
	data->fd = fd;
	data->filepath = i_strdup(path);

	index->data = data;

	if (!mmap_update(data, 0, sizeof(struct mail_index_data_header))) {
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

static int mail_index_data_init(struct mail_index *index,
				struct mail_index_data_header *hdr,
				const char *path, int fd)
{
	if (write_full(fd, hdr, sizeof(*hdr)) < 0) {
		index_file_set_syscall_error(index, path, "write_full()");
		return FALSE;
	}

	if (file_set_size(fd, INDEX_DATA_INITIAL_SIZE) < 0) {
		index_file_set_syscall_error(index, path, "file_set_size()");
		return FALSE;
	}

	return TRUE;
}

int mail_index_data_create(struct mail_index *index)
{
        struct mail_index_data_header hdr;
	struct mail_index_data *data;
	const char *path;
	int fd;

	i_assert(index->lock_type == MAIL_LOCK_EXCLUSIVE);

	memset(&hdr, 0, sizeof(struct mail_index_data_header));
	hdr.indexid = index->indexid;
	hdr.used_file_size = sizeof(struct mail_index_data_header);

	/* we'll do anon-mmaping only if initially requested. if we fail
	   because of out of disk space, we'll just let the main index code
	   know it and fail. */
	if (INDEX_IS_IN_MEMORY(index)) {
		fd = -1;
		path = NULL;
	} else {
		path = t_strconcat(index->filepath, DATA_FILE_PREFIX, NULL);
		fd = open(path, O_RDWR | O_CREAT, 0660);
		if (fd == -1) {
			index_file_set_syscall_error(index, path, "open()");
			return FALSE;
		}

		if (!mail_index_data_init(index, &hdr, path, fd)) {
			(void)close(fd);
			return FALSE;
		}
	}

	data = i_new(struct mail_index_data, 1);

	if (fd == -1) {
		data->mmap_full_length = INDEX_DATA_INITIAL_SIZE;
		data->mmap_base = mmap_anon(data->mmap_full_length);
		if (data->mmap_base == MAP_FAILED) {
			i_free(data);
			return index_file_set_syscall_error(index, path,
							    "mmap_anon()");
		}

		memcpy(data->mmap_base, &hdr, sizeof(hdr));
		data->header = data->mmap_base;
		data->mmap_used_length = data->header->used_file_size;

		data->anon_mmap = TRUE;
		data->filepath =
			i_strdup_printf("(in-memory index data index for %s)",
					index->mailbox_path);
	} else {
		data->filepath = i_strdup(path);
	}

	data->index = index;
	data->fd = fd;

	if (!mmap_update(data, 0, sizeof(struct mail_index_data_header))) {
		mail_index_data_free(data);
		return FALSE;
	}

	index->data = data;
	return TRUE;
}

void mail_index_data_free(struct mail_index_data *data)
{
	data->index->data = NULL;

	mail_index_data_file_close(data);

	i_free(data->filepath);
	i_free(data);
}

int mail_index_data_reset(struct mail_index_data *data)
{
	struct mail_index_data_header hdr;

	memset(&hdr, 0, sizeof(struct mail_index_data_header));
	hdr.indexid = data->index->indexid;
	hdr.used_file_size = sizeof(struct mail_index_data_header);
	memcpy(data->mmap_base, &hdr, sizeof(hdr));

	if (data->anon_mmap)
		return TRUE;

	if (msync(data->mmap_base, sizeof(hdr), MS_SYNC) < 0)
		return index_data_set_syscall_error(data, "msync()");

	if (file_set_size(data->fd, INDEX_DATA_INITIAL_SIZE) < 0)
		return index_data_set_syscall_error(data, "file_set_size()");

	data->modified = FALSE;
	data->fsynced = FALSE;
	return mmap_update(data, 0, 0);
}

int mail_index_data_mark_file_deleted(struct mail_index_data *data)
{
	if (data->anon_mmap)
		return TRUE;

	data->header->indexid = 0;
	if (msync(data->mmap_base,
		  sizeof(struct mail_index_data_header), MS_SYNC) < 0)
		return index_data_set_syscall_error(data, "msync()");

	data->fsynced = FALSE;
	return TRUE;
}

void mail_index_data_mark_modified(struct mail_index_data *data)
{
	data->modified = TRUE;
}

static int mail_index_data_grow(struct mail_index_data *data, size_t size)
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
		data->header = data->mmap_base;
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

	if (pos < (off_t)sizeof(struct mail_index_data_header))
		return index_data_set_corrupted(data, "Header is missing");

	if (file_set_size(data->fd, (off_t)new_fsize) < 0)
		return index_data_set_syscall_error(data, "file_set_size()");

	return mmap_update(data, 0, 0);
}

uoff_t mail_index_data_append(struct mail_index_data *data, const void *buffer,
			      size_t size)
{
	uoff_t offset;

	i_assert((size & (INDEX_ALIGN_SIZE-1)) == 0);
	i_assert(data->index->lock_type == MAIL_LOCK_EXCLUSIVE);

	if (!mmap_update(data, 0, sizeof(struct mail_index_data_header)))
		return 0;

	if (size > data->mmap_full_length ||
	    data->mmap_full_length - size < data->header->used_file_size) {
		if (!mail_index_data_grow(data, size))
			return 0;
	}

	offset = data->header->used_file_size;
	i_assert(offset + size <= data->mmap_full_length);

	memcpy((char *) data->mmap_base + offset, buffer, size);
	data->header->used_file_size += size;
	data->mmap_used_length += size;

        data->modified = TRUE;
	return offset;
}

int mail_index_data_delete(struct mail_index_data *data,
			   struct mail_index_record *index_rec)
{
        struct mail_index_data_record_header *rec_hdr;
	uoff_t max_del_space;

	i_assert(data->index->lock_type == MAIL_LOCK_EXCLUSIVE);

	rec_hdr = mail_index_data_lookup_header(data, index_rec);
	if (rec_hdr == NULL)
		return FALSE;

	/* just mark it deleted. */
	data->header->deleted_space += rec_hdr->data_size;

	/* clear the record data. not really needed, but better not to keep
	   deleted information lying around.. */
	memset((char *) rec_hdr + sizeof(*rec_hdr), 0,
	       rec_hdr->data_size - sizeof(*rec_hdr));

	/* see if we've reached the max. deleted space in file */
	if (data->header->used_file_size >= COMPRESS_MIN_SIZE &&
	    (data->index->header->flags & MAIL_INDEX_FLAG_COMPRESS_DATA) == 0) {
		max_del_space = data->header->used_file_size /
			100 * COMPRESS_PERCENTAGE;
		if (data->header->deleted_space >= max_del_space)
			data->index->set_flags |= MAIL_INDEX_FLAG_COMPRESS_DATA;
	}

        data->modified = TRUE;
	return TRUE;
}

int mail_index_data_sync_file(struct mail_index_data *data, int *fsync_fd)
{
	*fsync_fd = -1;

	if (data->anon_mmap)
		return TRUE;

	if (!mail_index_data_msync(data))
		return FALSE;

	if (!data->fsynced) {
		data->fsynced = TRUE;
		*fsync_fd = data->fd;
	}

	return TRUE;
}

struct mail_index_data_record_header *
mail_index_data_lookup_header(struct mail_index_data *data,
			      struct mail_index_record *index_rec)
{
	uoff_t pos;

	pos = index_rec->data_position;
	if (pos == 0) {
		/* data not yet written to record */
		return NULL;
	}

	if (!mmap_update(data, pos,
			 sizeof(struct mail_index_data_record_header)))
		return NULL;

	if (pos + sizeof(struct mail_index_data_record_header) >
	    data->mmap_used_length) {
		index_data_set_corrupted(data,
			"Data position of record %u points outside file "
			"(%"PRIuUOFF_T" + %"PRIuSIZE_T" > %"PRIuSIZE_T")",
			index_rec->uid, pos,
			sizeof(struct mail_index_data_record_header),
			data->mmap_used_length);
		return NULL;
	}

	if ((pos % INDEX_ALIGN_SIZE) != 0) {
		index_data_set_corrupted(data, "Data position (%"PRIuUOFF_T") "
					 "is not memory aligned for record %u",
					 pos, index_rec->uid);
		return NULL;
	}

	return (struct mail_index_data_record_header *)
		((char *) data->mmap_base + pos);
}

struct mail_index_data_record *
mail_index_data_lookup(struct mail_index_data *data,
		       struct mail_index_record *index_rec,
		       enum mail_data_field field)
{
        struct mail_index_data_record_header *rec_hdr;
	struct mail_index_data_record *rec;
	uoff_t pos, max_pos;

	index_reset_error(data->index);

	if (index_rec->data_position == 0) {
		/* data not yet written to record */
		return NULL;
	}

	rec_hdr = mail_index_data_lookup_header(data, index_rec);
	if (rec_hdr == NULL)
		return NULL;

	if (!mmap_update(data, index_rec->data_position, rec_hdr->data_size))
		return NULL;

	pos = index_rec->data_position;
	max_pos = index_rec->data_position + rec_hdr->data_size;

	if (pos > data->mmap_used_length ||
	    (data->mmap_used_length - pos < rec_hdr->data_size)) {
		index_data_set_corrupted(data,
			"Given data size larger than file size "
			"(%"PRIuUOFF_T" + %u > %"PRIuSIZE_T") for record %u",
			index_rec->data_position, rec_hdr->data_size,
			data->mmap_used_length, index_rec->uid);
		return NULL;
	}

	pos += sizeof(struct mail_index_data_record_header);
	do {
		rec = (struct mail_index_data_record *)
			((char *) data->mmap_base + pos);

		if (rec->full_field_size > max_pos ||
		    pos + sizeof(struct mail_index_data_record) > max_pos ||
		    pos + DATA_RECORD_SIZE(rec) > max_pos) {
			index_data_set_corrupted(data,
				"Field %d size points outside file "
				"(%"PRIuUOFF_T" / %"PRIuUOFF_T") for record %u",
				(int)field, pos, max_pos, index_rec->uid);
			break;
		}

		if ((rec->full_field_size % INDEX_ALIGN_SIZE) != 0) {
			index_data_set_corrupted(data, "Field %d size %u "
				"is not memory aligned for record %u",
				(int)field, rec->full_field_size,
				index_rec->uid);
			break;
		}

		if (rec->field == field || field == 0) {
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

struct mail_index_data_record *
mail_index_data_next(struct mail_index_data *data,
		     struct mail_index_record *index_rec,
		     struct mail_index_data_record *rec)
{
        struct mail_index_data_record_header *rec_hdr;
	uoff_t pos, end_pos, max_pos;

	index_reset_error(data->index);

	if (rec == NULL)
		return NULL;

	rec_hdr = (struct mail_index_data_record_header *)
		((char *) data->mmap_base + index_rec->data_position);

	/* get position to next record */
	pos = DATA_FILE_POSITION(data, rec) + DATA_RECORD_SIZE(rec);
	max_pos = index_rec->data_position + rec_hdr->data_size;

	/* make sure it's within range */
	if (pos >= max_pos)
		return NULL;

	rec = (struct mail_index_data_record *)
		((char *) data->mmap_base + pos);
	end_pos = pos + DATA_RECORD_SIZE(rec);
	if (end_pos < pos || end_pos > max_pos) {
		index_data_set_corrupted(data, "Field size points outside file "
					 "(%"PRIuUOFF_T" + %u > %"PRIuUOFF_T")",
					 pos, rec->full_field_size, max_pos);
		return NULL;
	}

	return rec;
}

int mail_index_data_record_verify(struct mail_index_data *data,
				  struct mail_index_data_record *rec)
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

void *mail_index_data_get_mmaped(struct mail_index_data *data, size_t *size)
{
	if (!mmap_update(data, 0, 0))
		return NULL;

	*size = data->mmap_used_length;
	return data->mmap_base;
}
