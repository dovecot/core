/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "buffer.h"
#include "file-dotlock.h"
#include "read-full.h"
#include "write-full.h"
#include "mmap-util.h"
#include "mail-index-private.h"
#include "mail-index-view-private.h"
#include "mail-transaction-log-private.h"
#include "mail-transaction-util.h"
#include "mail-index-transaction-private.h"

#include <stddef.h>
#include <sys/stat.h>

#define LOG_PREFETCH 1024

/* this lock should never exist for a long time.. */
#define LOG_DOTLOCK_TIMEOUT 30
#define LOG_DOTLOCK_STALE_TIMEOUT 0
#define LOG_DOTLOCK_IMMEDIATE_STALE_TIMEOUT 300

#define LOG_NEW_DOTLOCK_SUFFIX ".newlock"

static struct mail_transaction_log_file *
mail_transaction_log_file_open_or_create(struct mail_transaction_log *log,
					 const char *path);
static int mail_transaction_log_rotate(struct mail_transaction_log *log,
				       int lock_type);
static int mail_transaction_log_lock_head(struct mail_transaction_log *log);

void
mail_transaction_log_file_set_corrupted(struct mail_transaction_log_file *file,
					const char *fmt, ...)
{
	va_list va;

	file->hdr.indexid = 0;
	if (pwrite_full(file->fd, &file->hdr.indexid,
			sizeof(file->hdr.indexid), 0) < 0) {
		mail_index_file_set_syscall_error(file->log->index,
						  file->filepath, "pwrite()");
	}

	va_start(va, fmt);
	t_push();
	mail_index_set_error(file->log->index,
			     "Corrupted transaction log file %s: %s",
			     file->filepath, t_strdup_vprintf(fmt, va));
	t_pop();
	va_end(va);

	/* this may have happened because of broken index. make sure it's ok. */
	(void)mail_index_fsck(file->log->index);
}

static int
mail_transaction_log_file_dotlock(struct mail_transaction_log_file *file)
{
	int ret;

	if (file->log->dotlock_count > 0)
		ret = 1;
	else {
		ret = file_lock_dotlock(file->filepath, NULL, FALSE,
					LOG_DOTLOCK_TIMEOUT,
					LOG_DOTLOCK_STALE_TIMEOUT,
					LOG_DOTLOCK_IMMEDIATE_STALE_TIMEOUT,
					NULL, NULL, &file->log->dotlock);
	}
	if (ret > 0) {
		file->log->dotlock_count++;
		file->locked = TRUE;
		return 0;
	}
	if (ret < 0) {
		mail_index_file_set_syscall_error(file->log->index,
						  file->filepath,
						  "file_lock_dotlock()");
		return -1;
	}

	mail_index_set_error(file->log->index,
			     "Timeout while waiting for release of "
			     "dotlock for transaction log file %s",
			     file->filepath);
	file->log->index->index_lock_timeout = TRUE;
	return -1;
}

static int
mail_transaction_log_file_undotlock(struct mail_transaction_log_file *file)
{
	int ret;

	if (--file->log->dotlock_count > 0)
		return 0;

	ret = file_unlock_dotlock(file->filepath, &file->log->dotlock);
	if (ret < 0) {
		mail_index_file_set_syscall_error(file->log->index,
			file->filepath, "file_unlock_dotlock()");
		return -1;
	}

	if (ret == 0) {
		mail_index_set_error(file->log->index,
			"Dotlock was lost for transaction log file %s",
			file->filepath);
		return -1;
	}
	return 0;
}

static int
mail_transaction_log_file_lock(struct mail_transaction_log_file *file)
{
	int ret;

	if (file->locked)
		return 0;

	if (file->log->index->lock_method == MAIL_INDEX_LOCK_DOTLOCK)
		return mail_transaction_log_file_dotlock(file);

	ret = mail_index_lock_fd(file->log->index, file->filepath, file->fd,
				 F_WRLCK, MAIL_INDEX_LOCK_SECS);
	if (ret > 0) {
		file->locked = TRUE;
		return 0;
	}
	if (ret < 0) {
		mail_index_file_set_syscall_error(file->log->index,
						  file->filepath,
						  "mail_index_wait_lock_fd()");
		return -1;
	}

	mail_index_set_error(file->log->index,
			     "Timeout while waiting for release of "
			     "fcntl() lock for transaction log file %s",
			     file->filepath);
	file->log->index->index_lock_timeout = TRUE;
	return -1;
}

static void
mail_transaction_log_file_unlock(struct mail_transaction_log_file *file)
{
	int ret;

	if (!file->locked)
		return;

	file->locked = FALSE;

	if (file->log->index->lock_method == MAIL_INDEX_LOCK_DOTLOCK) {
		mail_transaction_log_file_undotlock(file);
		return;
	}

	ret = mail_index_lock_fd(file->log->index, file->filepath, file->fd,
				 F_UNLCK, 0);
	if (ret <= 0) {
		mail_index_file_set_syscall_error(file->log->index,
						  file->filepath,
						  "mail_index_wait_lock_fd()");
	}
}

#define INDEX_HAS_MISSING_LOGS(index, file) \
	!(((file)->hdr.file_seq == (index)->hdr->log_file_seq && \
	   (index)->hdr->log_file_int_offset >= \
	   sizeof(struct mail_transaction_log_header)) || \
	  ((file)->hdr.prev_file_seq == (index)->hdr->log_file_seq && \
	   (file)->hdr.prev_file_offset == (index)->hdr->log_file_int_offset))

static int mail_transaction_log_check_file_seq(struct mail_transaction_log *log)
{
	struct mail_index *index = log->index;
	struct mail_transaction_log_file *file;
	unsigned int lock_id;
	int ret;

	if (mail_transaction_log_lock_head(log) < 0)
		return -1;

	file = log->head;
	file->refcount++;

	ret = mail_index_lock_shared(index, TRUE, &lock_id);
	if (ret == 0) {
		ret = mail_index_map(index, FALSE);
		if (ret <= 0)
			ret = -1;
		else if (INDEX_HAS_MISSING_LOGS(index, file)) {
			/* broken - fix it by creating a new log file */
			ret = mail_transaction_log_rotate(log, FALSE);
		}
	}

	if (--file->refcount == 0)
		mail_transaction_logs_clean(log);
	else
		mail_transaction_log_file_unlock(file);
	return ret;
}

struct mail_transaction_log *
mail_transaction_log_open_or_create(struct mail_index *index)
{
	struct mail_transaction_log *log;
	const char *path;

	log = i_new(struct mail_transaction_log, 1);
	log->index = index;

	path = t_strconcat(log->index->filepath,
			   MAIL_TRANSACTION_LOG_PREFIX, NULL);
	log->head = mail_transaction_log_file_open_or_create(log, path);
	if (log->head == NULL) {
		i_free(log);
		return NULL;
	}

	if (index->fd != -1 &&
	    INDEX_HAS_MISSING_LOGS(index, log->head)) {
		/* head log file isn't same as head index file -
		   shouldn't happen except in race conditions. lock them and
		   check again - FIXME: missing error handling. */
		(void)mail_transaction_log_check_file_seq(log);
	}
	return log;
}

void mail_transaction_log_close(struct mail_transaction_log *log)
{
	mail_transaction_log_views_close(log);

	log->head->refcount--;
	mail_transaction_logs_clean(log);

	log->index->log = NULL;
	i_free(log);
}

static void
mail_transaction_log_file_close(struct mail_transaction_log_file *file)
{
	mail_transaction_log_file_unlock(file);

	if (file->buffer != NULL)
		buffer_free(file->buffer);

	if (file->mmap_base != NULL) {
		if (munmap(file->mmap_base, file->mmap_size) < 0) {
			mail_index_file_set_syscall_error(file->log->index,
							  file->filepath,
							  "munmap()");
		}
	}

	if (close(file->fd) < 0) {
		mail_index_file_set_syscall_error(file->log->index,
						  file->filepath, "close()");
	}

	i_free(file->filepath);
	i_free(file);
}

static int
mail_transaction_log_file_read_hdr(struct mail_transaction_log_file *file)
{
	int ret;

	ret = pread_full(file->fd, &file->hdr, sizeof(file->hdr), 0);
	if (ret < 0) {
		// FIXME: handle ESTALE
		mail_index_file_set_syscall_error(file->log->index,
						  file->filepath,
						  "pread_full()");
		return -1;
	}
	if (ret == 0) {
		mail_transaction_log_file_set_corrupted(file,
			"unexpected end of file while reading header");
		return 0;
	}

	if (file->hdr.indexid == 0) {
		/* corrupted */
		mail_index_set_error(file->log->index,
			"Transaction log file %s: marked corrupted",
			file->filepath);
		return 0;
	}
	if (file->hdr.indexid != file->log->index->indexid) {
		if (file->log->index->fd == -1) {
			/* creating index file, silently rebuild
			   transaction log as well */
			return 0;
		}

		/* index file was probably just rebuilt and we don't know
		   about it yet */
		mail_index_set_error(file->log->index,
			"Transaction log file %s: invalid indexid (%u != %u)",
			file->filepath, file->hdr.indexid,
			file->log->index->indexid);
		return 0;
	}
	return 1;
}

static int
mail_transaction_log_file_create2(struct mail_transaction_log *log,
				  const char *path, int fd,
				  dev_t dev, ino_t ino)
{
	struct mail_index *index = log->index;
	struct mail_transaction_log_header hdr;
	struct stat st;
	unsigned int lock_id;
	int fd2, ret;

	/* log creation is locked now - see if someone already created it */
	fd2 = open(path, O_RDWR);
	if (fd2 != -1) {
		if ((ret = fstat(fd2, &st)) < 0) {
			mail_index_file_set_syscall_error(index, path,
							  "fstat()");
		} else if (st.st_ino == ino && CMP_DEV_T(st.st_dev, dev)) {
			/* same file, still broken */
		} else {
			(void)file_dotlock_delete(path, LOG_NEW_DOTLOCK_SUFFIX,
						  fd);
			return fd2;
		}

		(void)close(fd2);
		fd2 = -1;

		if (ret < 0)
			return -1;
	} else if (errno != ENOENT) {
		mail_index_file_set_syscall_error(index, path, "open()");
		return -1;
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.indexid = index->indexid;

	if (index->fd != -1) {
		if (mail_index_lock_shared(index, TRUE, &lock_id) < 0)
			return -1;
		hdr.prev_file_seq = index->hdr->log_file_seq;
		hdr.prev_file_offset = index->hdr->log_file_int_offset;
	}
	hdr.file_seq = index->hdr->log_file_seq+1;

	if (index->fd != -1)
		mail_index_unlock(index, lock_id);

	if (log->head != NULL && hdr.file_seq <= log->head->hdr.file_seq) {
		/* make sure the sequence grows */
		hdr.file_seq = log->head->hdr.file_seq+1;
	}

	if (write_full(fd, &hdr, sizeof(hdr)) < 0) {
		mail_index_file_set_syscall_error(index, path,
						  "write_full()");
		return -1;
	}

	fd2 = dup(fd);
	if (fd2 < 0) {
		mail_index_file_set_syscall_error(index, path, "dup()");
		return -1;
	}

	if (file_dotlock_replace(path, LOG_NEW_DOTLOCK_SUFFIX, fd, FALSE) <= 0)
		return -1;

	/* success */
	return fd2;
}

static int
mail_transaction_log_file_create(struct mail_transaction_log *log,
				 const char *path, dev_t dev, ino_t ino)
{
        mode_t old_mask;
	int fd, fd2;

	/* With dotlocking we might already have path.lock created, so this
	   filename has to be different. */
	old_mask = umask(log->index->mode ^ 0666);
	fd = file_dotlock_open(path, NULL, LOG_NEW_DOTLOCK_SUFFIX,
			       LOG_DOTLOCK_TIMEOUT,
			       LOG_DOTLOCK_STALE_TIMEOUT,
			       LOG_DOTLOCK_IMMEDIATE_STALE_TIMEOUT, NULL, NULL);
	umask(old_mask);

	if (fd == -1) {
		mail_index_file_set_syscall_error(log->index, path,
						  "file_dotlock_open()");
		return -1;
	}

	if (log->index->gid != (gid_t)-1 &&
	    fchown(fd, (uid_t)-1, log->index->gid) < 0) {
		mail_index_file_set_syscall_error(log->index, path, "fchown()");
		return -1;
	}

	fd2 = mail_transaction_log_file_create2(log, path, fd, dev, ino);
	if (fd2 < 0) {
		(void)file_dotlock_delete(path, LOG_NEW_DOTLOCK_SUFFIX, fd);
		return -1;
	}
	return fd2;
}

static struct mail_transaction_log_file *
mail_transaction_log_file_fd_open(struct mail_transaction_log *log,
				  const char *path, int fd)
{
	struct mail_transaction_log_file **p;
        struct mail_transaction_log_file *file;
	struct stat st;
	int ret;

	if (fstat(fd, &st) < 0) {
		mail_index_file_set_syscall_error(log->index, path, "fstat()");
		(void)close(fd);
		return NULL;
	}

	file = i_new(struct mail_transaction_log_file, 1);
	file->refcount = 1;
	file->log = log;
	file->filepath = i_strdup(path);
	file->fd = fd;
	file->st_dev = st.st_dev;
	file->st_ino = st.st_ino;
	file->last_mtime = st.st_mtime;
	file->sync_offset = sizeof(struct mail_transaction_log_header);

	ret = mail_transaction_log_file_read_hdr(file);
	if (ret == 0) {
		/* corrupted header */
		fd = mail_transaction_log_file_create(log, path,
						      st.st_dev, st.st_ino);
		if (fd == -1)
			ret = -1;
		else if (fstat(fd, &st) < 0) {
			mail_index_file_set_syscall_error(log->index, path,
							  "fstat()");
			(void)close(fd);
			fd = -1;
			ret = -1;
		}

		if (fd != -1) {
			(void)close(file->fd);
			file->fd = fd;

			file->st_dev = st.st_dev;
			file->st_ino = st.st_ino;
			file->last_mtime = st.st_mtime;

			memset(&file->hdr, 0, sizeof(file->hdr));
			ret = mail_transaction_log_file_read_hdr(file);
		}
	}
	if (ret <= 0) {
		mail_transaction_log_file_close(file);
		return NULL;
	}

	if (log->index->map != NULL &&
	    file->hdr.file_seq == log->index->map->hdr.log_file_seq &&
	    log->index->map->hdr.log_file_int_offset != 0) {
		/* we can get a valid log offset from index file. initialize
		   sync_offset from it so we don't have to read the whole log
		   file from beginning. */
		file->sync_offset = log->index->map->hdr.log_file_int_offset;
	}

	for (p = &log->tail; *p != NULL; p = &(*p)->next) {
		if ((*p)->hdr.file_seq >= file->hdr.file_seq) {
			/* log replaced with file having same sequence as
			   previous one. shouldn't happen unless previous
			   log file was corrupted.. */
			break;
		}
	}
	*p = file;

	return file;
}

static struct mail_transaction_log_file *
mail_transaction_log_file_open_or_create(struct mail_transaction_log *log,
					 const char *path)
{
	int fd;

	fd = open(path, O_RDWR);
	if (fd == -1) {
		if (errno != ENOENT) {
			mail_index_file_set_syscall_error(log->index, path,
							  "open()");
			return NULL;
		}

		fd = mail_transaction_log_file_create(log, path, 0, 0);
		if (fd == -1)
			return NULL;
	}

	return mail_transaction_log_file_fd_open(log, path, fd);
}

void mail_transaction_logs_clean(struct mail_transaction_log *log)
{
	struct mail_transaction_log_file **p, *next;

	for (p = &log->tail; *p != NULL; ) {
		if ((*p)->refcount != 0)
                        p = &(*p)->next;
		else {
			next = (*p)->next;
			mail_transaction_log_file_close(*p);
			*p = next;
		}
	}

	if (log->tail == NULL)
		log->head = NULL;
}

static int
mail_transaction_log_rotate(struct mail_transaction_log *log, int lock)
{
	struct mail_transaction_log_file *file;
	struct stat st;
	int fd;

	if (fstat(log->head->fd, &st) < 0) {
		mail_index_file_set_syscall_error(log->index,
						  log->head->filepath,
						  "fstat()");
		return -1;
	}

	fd = mail_transaction_log_file_create(log, log->head->filepath,
					      st.st_dev, st.st_ino);
	if (fd == -1)
		return -1;

	file = mail_transaction_log_file_fd_open(log, log->head->filepath, fd);
	if (file == NULL)
		return -1;

	if (lock) {
		if (mail_transaction_log_file_lock(file) < 0) {
			file->refcount--;
			mail_transaction_logs_clean(log);
			return -1;
		}
	}
	i_assert(file->locked == lock);

	if (--log->head->refcount == 0)
		mail_transaction_logs_clean(log);
	else
		mail_transaction_log_file_unlock(log->head);

	i_assert(log->head != file);
	log->head = file;
	return 0;
}

static int mail_transaction_log_recreate(struct mail_transaction_log *log)
{
	unsigned int lock_id;
	int ret;

	if (mail_index_lock_shared(log->index, TRUE, &lock_id) < 0)
		return -1;

	ret = mail_transaction_log_rotate(log, FALSE);
	mail_index_unlock(log->index, lock_id);
	return ret;
}

static int mail_transaction_log_refresh(struct mail_transaction_log *log)
{
        struct mail_transaction_log_file *file;
	struct stat st;
	const char *path;

	path = t_strconcat(log->index->filepath,
			   MAIL_TRANSACTION_LOG_PREFIX, NULL);
	if (stat(path, &st) < 0) {
		mail_index_file_set_syscall_error(log->index, path, "stat()");
		if (errno == ENOENT && log->head->locked) {
			/* lost? */
			return mail_transaction_log_recreate(log);
		}
		return -1;
	}

	if (log->head != NULL &&
	    log->head->st_ino == st.st_ino &&
	    CMP_DEV_T(log->head->st_dev, st.st_dev)) {
		/* same file */
		return 0;
	}

	file = mail_transaction_log_file_open_or_create(log, path);
	if (file == NULL)
		return -1;

	i_assert(!file->locked);

	if (log->head != NULL) {
		if (--log->head->refcount == 0)
			mail_transaction_logs_clean(log);
	}

	log->head = file;
	return 0;
}

int mail_transaction_log_file_find(struct mail_transaction_log *log,
				   uint32_t file_seq,
				   struct mail_transaction_log_file **file_r)
{
	struct mail_transaction_log_file *file;

	if (file_seq > log->head->hdr.file_seq) {
		if (mail_transaction_log_refresh(log) < 0)
			return -1;
	}

	for (file = log->tail; file != NULL; file = file->next) {
		if (file->hdr.file_seq == file_seq) {
			*file_r = file;
			return 1;
		}
	}

	return 0;
}

static int
mail_transaction_log_file_sync(struct mail_transaction_log_file *file)
{
        const struct mail_transaction_header *hdr;
	const void *data;
	size_t size;
	uint32_t hdr_size;

	data = buffer_get_data(file->buffer, &size);

	while (file->sync_offset - file->buffer_offset + sizeof(*hdr) <= size) {
		hdr = CONST_PTR_OFFSET(data, file->sync_offset -
				       file->buffer_offset);
		hdr_size = mail_index_offset_to_uint32(hdr->size);
		if (hdr_size == 0) {
			/* unfinished */
			if (file->mmap_base == NULL) {
				size = file->sync_offset - file->buffer_offset;
				buffer_set_used_size(file->buffer, size);
			}
			return 0;
		}
		if (hdr_size < sizeof(*hdr)) {
			mail_transaction_log_file_set_corrupted(file,
				"hdr.size too small (%u)", hdr_size);
			return -1;
		}

		if (file->sync_offset - file->buffer_offset + hdr_size > size)
			break;
		file->sync_offset += hdr_size;
	}
	return 0;
}

static int
mail_transaction_log_file_read(struct mail_transaction_log_file *file,
			       uoff_t offset)
{
	void *data;
	size_t size;
	uint32_t read_offset;
	int ret;

	i_assert(file->mmap_base == NULL);

	if (file->buffer != NULL && file->buffer_offset > offset) {
		/* we have to insert missing data to beginning of buffer */
		size = file->buffer_offset - offset;
		buffer_copy(file->buffer, size, file->buffer, 0, (size_t)-1);
		file->buffer_offset -= size;

		data = buffer_get_space_unsafe(file->buffer, 0, size);
		ret = pread_full(file->fd, data, size, offset);
		if (ret == 0) {
			mail_transaction_log_file_set_corrupted(file,
				"Unexpected end of file");
			return 0;
		}
		if (ret < 0) {
			if (errno == ESTALE) {
				/* log file was deleted in NFS server,
				   fail silently */
				return 0;
			}
			mail_index_file_set_syscall_error(file->log->index,
							  file->filepath,
							  "pread()");
			return -1;
 		}
	}

	if (file->buffer == NULL) {
		file->buffer =
			buffer_create_dynamic(default_pool, LOG_PREFETCH);
		file->buffer_offset = offset;
	}

	/* read all records */
	read_offset = file->buffer_offset + buffer_get_used_size(file->buffer);

	do {
		data = buffer_append_space_unsafe(file->buffer, LOG_PREFETCH);
		ret = pread(file->fd, data, LOG_PREFETCH, read_offset);
		if (ret > 0)
			read_offset += ret;

		size = read_offset - file->buffer_offset;
		buffer_set_used_size(file->buffer, size);
	} while (ret > 0 || (ret < 0 && errno == EINTR));

	if (mail_transaction_log_file_sync(file) < 0)
		return -1;

	if (ret == 0) {
		/* EOF */
		if (file->sync_offset > file->buffer_offset) {
			buffer_set_used_size(file->buffer, file->sync_offset -
					     file->buffer_offset);
		}
		return 1;
	}

	if (errno == ESTALE) {
		/* log file was deleted in NFS server, fail silently */
		buffer_set_used_size(file->buffer,
				     offset - file->buffer_offset);
		return 0;
	}

	mail_index_file_set_syscall_error(file->log->index, file->filepath,
					  "pread()");
	return -1;
}

int mail_transaction_log_file_map(struct mail_transaction_log_file *file,
				  uoff_t start_offset, uoff_t end_offset)
{
	struct mail_index *index = file->log->index;
	size_t size;
	struct stat st;
	int ret, use_mmap;

	i_assert(start_offset <= end_offset);

	if (file->hdr.indexid == 0) {
		/* corrupted */
		return 0;
	}

	if (start_offset < sizeof(file->hdr)) {
		mail_transaction_log_file_set_corrupted(file,
			"offset (%"PRIuUOFF_T") < header size (%"PRIuSIZE_T")",
			start_offset, sizeof(file->hdr));
		return -1;
	}

	/* with mmap_no_write we could alternatively just write to log with
	   msync() rather than pwrite(). that'd cause slightly more disk I/O,
	   so rather use more memory. */
	use_mmap = !index->mmap_disable && !index->mmap_no_write;

	if (file->buffer != NULL && file->buffer_offset <= start_offset) {
		/* see if we already have it */
		size = buffer_get_used_size(file->buffer);
		if (file->buffer_offset + size >= end_offset)
			return 1;
	}

	if (file->mmap_base != NULL || use_mmap) {
		if (fstat(file->fd, &st) < 0) {
			mail_index_file_set_syscall_error(index, file->filepath,
							  "fstat()");
			return -1;
		}
	}

	if (file->mmap_base != NULL && (uoff_t)st.st_size == file->mmap_size &&
	    file->buffer_offset <= start_offset && end_offset == (uoff_t)-1) {
		/* it's all mmaped already */
		if (mail_transaction_log_file_sync(file) < 0)
			return -1;
		return 1;
	}

	if (file->buffer != NULL &&
	    (file->mmap_base != NULL || use_mmap)) {
		buffer_free(file->buffer);
		file->buffer = NULL;
	}
	if (file->mmap_base != NULL) {
		if (munmap(file->mmap_base, file->mmap_size) < 0) {
			mail_index_file_set_syscall_error(index, file->filepath,
							  "munmap()");
		}
		file->mmap_base = NULL;
	}

	if (!use_mmap) {
		ret = mail_transaction_log_file_read(file, start_offset);
		if (ret <= 0) {
			/* make sure we don't leave ourself in
			   inconsistent state */
			if (file->buffer != NULL) {
				buffer_free(file->buffer);
				file->buffer = NULL;
			}
			return ret;
		}
	} else {
		file->mmap_size = st.st_size;
		file->mmap_base = mmap(NULL, file->mmap_size, PROT_READ,
				       MAP_SHARED, file->fd, 0);
		if (file->mmap_base == MAP_FAILED) {
			file->mmap_base = NULL;
			mail_index_file_set_syscall_error(index, file->filepath,
							  "mmap()");
			return -1;
		}

		if (file->mmap_size > mmap_get_page_size()) {
			if (madvise(file->mmap_base, file->mmap_size,
				    MADV_SEQUENTIAL) < 0) {
				mail_index_file_set_syscall_error(index,
					file->filepath, "madvise()");
			}
		}

		file->buffer = buffer_create_const_data(default_pool,
							file->mmap_base,
							file->mmap_size);
		file->buffer_offset = 0;

		if (mail_transaction_log_file_sync(file) < 0)
			return -1;
	}

	if (end_offset != (uoff_t)-1 && end_offset > file->sync_offset) {
		mail_transaction_log_file_set_corrupted(file,
			"end_offset (%"PRIuUOFF_T") > current sync_offset "
			"(%"PRIuSIZE_T")", end_offset, file->sync_offset);
		return -1;
	}

	return 1;
}

static int mail_transaction_log_lock_head(struct mail_transaction_log *log)
{
	struct mail_transaction_log_file *file;
	int ret = 0;

	/* we want to get the head file locked. this is a bit racy,
	   since by the time we have it locked a new log file may have been
	   created.

	   creating new log file requires locking the head file, so if we
	   can lock it and don't see another file, we can be sure no-one is
	   creating a new log at the moment */

	for (;;) {
		file = log->head;
		if (mail_transaction_log_file_lock(file) < 0)
			return -1;

		file->refcount++;
		ret = mail_transaction_log_refresh(log);
		if (--file->refcount == 0) {
			mail_transaction_logs_clean(log);
			file = NULL;
		}

		if (ret == 0 && log->head == file) {
			/* success */
			break;
		}

		if (file != NULL)
			mail_transaction_log_file_unlock(file);

		if (ret < 0)
			break;

		/* try again */
	}

	return ret;
}

static int log_append_buffer(struct mail_transaction_log_file *file,
			     const buffer_t *buf, const buffer_t *hdr_buf,
			     enum mail_transaction_type type, int external)
{
	struct mail_transaction_header hdr;
	const void *data, *hdr_data;
	size_t size, hdr_data_size;
	uint32_t hdr_size;

	i_assert((type & MAIL_TRANSACTION_TYPE_MASK) != 0);

	data = buffer_get_data(buf, &size);
	if (size == 0)
		return 0;

	i_assert((size % 4) == 0);

	if (hdr_buf != NULL) {
		hdr_data = buffer_get_data(hdr_buf, &hdr_data_size);
		i_assert((hdr_data_size % 4) == 0);
	} else {
		hdr_data = NULL;
		hdr_data_size = 0;
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.type = type;
	if (type == MAIL_TRANSACTION_EXPUNGE)
		hdr.type |= MAIL_TRANSACTION_EXPUNGE_PROT;
	if (external)
		hdr.type |= MAIL_TRANSACTION_EXTERNAL;

	hdr_size =
		mail_index_uint32_to_offset(sizeof(hdr) + size + hdr_data_size);
	if (file->first_append_size == 0) {
		/* size will be written later once everything is in disk */
		file->first_append_size = hdr_size;
	} else {
		hdr.size = hdr_size;
	}

	if (pwrite_full(file->fd, &hdr, sizeof(hdr), file->sync_offset) < 0)
		return -1;
	file->sync_offset += sizeof(hdr);

	if (hdr_data_size > 0) {
		if (pwrite_full(file->fd, hdr_data, hdr_data_size,
				file->sync_offset) < 0)
			return -1;
		file->sync_offset += hdr_data_size;
	}

	if (pwrite_full(file->fd, data, size, file->sync_offset) < 0)
		return -1;
	file->sync_offset += size;
	return 0;
}

static const buffer_t *
log_get_hdr_update_buffer(struct mail_index_transaction *t)
{
	buffer_t *buf;
	struct mail_transaction_header_update u;
	uint16_t offset;
	int state = 0;

	memset(&u, 0, sizeof(u));

	buf = buffer_create_dynamic(pool_datastack_create(), 256);
	for (offset = 0; offset <= sizeof(t->hdr_change); offset++) {
		if (offset < sizeof(t->hdr_change) && t->hdr_mask[offset]) {
			if (state == 0) {
				u.offset = offset;
				state++;
			}
		} else {
			if (state > 0) {
				u.size = offset - u.offset;
				buffer_append(buf, &u, sizeof(uint16_t)*2);
				buffer_append(buf, t->hdr_change + u.offset,
					      u.size);
				state = 0;
			}
		}
	}
	return buf;
}

static int log_append_ext_intro(struct mail_transaction_log_file *file,
				struct mail_index_transaction *t,
				uint32_t ext_id, uint32_t reset_id)
{
	const struct mail_index_ext *ext;
        struct mail_transaction_ext_intro *intro;
	buffer_t *buf;
	uint32_t idx;
	size_t size;

	if (!mail_index_map_get_ext_idx(t->view->map, ext_id, &idx)) {
		/* new extension */
		idx = (uint32_t)-1;
	}

	ext = t->view->index->extensions->data;
	ext += ext_id;

	if (t->ext_resizes == NULL) {
		intro = NULL;
		size = 0;
	} else {
		intro = buffer_get_modifyable_data(t->ext_resizes, &size);
		size /= sizeof(*intro);
	}

	buf = buffer_create_dynamic(pool_datastack_create(), 128);
	if (ext_id < size && intro[ext_id].name_size != 0) {
		/* we're resizing it */
		intro += ext_id;

		i_assert(intro->ext_id == idx);
		intro->name_size = idx != (uint32_t)-1 ? 0 :
			strlen(ext->name);
		buffer_append(buf, intro, sizeof(*intro));
	} else {
		/* generate a new intro structure */
		intro = buffer_append_space_unsafe(buf, sizeof(*intro));
		intro->ext_id = idx;
		intro->hdr_size = ext->hdr_size;
		intro->record_size = ext->record_size;
		intro->record_align = ext->record_align;
		intro->name_size = idx != (uint32_t)-1 ? 0 :
			strlen(ext->name);
	}
	if (reset_id != 0) {
		/* we're going to reset this extension in this transaction */
		intro->reset_id = reset_id;
	} else if (idx != (uint32_t)-1) {
		/* use the existing reset_id */
		const struct mail_index_ext *map_ext =
			t->view->map->extensions->data;
		map_ext += idx;

		intro->reset_id = map_ext->reset_id;
	} else {
		/* new extension, reset_id defaults to 0 */
	}
	buffer_append(buf, ext->name, intro->name_size);

	if ((buf->used % 4) != 0)
		buffer_append_zero(buf, 4 - (buf->used % 4));

	return log_append_buffer(file, buf, NULL, MAIL_TRANSACTION_EXT_INTRO,
				 t->external);
}

static int
mail_transaction_log_append_ext_intros(struct mail_transaction_log_file *file,
				       struct mail_index_transaction *t)
{
        const struct mail_transaction_ext_intro *resize;
	struct mail_transaction_ext_reset ext_reset;
	uint32_t ext_id, ext_count, update_count, resize_count, reset_count;
	const uint32_t *reset;
	const buffer_t *const *update;
	buffer_t *buf;
	size_t size;

	if (t->ext_rec_updates == NULL) {
		update = NULL;
		update_count = 0;
	} else {
		update = buffer_get_data(t->ext_rec_updates, &size);
		update_count = size / sizeof(*update);
	}

	if (t->ext_resizes == NULL) {
		resize = NULL;
		resize_count = 0;
	} else {
		resize = buffer_get_data(t->ext_resizes, &size);
		resize_count = size / sizeof(*resize);
	}

	if (t->ext_resets == NULL) {
		reset = NULL;
		reset_count = 0;
	} else {
		reset = buffer_get_data(t->ext_resets, &size);
		reset_count = size / sizeof(*reset);
	}

	memset(&ext_reset, 0, sizeof(ext_reset));

	buf = buffer_create_data(pool_datastack_create(),
				 &ext_reset, sizeof(ext_reset));
	buffer_set_used_size(buf, sizeof(ext_reset));
	ext_count = I_MAX(I_MAX(update_count, resize_count), reset_count);

	for (ext_id = 0; ext_id < ext_count; ext_id++) {
		ext_reset.new_reset_id =
			ext_id < reset_count && reset[ext_id] != 0 ?
			reset[ext_id] : 0;
		if ((ext_id < resize_count && resize[ext_id].name_size) ||
		    (ext_id < update_count && update[ext_id] != NULL) ||
		    ext_reset.new_reset_id != 0) {
			if (log_append_ext_intro(file, t, ext_id, 0) < 0)
				return -1;
		}
		if (ext_reset.new_reset_id != 0) {
			if (log_append_buffer(file, buf, NULL,
					      MAIL_TRANSACTION_EXT_RESET,
					      t->external) < 0)
				return -1;
		}
	}

	return 0;
}

static int log_append_ext_rec_updates(struct mail_transaction_log_file *file,
				      struct mail_index_transaction *t)
{
	buffer_t **updates;
	const uint32_t *reset;
	uint32_t ext_id, reset_id, reset_count;
	size_t size;

	if (t->ext_rec_updates == NULL) {
		updates = NULL;
		size = 0;
	} else {
		updates = buffer_get_modifyable_data(t->ext_rec_updates, &size);
		size /= sizeof(*updates);
	}

	if (t->ext_resets == NULL) {
		reset = NULL;
		reset_count = 0;
	} else {
		reset = buffer_get_data(t->ext_resets, &size);
		reset_count = size / sizeof(*reset);
	}

	for (ext_id = 0; ext_id < size; ext_id++) {
		if (updates[ext_id] == NULL)
			continue;

		reset_id = ext_id < reset_count && reset[ext_id] != 0 ?
			reset[ext_id] : 0;
		if (log_append_ext_intro(file, t, ext_id, reset_id) < 0)
			return -1;

		if (log_append_buffer(file, updates[ext_id], NULL,
				      MAIL_TRANSACTION_EXT_REC_UPDATE,
				      t->external) < 0)
			return -1;
	}
	return 0;
}

static int log_append_keyword_updates(struct mail_transaction_log_file *file,
				      struct mail_index_transaction *t)
{
	struct mail_index *index = t->view->index;
	struct mail_keyword_transaction **kt;
	struct mail_transaction_keyword_update kt_hdr;
	buffer_t *buf;
	size_t i, size, size_offset, name_offset;
	unsigned int idx, last_idx, first_keyword;

	buf = buffer_create_dynamic(pool_datastack_create(), 128);

	kt = buffer_get_modifyable_data(t->keyword_updates, &size);
	size /= sizeof(*kt);
	for (i = 0; i < size; i++) {
		buffer_set_used_size(buf, 0);

		memset(&kt_hdr, 0, sizeof(kt_hdr));
		kt_hdr.keywords_count = kt[i]->keywords->count;
		kt_hdr.modify_type = kt[i]->modify_type;
		buffer_append(buf, &kt_hdr,
			      sizeof(kt_hdr) - sizeof(kt_hdr.name_size));

		size_offset = buf->used;
		name_offset = buf->used +
			kt[i]->keywords->count * sizeof(uint16_t);

		idx = 0;
		first_keyword = kt[i]->keywords->start;
		last_idx = kt[i]->keywords->end - first_keyword;

		for (; idx <= last_idx; idx++) {
			uint16_t name_size;
			const char *keyword;

			if ((kt[i]->keywords->bitmask[idx / 8] &
			     (1 << (idx % 8))) == 0)
				continue;

			i_assert(first_keyword + idx <
				 index->keywords_buf->used / sizeof(keyword));
			keyword = index->keywords[first_keyword + idx];

			name_size = strlen(keyword);
			buffer_write(buf, size_offset,
				     &name_size, sizeof(name_size));
			size_offset += sizeof(name_size);

			buffer_write(buf, name_offset, keyword, name_size);
			name_offset += name_size;
		}

		if ((buf->used % 4) != 0)
			buffer_append_zero(buf, 4 - (buf->used % 4));
		buffer_append_buf(buf, kt[i]->messages, 0, (size_t)-1);

		if (log_append_buffer(file, buf, NULL,
				      MAIL_TRANSACTION_KEYWORD_UPDATE,
				      t->external) < 0)
			return -1;
	}

	return 0;
}

int mail_transaction_log_append(struct mail_index_transaction *t,
				uint32_t *log_file_seq_r,
				uoff_t *log_file_offset_r)
{
	struct mail_index_view *view = t->view;
	struct mail_index *index;
	struct mail_transaction_log *log;
	struct mail_transaction_log_file *file;
	struct mail_index_header idx_hdr;
	uoff_t append_offset;
	unsigned int lock_id;
	int ret;

	index = mail_index_view_get_index(view);
	log = index->log;

	if (!t->log_updates) {
		/* nothing to append */
		*log_file_seq_r = 0;
		*log_file_offset_r = 0;
		return 0;
	}

	if (log->index->log_locked) {
		i_assert(t->external);
	} else {
		if (mail_transaction_log_lock_head(log) < 0)
			return -1;

		/* update sync_offset */
		if (mail_transaction_log_file_map(log->head,
						  log->head->sync_offset,
						  (uoff_t)-1) < 0) {
			mail_transaction_log_file_unlock(log->head);
			return -1;
		}
	}

	if (log->head->sync_offset > MAIL_TRANSACTION_LOG_ROTATE_SIZE &&
	    log->head->last_mtime <
	    ioloop_time - MAIL_TRANSACTION_LOG_ROTATE_MIN_TIME) {
		/* we might want to rotate, but check first that everything is
		   synced in index. */
		if (mail_index_lock_shared(log->index, TRUE, &lock_id) < 0) {
			if (!log->index->log_locked)
				mail_transaction_log_file_unlock(log->head);
			return -1;
		}
		idx_hdr = *log->index->hdr;
		mail_index_unlock(log->index, lock_id);

		if (log->head->hdr.file_seq == idx_hdr.log_file_seq &&
		    log->head->sync_offset == idx_hdr.log_file_int_offset &&
		    log->head->sync_offset == idx_hdr.log_file_ext_offset) {
			if (mail_transaction_log_rotate(log, TRUE) < 0) {
				/* that didn't work. well, try to continue
				   anyway */
			}
		}
	}

	file = log->head;
	file->first_append_size = 0;
	append_offset = file->sync_offset;

	ret = 0;

	/* send all extension introductions and resizes before appends
	   to avoid resize overhead as much as possible */
        ret = mail_transaction_log_append_ext_intros(file, t);

	if (t->appends != NULL && ret == 0) {
		ret = log_append_buffer(file, t->appends, NULL,
					MAIL_TRANSACTION_APPEND, t->external);
	}
	if (t->updates != NULL && ret == 0) {
		ret = log_append_buffer(file, t->updates, NULL,
					MAIL_TRANSACTION_FLAG_UPDATE,
					t->external);
	}

	if (t->ext_rec_updates != NULL && ret == 0)
		ret = log_append_ext_rec_updates(file, t);

	if (t->keyword_updates != NULL && ret == 0)
		ret = log_append_keyword_updates(file, t);

	if (t->expunges != NULL && ret == 0) {
		ret = log_append_buffer(file, t->expunges, NULL,
					MAIL_TRANSACTION_EXPUNGE, t->external);
	}
	if (t->hdr_changed && ret == 0) {
		ret = log_append_buffer(file, log_get_hdr_update_buffer(t),
					NULL, MAIL_TRANSACTION_HEADER_UPDATE,
					t->external);
	}

	if (ret < 0) {
		mail_index_file_set_syscall_error(log->index, file->filepath,
						  "pwrite()");
	}

	if (ret == 0 && (t->updates != NULL || t->appends != NULL) &&
	    t->hide_transaction) {
		mail_index_view_add_synced_transaction(view, file->hdr.file_seq,
						       append_offset);
	}

	if (ret == 0 && fsync(file->fd) < 0) {
		/* we don't know how much of it got written,
		   it may be corrupted now.. */
		mail_index_file_set_syscall_error(log->index, file->filepath,
						  "fsync()");
		ret = -1;
	}

	if (ret == 0 && file->first_append_size != 0) {
		/* synced - rewrite first record's header */
		ret = pwrite_full(file->fd, &file->first_append_size,
				  sizeof(uint32_t), append_offset);
		if (ret < 0) {
			mail_index_file_set_syscall_error(log->index,
							  file->filepath,
							  "pwrite()");
		}
	}

	if (ret < 0)
		file->sync_offset = append_offset;

	*log_file_seq_r = file->hdr.file_seq;
	*log_file_offset_r = file->sync_offset;

	if (!log->index->log_locked)
		mail_transaction_log_file_unlock(file);
	return ret;
}

int mail_transaction_log_sync_lock(struct mail_transaction_log *log,
				   uint32_t *file_seq_r, uoff_t *file_offset_r)
{
	i_assert(!log->index->log_locked);

	if (mail_transaction_log_lock_head(log) < 0)
		return -1;

	/* update sync_offset */
	if (mail_transaction_log_file_map(log->head, log->head->sync_offset,
					  (uoff_t)-1) < 0) {
		mail_transaction_log_file_unlock(log->head);
		return -1;
	}

	log->index->log_locked = TRUE;
	*file_seq_r = log->head->hdr.file_seq;
	*file_offset_r = log->head->sync_offset;
	return 0;
}

void mail_transaction_log_sync_unlock(struct mail_transaction_log *log)
{
	i_assert(log->index->log_locked);

	log->index->log_locked = FALSE;
	mail_transaction_log_file_unlock(log->head);
}

void mail_transaction_log_get_head(struct mail_transaction_log *log,
				   uint32_t *file_seq_r, uoff_t *file_offset_r)
{
	i_assert(log->index->log_locked);

	*file_seq_r = log->head->hdr.file_seq;
	*file_offset_r = log->head->sync_offset;
}
