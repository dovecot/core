/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "buffer.h"
#include "file-lock.h"
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

struct mail_transaction_add_ctx {
	struct mail_transaction_log *log;
	struct mail_index_view *view;

	buffer_t *appends, *expunges;
	buffer_t *flag_updates, *cache_updates;
};

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

	if (file->log->index->fcntl_locks_disable)
		return mail_transaction_log_file_dotlock(file);

	ret = file_wait_lock_full(file->fd, F_WRLCK, DEFAULT_LOCK_TIMEOUT,
				  NULL, NULL);
	if (ret > 0) {
		file->locked = TRUE;
		return 0;
	}
	if (ret < 0) {
		mail_index_file_set_syscall_error(file->log->index,
						  file->filepath,
						  "file_wait_lock()");
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

	if (file->log->index->fcntl_locks_disable) {
		mail_transaction_log_file_undotlock(file);
		return;
	}

	ret = file_wait_lock(file->fd, F_UNLCK);
	if (ret <= 0) {
		mail_index_file_set_syscall_error(file->log->index,
						  file->filepath,
						  "file_wait_lock()");
	}
}

#define INDEX_HAS_MISSING_LOGS(index, file) \
	!(((file)->hdr.file_seq == (index)->hdr->log_file_seq && \
	   (index)->hdr->log_file_offset >= \
	   sizeof(struct mail_transaction_log_header)) || \
	  ((file)->hdr.prev_file_seq == (index)->hdr->log_file_seq && \
	   (file)->hdr.prev_file_offset == (index)->hdr->log_file_offset))

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
			ret = mail_transaction_log_rotate(log, F_UNLCK);
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
		hdr.prev_file_offset = index->hdr->log_file_offset;
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
	int fd, fd2;

	/* With dotlocking we might already have path.lock created, so this
	   filename has to be different. */
	fd = file_dotlock_open(path, NULL, LOG_NEW_DOTLOCK_SUFFIX,
			       LOG_DOTLOCK_TIMEOUT,
			       LOG_DOTLOCK_STALE_TIMEOUT,
			       LOG_DOTLOCK_IMMEDIATE_STALE_TIMEOUT, NULL, NULL);
	if (fd == -1) {
		mail_index_file_set_syscall_error(log->index, path,
						  "file_dotlock_open()");
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
	    file->hdr.file_seq == log->index->map->log_file_seq &&
	    log->index->map->log_file_offset != 0) {
		/* we can get a valid log offset from index file. initialize
		   sync_offset from it so we don't have to read the whole log
		   file from beginning. */
		file->sync_offset = log->index->map->log_file_offset;
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
		file->buffer = buffer_create_dynamic(default_pool,
						     LOG_PREFETCH, (size_t)-1);
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

		if (mail_transaction_log_file_sync(file) < 0)
			return -1;
	} while (ret > 0 || (ret < 0 && errno == EINTR));

	if (ret == 0) {
		/* EOF */
		buffer_set_used_size(file->buffer,
				     file->sync_offset - file->buffer_offset);
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
	    file->buffer_offset <= start_offset) {
		/* it's all mmaped already */
		i_assert(end_offset == (uoff_t)-1);
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

static void
mail_transaction_log_append_fix(struct mail_index_transaction *t,
				const struct mail_transaction_header *hdr,
				const void *data)
{
	const struct mail_index_record *old, *old_end;
	struct mail_index_record *appends, *end, *rec, *dest;
	size_t size;
	int deleted = FALSE;

	if (t->appends == NULL)
		return;

	appends = buffer_get_modifyable_data(t->appends, &size);
	end = PTR_OFFSET(appends, size);

	if (appends == end)
		return;

	/* we'll just check that none of the appends are already in
	   transaction log. this could happen if we crashed before we had
	   a chance to update index file */
	old_end = CONST_PTR_OFFSET(data, hdr->size);
	for (old = data; old != old_end; old++) {
		/* appends are sorted */
		for (rec = appends; rec != end; rec++) {
			if (rec->uid >= old->uid) {
				if (rec->uid == old->uid) {
					rec->uid = 0;
					deleted = TRUE;
				}
				break;
			}
		}
	}

	if (deleted) {
		/* compress deleted appends away */
		for (rec = dest = appends; rec != end; rec++) {
			if (rec->uid != 0)
				dest++;
			else if (rec != dest)
				*rec = *dest;
		}
		buffer_set_used_size(t->appends,
				     (char *)dest - (char *)appends);
	}
}

static void
transaction_save_ext_intro(struct mail_index_transaction *t,
			   const struct mail_transaction_ext_intro *intro)
{
	const char *name;
	void *p;
	uint32_t ext_id;
	size_t pos;

	if (t->ext_intros == NULL) {
		t->ext_intros = buffer_create_dynamic(default_pool,
						      128, (size_t)-1);
	}

	t_push();
	name = t_strndup((const char *)(intro+1), intro->name_size);
	ext_id = mail_index_ext_register(t->view->index, name,
					 intro->hdr_size, intro->record_size);
	pos = ext_id * sizeof(intro->ext_id);
	if (pos > t->ext_intros->used) {
		/* unused records are -1 */
		p = buffer_append_space_unsafe(t->ext_intros,
					       pos - t->ext_intros->used);
		memset(p, 0xff, pos - t->ext_intros->used);
	}

	buffer_write(t->ext_intros, pos,
		     &intro->ext_id, sizeof(intro->ext_id));
	if (intro->ext_id > t->ext_intros_max_id)
		t->ext_intros_max_id = intro->ext_id;
	t_pop();
}

static int mail_transaction_log_scan_pending(struct mail_transaction_log *log,
					     struct mail_index_transaction *t)
{
	struct mail_transaction_log_view *sync_view;
	const struct mail_transaction_header *hdr;
	const void *data;
	uint32_t max_cache_file_seq = 0;
	int ret;

	sync_view = mail_transaction_log_view_open(log);
	ret = mail_transaction_log_view_set(sync_view, t->view->log_file_seq,
					    t->view->log_file_offset,
					    log->head->hdr.file_seq, (uoff_t)-1,
					    MAIL_TRANSACTION_TYPE_MASK);
	while ((ret = mail_transaction_log_view_next(sync_view,
						     &hdr, &data, NULL)) == 1) {
		switch (hdr->type & MAIL_TRANSACTION_TYPE_MASK) {
		case MAIL_TRANSACTION_APPEND:
			mail_transaction_log_append_fix(t, hdr, data);
			break;
		case MAIL_TRANSACTION_CACHE_RESET: {
			const struct mail_transaction_cache_reset *reset = data;

			max_cache_file_seq = reset->new_file_seq;
			break;
		}
		case MAIL_TRANSACTION_EXT_INTRO: {
			const struct mail_transaction_ext_intro *intro = data;

			transaction_save_ext_intro(t, intro);
			break;
		}
		}
	}

	/* make sure we're not writing cache_offsets to old cache file */
	if (t->new_cache_file_seq == 0 && max_cache_file_seq != 0 &&
	    max_cache_file_seq != t->last_cache_file_seq &&
	    t->cache_updates != NULL) {
		buffer_free(t->cache_updates);
		t->cache_updates = NULL;

		if (t->appends != NULL) {
			struct mail_index_record *rec;
			size_t i, size;

			rec = buffer_get_modifyable_data(t->appends, &size);
			size /= sizeof(*rec);

			for (i = 0; i < size; i++)
				rec[i].cache_offset = 0;
		}
	}

	mail_transaction_log_view_close(sync_view);
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

static const buffer_t *get_cache_reset_buf(struct mail_index_transaction *t)
{
	struct mail_transaction_cache_reset u;
	buffer_t *buf;

	memset(&u, 0, sizeof(u));
	u.new_file_seq = t->new_cache_file_seq;

	buf = buffer_create_static(pool_datastack_create(), sizeof(u));
	buffer_append(buf, &u, sizeof(u));
	return buf;
}

static const buffer_t *
log_get_hdr_update_buffer(struct mail_index_transaction *t)
{
	buffer_t *buf;
	struct mail_transaction_header_update u;
	uint16_t offset;
	int state = 0;

	memset(&u, 0, sizeof(u));

	buf = buffer_create_dynamic(pool_datastack_create(), 256, (size_t)-1);
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

static int
mail_transaction_log_register_ext(struct mail_transaction_log_file *file,
				  struct mail_index_transaction *t,
				  uint32_t ext_id, uint32_t *idx_r)
{
	const struct mail_index_ext *ext;
	struct mail_transaction_ext_intro *intro;
	const uint32_t *id_map;
	buffer_t *buf;
	size_t size;
	int ret;

	/* first check if it's already in nonsynced part of transaction log */
	if (t->ext_intros != NULL) {
		id_map = buffer_get_data(t->ext_intros, &size);
		size /= sizeof(*id_map);

		if (ext_id < size && id_map[ext_id] != (uint32_t)-1) {
			*idx_r = id_map[ext_id];
			return 0;
		}
	}
	*idx_r = t->ext_intros_max_id++;

	ext = t->view->index->extensions->data;
	ext += ext_id;

	/* nope, register */
	t_push();
	buf = buffer_create_dynamic(pool_datastack_create(), 128, (size_t)-1);
	intro = buffer_append_space_unsafe(buf, sizeof(*intro));
	intro->ext_id = *idx_r;
	intro->hdr_size = ext->hdr_size;
	intro->record_size = ext->record_size;
	intro->name_size = strlen(ext->name);
	buffer_append(buf, ext->name, intro->name_size);

	if ((buf->used % 4) != 0)
		buffer_append(buf, null4, 4 - (buf->used % 4));

	ret = log_append_buffer(file, buf, NULL, MAIL_TRANSACTION_EXT_INTRO,
				t->view->external);
	t_pop();
	return ret;
}

int mail_transaction_log_append(struct mail_index_transaction *t,
				uint32_t *log_file_seq_r,
				uoff_t *log_file_offset_r)
{
	struct mail_transaction_ext_rec_header ext_rec_hdr;
	struct mail_index_view *view = t->view;
	struct mail_index *index;
	struct mail_transaction_log *log;
	struct mail_transaction_log_file *file;
	struct mail_index_header idx_hdr;
	uoff_t append_offset;
	buffer_t *hdr_buf, **updates;
	unsigned int i, lock_id;
	uint32_t idx;
	size_t size;
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
		i_assert(view->external);
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

	if (mail_index_lock_shared(log->index, TRUE, &lock_id) < 0) {
		if (!log->index->log_locked)
			mail_transaction_log_file_unlock(log->head);
		return -1;
	}
	idx_hdr = *log->index->hdr;
	mail_index_unlock(log->index, lock_id);

	if (log->head->sync_offset > MAIL_TRANSACTION_LOG_ROTATE_SIZE &&
	    log->head->last_mtime <
	    ioloop_time - MAIL_TRANSACTION_LOG_ROTATE_MIN_TIME) {
		/* we might want to rotate, but check first that everything is
		   synced in index. */
		if (log->head->hdr.file_seq == idx_hdr.log_file_seq &&
		    log->head->sync_offset == idx_hdr.log_file_offset) {
			if (mail_transaction_log_rotate(log, TRUE) < 0) {
				/* that didn't work. well, try to continue
				   anyway */
			}
		}
	}

	file = log->head;
	file->first_append_size = 0;
	append_offset = file->sync_offset;

	if (t->cache_updates != NULL &&
	    t->last_cache_file_seq < idx_hdr.cache_file_seq) {
		/* cache_offsets point to old file, don't allow */
		buffer_free(t->cache_updates);
		t->cache_updates = NULL;
	}

	t->ext_intros_max_id = t->view->index->map->extensions == NULL ? 0 :
		(t->view->index->map->extensions->used /
		 sizeof(struct mail_index_ext));

	if (t->appends != NULL ||
	    (t->cache_updates != NULL && t->new_cache_file_seq == 0) ||
	    (t->ext_rec_updates != NULL && t->ext_rec_updates->used > 0)) {
		if (mail_transaction_log_scan_pending(log, t) < 0) {
			if (!log->index->log_locked)
				mail_transaction_log_file_unlock(file);
			return -1;
		}
	}

	ret = 0;
	if (t->appends != NULL) {
		ret = log_append_buffer(file, t->appends, NULL,
					MAIL_TRANSACTION_APPEND,
					view->external);
	}
	if (t->updates != NULL && ret == 0) {
		ret = log_append_buffer(file, t->updates, NULL,
					MAIL_TRANSACTION_FLAG_UPDATE,
					view->external);
	}
	if (t->new_cache_file_seq != 0) {
		ret = log_append_buffer(file, get_cache_reset_buf(t), NULL,
					MAIL_TRANSACTION_CACHE_RESET,
					view->external);
	}
	if (t->cache_updates != NULL && ret == 0) {
		ret = log_append_buffer(file, t->cache_updates, NULL,
					MAIL_TRANSACTION_CACHE_UPDATE,
					view->external);
	}

	if (t->ext_rec_updates == NULL) {
		updates = NULL;
		size = 0;
	} else {
		updates = buffer_get_modifyable_data(t->ext_rec_updates, &size);
		size /= sizeof(*updates);
	}

	hdr_buf = buffer_create_data(pool_datastack_create(),
				     &ext_rec_hdr, sizeof(ext_rec_hdr));
	buffer_set_used_size(hdr_buf, sizeof(ext_rec_hdr));
	for (i = 0; i < size && ret == 0; i++) {
		if (updates[i] == NULL)
			continue;

		if (!mail_index_map_get_ext_idx(index->map, i, &idx)) {
			/* new one */
			ret = mail_transaction_log_register_ext(file, t, i,
								&idx);
			if (ret < 0)
				break;
		}

		ext_rec_hdr.ext_id = idx;
		ret = log_append_buffer(file, updates[i], hdr_buf,
					MAIL_TRANSACTION_EXT_REC_UPDATE,
					view->external);
	}

	if (t->expunges != NULL && ret == 0) {
		ret = log_append_buffer(file, t->expunges, NULL,
					MAIL_TRANSACTION_EXPUNGE,
					view->external);
	}
	if (t->hdr_changed && ret == 0) {
		ret = log_append_buffer(file, log_get_hdr_update_buffer(t),
					NULL, MAIL_TRANSACTION_HEADER_UPDATE,
					view->external);
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
