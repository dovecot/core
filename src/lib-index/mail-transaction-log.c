/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
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

/* this lock should never exist for a long time.. */
#define LOG_DOTLOCK_TIMEOUT 30
#define LOG_DOTLOCK_STALE_TIMEOUT 0
#define LOG_DOTLOCK_IMMEDIATE_STALE_TIMEOUT 120

struct mail_transaction_add_ctx {
	struct mail_transaction_log *log;
	struct mail_index_view *view;

	buffer_t *appends, *expunges;
	buffer_t *flag_updates, *cache_updates;
};

static struct mail_transaction_log_file *
mail_transaction_log_file_open_or_create(struct mail_transaction_log *log,
					 const char *path);
static int mail_transaction_log_rotate(struct mail_transaction_log *log);

static int
mail_transaction_log_file_lock(struct mail_transaction_log_file *file,
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
			ret = mail_transaction_log_rotate(log);
		}
	}

	if (--file->refcount == 0)
		mail_transaction_logs_clean(log);
	else
		(void)mail_transaction_log_file_lock(file, F_UNLCK);
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

	log->index->log = NULL;
	i_free(log);
}

static int
mail_transaction_log_file_dotlock(struct mail_transaction_log_file *file,
				  int lock_type)
{
	int ret;

	if (lock_type == F_UNLCK) {
		ret = file_unlock_dotlock(file->filepath, &file->dotlock);
		if (ret < 0) {
			mail_index_file_set_syscall_error(file->log->index,
				file->filepath, "file_unlock_dotlock()");
			return -1;
		}
		file->lock_type = F_UNLCK;

		if (ret == 0) {
			mail_index_set_error(file->log->index,
				"Dotlock was lost for transaction log file %s",
				file->filepath);
			return -1;
		}
		return 0;
	}

	ret = file_lock_dotlock(file->filepath, NULL, FALSE,
				LOG_DOTLOCK_TIMEOUT,
				LOG_DOTLOCK_STALE_TIMEOUT,
				LOG_DOTLOCK_IMMEDIATE_STALE_TIMEOUT,
				NULL, NULL, &file->dotlock);
	if (ret > 0) {
		file->lock_type = F_WRLCK;
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
mail_transaction_log_file_lock(struct mail_transaction_log_file *file,
			       int lock_type)
{
	int ret;

	if (lock_type == F_UNLCK) {
		i_assert(file->lock_type != F_UNLCK);
	} else {
		i_assert(file->lock_type == F_UNLCK);
	}

	if (file->log->index->fcntl_locks_disable)
		return mail_transaction_log_file_dotlock(file, lock_type);

	ret = file_wait_lock_full(file->fd, lock_type, DEFAULT_LOCK_TIMEOUT,
				  NULL, NULL);
	if (ret > 0) {
		file->lock_type = lock_type;
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
			     "%s fcntl() lock for transaction log file %s",
			     lock_type == F_WRLCK ? "exclusive" : "shared",
			     file->filepath);
	file->log->index->index_lock_timeout = TRUE;
	return -1;
}

static void
mail_transaction_log_file_close(struct mail_transaction_log_file *file)
{
	if (close(file->fd) < 0) {
		mail_index_file_set_syscall_error(file->log->index,
						  file->filepath, "close()");
	}

	i_free(file->filepath);
	i_free(file);
}

static int
mail_transaction_log_file_read_hdr(struct mail_transaction_log_file *file,
				   struct stat *st)
{
	int ret;
	uint32_t old_size = file->hdr.used_size;

	if (file->lock_type != F_UNLCK)
		ret = pread_full(file->fd, &file->hdr, sizeof(file->hdr), 0);
	else {
		if (mail_transaction_log_file_lock(file, F_RDLCK) < 0)
			return -1;
		ret = pread_full(file->fd, &file->hdr, sizeof(file->hdr), 0);
		(void)mail_transaction_log_file_lock(file, F_UNLCK);
	}

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
	if (file->hdr.indexid != file->log->index->indexid &&
	    file->log->index->indexid != 0) {
		/* either index was just recreated, or transaction has wrong
		   indexid. we don't know here which one is the case, so we'll
		   just fail. If index->indexid == 0, we're rebuilding it and
		   we just want to lock the transaction log. */
		mail_index_set_error(file->log->index,
			"Transaction log file %s: invalid indexid",
			file->filepath);
		return 0;
	}
	if (file->hdr.used_size > st->st_size) {
		mail_transaction_log_file_set_corrupted(file,
			"used_size (%u) > file size (%"PRIuUOFF_T")",
			file->hdr.used_size, (uoff_t)st->st_size);
		return 0;
	}
	if (file->hdr.used_size < old_size) {
		mail_transaction_log_file_set_corrupted(file,
			"used_size (%u) < old_size (%u)",
			file->hdr.used_size, old_size);
		return 0;
	}

	return 1;
}

static int
mail_transaction_log_file_create(struct mail_transaction_log *log,
				 const char *path, dev_t dev, ino_t ino)
{
	struct mail_index *index = log->index;
	struct mail_transaction_log_header hdr;
	struct stat st;
	int fd, fd2, ret;

	fd = file_dotlock_open(path, NULL, LOG_DOTLOCK_TIMEOUT,
			       LOG_DOTLOCK_STALE_TIMEOUT,
			       LOG_DOTLOCK_IMMEDIATE_STALE_TIMEOUT, NULL, NULL);
	if (fd == -1) {
		mail_index_file_set_syscall_error(index, path,
						  "file_dotlock_open()");
		return -1;
	}

	/* log creation is locked now - see if someone already created it */
	fd2 = open(path, O_RDWR);
	if (fd2 != -1) {
		if ((ret = fstat(fd2, &st)) < 0) {
			mail_index_file_set_syscall_error(index, path,
							  "fstat()");
		} else if (st.st_dev == dev && st.st_ino == ino) {
			/* same file, still broken */
		} else {
			(void)file_dotlock_delete(path, fd2);
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
	hdr.used_size = sizeof(hdr);

	if (index->fd != -1) {
		hdr.prev_file_seq = index->hdr->log_file_seq;
		hdr.prev_file_offset = index->hdr->log_file_offset;
	}
	hdr.file_seq = index->hdr->log_file_seq+1;

	if (log->head != NULL && hdr.file_seq <= log->head->hdr.file_seq) {
		/* make sure the sequence grows */
		hdr.file_seq = log->head->hdr.file_seq+1;
	}

	if (write_full(fd, &hdr, sizeof(hdr)) < 0) {
		mail_index_file_set_syscall_error(index, path, "write_full()");
                (void)file_dotlock_delete(path, fd);
		return -1;
	}

	fd2 = dup(fd);
	if (fd2 < 0) {
		mail_index_file_set_syscall_error(index, path, "dup()");
                (void)file_dotlock_delete(path, fd);
		return -1;
	}

	if (file_dotlock_replace(path, fd, FALSE) <= 0)
		return -1;

	/* success */
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
		mail_index_file_set_syscall_error(log->index, path, "stat()");
		return NULL;
	}

	file = i_new(struct mail_transaction_log_file, 1);
	file->refcount = 1;
	file->log = log;
	file->filepath = i_strdup(path);
	file->fd = fd;
	file->lock_type = F_UNLCK;
	file->st_dev = st.st_dev;
	file->st_ino = st.st_ino;

	ret = mail_transaction_log_file_read_hdr(file, &st);
	if (ret == 0) {
		/* corrupted header */
		fd = mail_transaction_log_file_create(log, path,
						      st.st_dev, st.st_ino);
		if (fstat(fd, &st) < 0) {
			mail_index_file_set_syscall_error(log->index, path,
							  "stat()");
			(void)close(fd);
			fd = -1;
			ret = -1;
		}

		if (fd != -1) {
			(void)close(file->fd);
			file->fd = fd;

			file->st_dev = st.st_dev;
			file->st_ino = st.st_ino;

			memset(&file->hdr, 0, sizeof(file->hdr));
			ret = mail_transaction_log_file_read_hdr(file, &st);
		}
	}
	if (ret <= 0) {
		mail_transaction_log_file_close(file);
		return NULL;
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

static int mail_transaction_log_rotate(struct mail_transaction_log *log)
{
	struct mail_transaction_log_file *file;
	struct stat st;
	int fd, lock_type;

	if (fstat(log->head->fd, &st) < 0) {
		mail_index_file_set_syscall_error(log->index,
						  log->head->filepath,
						  "fstat()");
		return -1;
	}

	fd = mail_transaction_log_file_create(log, log->head->filepath,
					      st.st_dev, st.st_ino);
	if (fd == -1)
		return 0;

	file = mail_transaction_log_file_fd_open(log, log->head->filepath, fd);
	if (file == NULL)
		return -1;

	lock_type = log->head->lock_type;
	if (lock_type != F_UNLCK) {
		if (mail_transaction_log_file_lock(file, lock_type) < 0)
			return -1;
	}

	if (--log->head->refcount == 0)
		mail_transaction_logs_clean(log);
	else
		(void)mail_transaction_log_file_lock(log->head, F_UNLCK);

	log->head = file;
	return 0;
}

static int mail_transaction_log_recreate(struct mail_transaction_log *log)
{
	unsigned int lock_id;
	int ret;

	if (mail_index_lock_shared(log->index, TRUE, &lock_id) < 0)
		return -1;

	ret = mail_transaction_log_rotate(log);
	mail_index_unlock(log->index, lock_id);

	if (ret == 0) {
		if (mail_transaction_log_file_lock(log->head, F_UNLCK) < 0)
			return -1;
	}
	return ret;
}

static int mail_transaction_log_refresh(struct mail_transaction_log *log)
{
        struct mail_transaction_log_file *file;
	struct stat st;
	const char *path;
	int ret;

	path = t_strconcat(log->index->filepath,
			   MAIL_TRANSACTION_LOG_PREFIX, NULL);
	if (stat(path, &st) < 0) {
		mail_index_file_set_syscall_error(log->index, path, "stat()");
		if (errno == ENOENT && log->head->lock_type == F_WRLCK) {
			/* lost? */
			return mail_transaction_log_recreate(log);
		}
		return -1;
	}

	if (log->head != NULL &&
	    log->head->st_ino == st.st_ino &&
	    log->head->st_dev == st.st_dev) {
		/* same file */
		ret = mail_transaction_log_file_read_hdr(log->head, &st);
		if (ret == 0 && log->head->lock_type == F_WRLCK) {
			/* corrupted, recreate */
			return mail_transaction_log_recreate(log);
		}
		return ret <= 0 ? -1 : 0;
	}

	file = mail_transaction_log_file_open_or_create(log, path);
	if (file == NULL)
		return -1;

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
mail_transaction_log_file_read(struct mail_transaction_log_file *file,
			       uoff_t offset)
{
	void *data;
	size_t size;
	int ret;

	i_assert(file->mmap_base == NULL);
	i_assert(offset <= file->hdr.used_size);

	if (file->buffer != NULL && file->buffer_offset > offset) {
		/* we have to insert missing data to beginning of buffer */
		size = file->buffer_offset - offset;
		buffer_copy(file->buffer, size, file->buffer, 0, (size_t)-1);
		file->buffer_offset = offset;

		data = buffer_get_space_unsafe(file->buffer, 0, size);
		ret = pread_full(file->fd, data, size, offset);
		if (ret < 0 && errno == ESTALE) {
			/* log file was deleted in NFS server, fail silently */
			ret = 0;
		}
		if (ret <= 0)
			return ret;
	}

	if (file->buffer == NULL) {
		size = file->hdr.used_size - offset;
		file->buffer = buffer_create_dynamic(default_pool,
						     size, (size_t)-1);
		file->buffer_offset = offset;
		size = 0;
	} else {
		size = buffer_get_used_size(file->buffer);
		if (file->buffer_offset + size >= file->hdr.used_size) {
			/* caller should have checked this.. */
			return 1;
		}
	}
	offset = file->buffer_offset + size;

	size = file->hdr.used_size - file->buffer_offset - size;
	if (size == 0)
		return 1;

	data = buffer_append_space_unsafe(file->buffer, size);

	ret = pread_full(file->fd, data, size, offset);
	if (ret < 0 && errno == ESTALE) {
		/* log file was deleted in NFS server, fail silently */
		ret = 0;
	}
	return ret;
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

	if (fstat(file->fd, &st) < 0) {
		mail_index_file_set_syscall_error(index, file->filepath,
						  "fstat()");
		return -1;
	}

	if (st.st_size == file->hdr.used_size &&
	    file->buffer_offset <= start_offset && end_offset == (uoff_t)-1) {
		/* we've seen the whole file.. do we have all of it mapped? */
		size = file->buffer == NULL ? 0 :
			buffer_get_used_size(file->buffer);
		if (file->buffer_offset + size == file->hdr.used_size)
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

	if (mail_transaction_log_file_read_hdr(file, &st) <= 0)
		return -1;

	if (end_offset == (uoff_t)-1)
		end_offset = file->hdr.used_size;

	if (start_offset < sizeof(file->hdr)) {
		mail_transaction_log_file_set_corrupted(file,
			"offset (%"PRIuUOFF_T") < header size (%"PRIuSIZE_T")",
			start_offset, sizeof(file->hdr));
		return -1;
	}
	if (end_offset > file->hdr.used_size) {
		mail_transaction_log_file_set_corrupted(file,
			"offset (%"PRIuUOFF_T") > used_size (%u)",
			end_offset, file->hdr.used_size);
		return -1;
	}

	if (!use_mmap) {
		ret = mail_transaction_log_file_read(file, start_offset);
		if (ret <= 0) {
			if (ret < 0) {
				mail_index_file_set_syscall_error(index,
					file->filepath, "pread_full()");
 			} else {
				mail_transaction_log_file_set_corrupted(file,
					"Unexpected EOF");
			}

			/* make sure we don't leave ourself in
			   inconsistent state */
			if (file->buffer != NULL) {
				buffer_free(file->buffer);
				file->buffer = NULL;
			}
		}
		return ret;
	}

	file->mmap_size = file->hdr.used_size;
	file->mmap_base = mmap(NULL, file->mmap_size, PROT_READ,
			       MAP_SHARED, file->fd, 0);
	if (file->mmap_base == MAP_FAILED) {
		file->mmap_base = NULL;
		mail_index_file_set_syscall_error(index, file->filepath,
						  "mmap()");
		return -1;
	}
	file->buffer = buffer_create_const_data(default_pool, file->mmap_base,
						file->mmap_size);
	file->buffer_offset = 0;
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
		if (mail_transaction_log_file_lock(file, F_WRLCK) < 0)
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

		if (file != NULL) {
			if (mail_transaction_log_file_lock(file, F_UNLCK) < 0)
				return -1;
		}

		if (ret < 0)
			break;

		/* try again */
	}

	return ret;
}

static int get_expunge_buf(struct mail_transaction_log *log,
			   struct mail_index_view *view, buffer_t *expunges)
{
	struct mail_transaction_log_view *sync_view;
	const struct mail_transaction_header *hdr;
	const void *data;
	int ret;

	sync_view = mail_transaction_log_view_open(log);
	ret = mail_transaction_log_view_set(sync_view, view->log_file_seq,
					    view->log_file_offset,
					    log->head->hdr.file_seq,
					    log->head->hdr.used_size,
					    MAIL_TRANSACTION_TYPE_MASK);
	while ((ret = mail_transaction_log_view_next(sync_view,
						     &hdr, &data, NULL)) == 1) {
		if ((hdr->type & MAIL_TRANSACTION_TYPE_MASK) ==
		    MAIL_TRANSACTION_EXPUNGE) {
			mail_transaction_log_sort_expunges(expunges,
							   data, hdr->size);
		}
	}
	mail_transaction_log_view_close(sync_view);
	return ret;
}

static void
log_view_fix_sequences(struct mail_index_view *view, buffer_t *view_expunges,
		       buffer_t *buf, size_t record_size, int two, int uids)
{
	// FIXME: make sure this function works correctly
	const struct mail_transaction_expunge *exp, *exp_end, *exp2;
	unsigned char *data;
	uint32_t *seq, expunges_before, count;
	size_t src_idx, dest_idx, size;

	if (buf == NULL)
		return;

	exp = buffer_get_data(view_expunges, &size);
	exp_end = exp + (size / sizeof(*exp));
	if (exp == exp_end)
		return;

	data = buffer_get_modifyable_data(buf, &size);

	expunges_before = 0;
	for (src_idx = dest_idx = 0; src_idx < size; src_idx += record_size) {
		seq = (uint32_t *)&data[src_idx];

		while (exp != exp_end && exp->seq1 < seq[0]) {
			expunges_before += exp->seq2 - exp->seq1 + 1;
			exp++;
		}
		if (exp != exp_end && exp->seq1 == seq[0]) {
			/* this sequence was expunged */
			if (!two)
				continue;

			/* we point to next non-expunged message */
		}
		if (expunges_before != 0) {
			if (uids) {
				(void)mail_index_lookup_uid(view, seq[0],
							    &seq[2]);
			}
			seq[0] -= expunges_before;
		}

		if (two) {
			exp2 = exp;
			count = expunges_before;
			while (exp2 != exp_end && exp2->seq1 <= seq[1]) {
				count += exp->seq2 - exp->seq1 + 1;
				exp2++;
			}
			if (seq[1] < count || seq[1]-count < seq[0]) {
				/* whole range is expunged */
				continue;
			}
			if (count != 0) {
				if (uids) {
					(void)mail_index_lookup_uid(view,
								    seq[1],
								    &seq[3]);
				}
				seq[1] -= count;
			}
		}

		if (src_idx != dest_idx)
			memcpy(&data[dest_idx], &data[src_idx], record_size);
		dest_idx += record_size;
	}
	buffer_set_used_size(buf, dest_idx);
}

static int
mail_transaction_log_fix_sequences(struct mail_transaction_log *log,
                                   struct mail_index_transaction *t)
{
	buffer_t *view_expunges;

	if (t->updates == NULL && t->cache_updates == NULL &&
	    t->expunges == NULL)
		return 0;

	/* all sequences are currently relative to given view. we have to
	   find out all the expunges since then, even the ones that aren't
	   yet synchronized to index file. */
	view_expunges = buffer_create_dynamic(default_pool, 1024, (size_t)-1);
	if (get_expunge_buf(log, t->view, view_expunges) < 0) {
		buffer_free(view_expunges);
		return -1;
	}

	log_view_fix_sequences(t->view, view_expunges, t->updates,
			       sizeof(struct mail_transaction_flag_update),
			       TRUE, FALSE);
	log_view_fix_sequences(t->view, view_expunges, t->cache_updates,
			       sizeof(struct mail_transaction_cache_update),
			       FALSE, FALSE);
	log_view_fix_sequences(t->view, view_expunges, t->expunges,
			       sizeof(struct mail_transaction_expunge),
			       TRUE, TRUE);

	buffer_free(view_expunges);
	return 0;
}

static int mail_transaction_log_fix_appends(struct mail_transaction_log *log,
					    struct mail_index_transaction *t)
{
	struct mail_transaction_log_view *sync_view;
	const struct mail_index_record *old, *old_end;
	struct mail_index_record *appends, *end, *rec, *dest;
	const struct mail_transaction_header *hdr;
	const void *data;
	size_t size;
	int ret, deleted = FALSE;

	if (t->appends == NULL)
		return 0;

	appends = buffer_get_modifyable_data(t->appends, &size);
	end = PTR_OFFSET(appends, size);

	if (appends == end)
		return 0;

	/* we'll just check that none of the appends are already in
	   transaction log. this could happen if we crashed before we had
	   a chance to update index file */
	sync_view = mail_transaction_log_view_open(log);
	ret = mail_transaction_log_view_set(sync_view, t->view->log_file_seq,
					    t->view->log_file_offset,
					    log->head->hdr.file_seq,
					    log->head->hdr.used_size,
					    MAIL_TRANSACTION_TYPE_MASK);
	while ((ret = mail_transaction_log_view_next(sync_view,
						     &hdr, &data, NULL)) == 1) {
		if ((hdr->type & MAIL_TRANSACTION_TYPE_MASK) !=
		    MAIL_TRANSACTION_APPEND)
			continue;

		old = data;
		old_end = CONST_PTR_OFFSET(old, hdr->size);
		for (; old != old_end; old++) {
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

	mail_transaction_log_view_close(sync_view);
	return ret;
}

static int
log_append_buffer(struct mail_transaction_log_file *file, const buffer_t *buf,
		  enum mail_transaction_type type, int external)
{
	struct mail_transaction_header hdr;
	const void *data;
	size_t size;

	i_assert((type & MAIL_TRANSACTION_TYPE_MASK) != 0);

	if (buf != NULL) {
		data = buffer_get_data(buf, &size);
		if (size == 0)
			return 0;
	} else {
		/* write only the header */
		data = NULL;
		size = 0;
	}

	hdr.type = type;
	if (type == MAIL_TRANSACTION_EXPUNGE)
		hdr.type |= MAIL_TRANSACTION_EXPUNGE_PROT;
	if (external)
		hdr.type |= MAIL_TRANSACTION_EXTERNAL;
	hdr.size = size;

	if (pwrite_full(file->fd, &hdr, sizeof(hdr), file->hdr.used_size) < 0)
		return -1;
	file->hdr.used_size += sizeof(hdr);

	if (size != 0) {
		if (pwrite_full(file->fd, data, size, file->hdr.used_size) < 0)
			return -1;
		file->hdr.used_size += size;
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
	size_t offset;
	uoff_t append_offset;
	int ret;

	index = mail_index_view_get_index(view);
	log = index->log;

	if (t->updates == NULL && t->cache_updates == NULL &&
	    t->expunges == NULL && t->appends == NULL) {
		/* nothing to append */
		*log_file_seq_r = log->head->hdr.file_seq;
		*log_file_offset_r = log->head->hdr.used_size;
		return 0;
	}

	if (log->index->log_locked) {
		i_assert(view->external);
	} else {
		if (mail_transaction_log_lock_head(log) < 0)
			return -1;
	}

	if (log->head->hdr.file_seq == index->hdr->log_file_seq &&
	    log->head->hdr.used_size > MAIL_TRANSACTION_LOG_ROTATE_SIZE) {
		/* everything synced in index, we can rotate. */
		if (mail_transaction_log_rotate(log) < 0) {
			if (!log->index->log_locked) {
				(void)mail_transaction_log_file_lock(log->head,
								     F_UNLCK);
			}
			return -1;
		}
	}

	file = log->head;
	append_offset = file->hdr.used_size;

	if (mail_transaction_log_fix_sequences(log, t) < 0 ||
	    mail_transaction_log_fix_appends(log, t) < 0) {
		if (!log->index->log_locked)
			(void)mail_transaction_log_file_lock(file, F_UNLCK);
		return -1;
	}

	ret = 0;
	if (t->appends != NULL) {
		ret = log_append_buffer(file, t->appends,
					MAIL_TRANSACTION_APPEND,
					view->external);
	}
	if (t->updates != NULL && ret == 0) {
		ret = log_append_buffer(file, t->updates,
					MAIL_TRANSACTION_FLAG_UPDATE,
					view->external);
	}
	if (t->cache_updates != NULL && ret == 0) {
		ret = log_append_buffer(file, t->cache_updates,
					MAIL_TRANSACTION_CACHE_UPDATE,
					view->external);
	}
	if (t->expunges != NULL && ret == 0) {
		ret = log_append_buffer(file, t->expunges,
					MAIL_TRANSACTION_EXPUNGE,
					view->external);
	}

	if (ret == 0) {
		/* rewrite used_size */
		offset = offsetof(struct mail_transaction_log_header,
				  used_size);
		ret = pwrite_full(file->fd, &file->hdr.used_size,
				  sizeof(file->hdr.used_size), offset);
	}

	if (ret == 0 && (t->updates != NULL || t->appends != NULL) &&
	    t->hide_transaction) {
		mail_index_view_add_synced_transaction(view, file->hdr.file_seq,
						       append_offset);
	}

	if (ret < 0) {
		file->hdr.used_size = append_offset;
		mail_index_file_set_syscall_error(log->index, file->filepath,
						  "pwrite()");
	} else if (fsync(file->fd) < 0) {
		/* we don't know how much of it got written,
		   it may be corrupted now.. */
		mail_index_file_set_syscall_error(log->index, file->filepath,
						  "fsync()");
		ret = -1;
	}

	*log_file_seq_r = file->hdr.file_seq;
	*log_file_offset_r = file->hdr.used_size;

	if (!log->index->log_locked)
		(void)mail_transaction_log_file_lock(file, F_UNLCK);
	return ret;
}

int mail_transaction_log_sync_lock(struct mail_transaction_log *log,
				   uint32_t *file_seq_r, uoff_t *file_offset_r)
{
	i_assert(!log->index->log_locked);

	if (mail_transaction_log_lock_head(log) < 0)
		return -1;

	log->index->log_locked = TRUE;
	*file_seq_r = log->head->hdr.file_seq;
	*file_offset_r = log->head->hdr.used_size;
	return 0;
}

void mail_transaction_log_sync_unlock(struct mail_transaction_log *log)
{
	i_assert(log->index->log_locked);

	log->index->log_locked = FALSE;
	(void)mail_transaction_log_file_lock(log->head, F_UNLCK);
}

void mail_transaction_log_get_head(struct mail_transaction_log *log,
				   uint32_t *file_seq_r, uoff_t *file_offset_r)
{
	i_assert(log->index->log_locked);

	*file_seq_r = log->head->hdr.file_seq;
	*file_offset_r = log->head->hdr.used_size;
}
