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

#define MAIL_TRANSACTION_LOG_PREFIX ".log"
#define LOG_NEW_DOTLOCK_SUFFIX ".newlock"

static struct mail_transaction_log_file *
mail_transaction_log_file_open_or_create(struct mail_transaction_log *log,
					 const char *path);

void
mail_transaction_log_file_set_corrupted(struct mail_transaction_log_file *file,
					const char *fmt, ...)
{
	va_list va;

	file->hdr.indexid = 0;
	if (!MAIL_TRANSACTION_LOG_FILE_IN_MEMORY(file)) {
		if (pwrite_full(file->fd, &file->hdr.indexid,
				sizeof(file->hdr.indexid), 0) < 0) {
			mail_index_file_set_syscall_error(file->log->index,
				file->filepath, "pwrite()");
		}
	}

	va_start(va, fmt);
	t_push();
	mail_index_set_error(file->log->index,
			     "Corrupted transaction log file %s: %s",
			     file->filepath, t_strdup_vprintf(fmt, va));
	t_pop();
	va_end(va);

	if (file->log->index->log != NULL) {
		/* this may have happened because of broken index.
		   make sure it's ok. */
		(void)mail_index_fsck(file->log->index);
	}
}

static int
mail_transaction_log_file_dotlock(struct mail_transaction_log_file *file)
{
	int ret;

	if (file->log->dotlock_count > 0)
		ret = 1;
	else {
		ret = file_dotlock_create(&file->log->dotlock_settings,
					  file->filepath, 0,
					  &file->log->dotlock);
	}
	if (ret > 0) {
		file->log->dotlock_count++;
		file->locked = TRUE;
		return 0;
	}
	if (ret < 0) {
		mail_index_file_set_syscall_error(file->log->index,
						  file->filepath,
						  "file_dotlock_create()");
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

	ret = file_dotlock_delete(&file->log->dotlock);
	if (ret < 0) {
		mail_index_file_set_syscall_error(file->log->index,
			file->filepath, "file_dotlock_delete()");
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

	if (MAIL_TRANSACTION_LOG_FILE_IN_MEMORY(file)) {
		file->locked = TRUE;
		return 0;
	}

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

void mail_transaction_log_file_unlock(struct mail_transaction_log_file *file)
{
	int ret;

	if (!file->locked)
		return;

	file->locked = FALSE;

	if (MAIL_TRANSACTION_LOG_FILE_IN_MEMORY(file))
		return;

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
	   (index)->hdr->log_file_int_offset >= (file)->hdr.hdr_size) || \
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

	log->dotlock_settings.timeout = LOG_DOTLOCK_TIMEOUT;
	log->dotlock_settings.stale_timeout = LOG_DOTLOCK_STALE_TIMEOUT;
	log->dotlock_settings.immediate_stale_timeout =
		LOG_DOTLOCK_IMMEDIATE_STALE_TIMEOUT;

	log->new_dotlock_settings = log->dotlock_settings;
	log->new_dotlock_settings.lock_suffix = LOG_NEW_DOTLOCK_SUFFIX;

	path = t_strconcat(log->index->filepath,
			   MAIL_TRANSACTION_LOG_PREFIX, NULL);
	log->head = mail_transaction_log_file_open_or_create(log, path);
	if (log->head == NULL) {
		mail_transaction_log_close(log);
		return NULL;
	}

	if (index->fd != -1 &&
	    INDEX_HAS_MISSING_LOGS(index, log->head)) {
		/* head log file isn't same as head index file -
		   shouldn't happen except in race conditions.
		   lock them and check again */
		if (mail_transaction_log_check_file_seq(log) < 0) {
			mail_transaction_log_close(log);
			return NULL;
		}
	}
	return log;
}

void mail_transaction_log_close(struct mail_transaction_log *log)
{
	mail_transaction_log_views_close(log);

	if (log->head != NULL) {
		log->head->refcount--;
		mail_transaction_logs_clean(log);
	}

	log->index->log = NULL;
	i_free(log);
}

static void
mail_transaction_log_file_close(struct mail_transaction_log_file *file)
{
	if (file == file->log->head)
		file->log->head = NULL;
	if (file == file->log->tail)
		file->log->tail = file->next;

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

	if (file->fd != -1) {
		if (close(file->fd) < 0) {
			mail_index_file_set_syscall_error(file->log->index,
							  file->filepath,
							  "close()");
		}
	}

	i_free(file->filepath);
	i_free(file);
}

static int
mail_transaction_log_file_read_hdr(struct mail_transaction_log_file *file)
{
        struct mail_transaction_log_file *f;
	int ret;

	i_assert(!MAIL_INDEX_IS_IN_MEMORY(file->log->index));

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

	if (file->hdr.major_version != MAIL_TRANSACTION_LOG_MAJOR_VERSION) {
		/* incompatible version - fix silently */
		return 0;
	}
	if (file->hdr.hdr_size < MAIL_TRANSACTION_LOG_HEADER_MIN_SIZE) {
		mail_transaction_log_file_set_corrupted(file,
			"Header size too small");
		return 0;
	}
	if (file->hdr.hdr_size < sizeof(file->hdr)) {
		/* @UNSAFE: smaller than we expected - zero out the fields we
		   shouldn't have filled */
		memset(PTR_OFFSET(&file->hdr, file->hdr.hdr_size), 0,
		       sizeof(file->hdr) - file->hdr.hdr_size);
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
		mail_transaction_log_file_set_corrupted(file,
			"invalid indexid (%u != %u)",
			file->hdr.indexid, file->log->index->indexid);
		return 0;
	}

	/* make sure we already don't have a file with the same sequence
	   opened. it shouldn't happen unless the old log file was
	   corrupted. */
	for (f = file->log->tail; f != NULL; f = f->next) {
		if (f->hdr.file_seq >= file->hdr.file_seq) {
			mail_transaction_log_file_set_corrupted(file,
				"invalid new transaction log sequence "
				"(%u >= %u)",
				f->hdr.file_seq, file->hdr.file_seq);
			return 0;
		}
	}

	return 1;
}

static int
mail_transaction_log_init_hdr(struct mail_transaction_log *log,
			      struct mail_transaction_log_header *hdr)
{
	struct mail_index *index = log->index;
	unsigned int lock_id;

	memset(hdr, 0, sizeof(*hdr));
	hdr->major_version = MAIL_TRANSACTION_LOG_MAJOR_VERSION;
	hdr->minor_version = MAIL_TRANSACTION_LOG_MINOR_VERSION;
	hdr->hdr_size = sizeof(struct mail_transaction_log_header);
	hdr->indexid = log->index->indexid;
	hdr->create_stamp = ioloop_time;

	if (index->fd != -1) {
		/* not creating index - make sure we have latest header */
		if (mail_index_lock_shared(index, TRUE, &lock_id) < 0)
			return -1;
		if (mail_index_map(index, FALSE) <= 0) {
			mail_index_unlock(index, lock_id);
			return -1;
		}
	}
	hdr->prev_file_seq = index->hdr->log_file_seq;
	hdr->prev_file_offset = index->hdr->log_file_int_offset;
	hdr->file_seq = index->hdr->log_file_seq+1;

	if (index->fd != -1)
		mail_index_unlock(index, lock_id);

	if (log->head != NULL && hdr->file_seq <= log->head->hdr.file_seq) {
		/* make sure the sequence grows */
		hdr->file_seq = log->head->hdr.file_seq+1;
	}
	return 0;
}

static int
mail_transaction_log_file_create2(struct mail_transaction_log *log,
				  const char *path, int fd,
				  struct dotlock **dotlock,
				  dev_t dev, ino_t ino, uoff_t file_size)
{
	struct mail_index *index = log->index;
	struct mail_transaction_log_header hdr;
	struct stat st;
	int fd2, ret;

	/* log creation is locked now - see if someone already created it */
	fd2 = open(path, O_RDWR);
	if (fd2 != -1) {
		if ((ret = fstat(fd2, &st)) < 0) {
			mail_index_file_set_syscall_error(index, path,
							  "fstat()");
		} else if (st.st_ino == ino && CMP_DEV_T(st.st_dev, dev) &&
			   (uoff_t)st.st_size == file_size) {
			/* same file, still broken */
		} else {
			(void)file_dotlock_delete(dotlock);
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

	if (mail_transaction_log_init_hdr(log, &hdr) < 0)
		return -1;

	if (write_full(fd, &hdr, sizeof(hdr)) < 0) {
		mail_index_file_set_syscall_error(index, path,
						  "write_full()");
		return -1;
	}

	if (file_dotlock_replace(dotlock,
				 DOTLOCK_REPLACE_FLAG_DONT_CLOSE_FD) <= 0)
		return -1;

	/* success */
	return fd;
}

static int
mail_transaction_log_file_create(struct mail_transaction_log *log,
				 const char *path,
				 dev_t dev, ino_t ino, uoff_t file_size)
{
	struct dotlock *dotlock;
        mode_t old_mask;
	int fd, fd2;

	i_assert(!MAIL_INDEX_IS_IN_MEMORY(log->index));

	/* With dotlocking we might already have path.lock created, so this
	   filename has to be different. */
	old_mask = umask(log->index->mode ^ 0666);
	fd = file_dotlock_open(&log->new_dotlock_settings, path, 0, &dotlock);
	umask(old_mask);

	if (fd == -1) {
		mail_index_file_set_syscall_error(log->index, path,
						  "file_dotlock_open()");
		return -1;
	}

	if (log->index->gid != (gid_t)-1 &&
	    fchown(fd, (uid_t)-1, log->index->gid) < 0) {
		mail_index_file_set_syscall_error(log->index, path, "fchown()");
		(void)file_dotlock_delete(&dotlock);
		return -1;
	}

	fd2 = mail_transaction_log_file_create2(log, path, fd, &dotlock,
						dev, ino, file_size);
	if (fd2 < 0) {
		(void)file_dotlock_delete(&dotlock);
		return -1;
	}
	return fd2;
}

static void
mail_transaction_log_file_alloc_finish(struct mail_transaction_log_file *file)
{
	struct mail_transaction_log *log = file->log;
	struct mail_transaction_log_file **p;

	if (log->index->map != NULL &&
	    file->hdr.file_seq == log->index->map->hdr.log_file_seq &&
	    log->index->map->hdr.log_file_int_offset != 0) {
		/* we can get a valid log offset from index file. initialize
		   sync_offset from it so we don't have to read the whole log
		   file from beginning. */
		file->sync_offset = log->index->map->hdr.log_file_int_offset;
	} else {
		file->sync_offset = file->hdr.hdr_size;
	}

	/* append to end of list. */
	for (p = &log->tail; *p != NULL; p = &(*p)->next)
		i_assert((*p)->hdr.file_seq < file->hdr.file_seq);
	*p = file;
}

static struct mail_transaction_log_file *
mail_transaction_log_file_fd_open(struct mail_transaction_log *log,
				  const char *path, int fd)
{
        struct mail_transaction_log_file *file;
	struct stat st;
	int ret;

	i_assert(!MAIL_INDEX_IS_IN_MEMORY(log->index));

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

	ret = mail_transaction_log_file_read_hdr(file);
	if (ret == 0) {
		/* corrupted header */
		fd = mail_transaction_log_file_create(log, path, st.st_dev,
						      st.st_ino, st.st_size);
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

        mail_transaction_log_file_alloc_finish(file);
	return file;
}

static struct mail_transaction_log_file *
mail_transaction_log_file_alloc_in_memory(struct mail_transaction_log *log)
{
	struct mail_transaction_log_file *file;

	file = i_new(struct mail_transaction_log_file, 1);
	file->refcount = 1;
	file->log = log;
	file->filepath = i_strdup("(in-memory transaction log file)");
	file->fd = -1;

	if (mail_transaction_log_init_hdr(log, &file->hdr) < 0) {
		i_free(file);
		return NULL;
	}

	file->buffer = buffer_create_dynamic(default_pool, 4096);
	file->buffer_offset = sizeof(file->hdr);

	mail_transaction_log_file_alloc_finish(file);
	return file;
}

static struct mail_transaction_log_file *
mail_transaction_log_file_open_or_create(struct mail_transaction_log *log,
					 const char *path)
{
	int fd;

	if (MAIL_INDEX_IS_IN_MEMORY(log->index))
		return mail_transaction_log_file_alloc_in_memory(log);

	fd = open(path, O_RDWR);
	if (fd == -1) {
		if (errno != ENOENT) {
			mail_index_file_set_syscall_error(log->index, path,
							  "open()");
			return NULL;
		}

		fd = mail_transaction_log_file_create(log, path, 0, 0, 0);
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
}

int mail_transaction_log_rotate(struct mail_transaction_log *log, int lock)
{
	struct mail_transaction_log_file *file;
	const char *path = log->head->filepath;
	struct stat st;
	int fd;

	i_assert(log->head->locked);

	if (MAIL_INDEX_IS_IN_MEMORY(log->index))
		file = mail_transaction_log_file_alloc_in_memory(log);
	else {
		if (fstat(log->head->fd, &st) < 0) {
			mail_index_file_set_syscall_error(log->index, path,
							  "fstat()");
			return -1;
		}

		fd = mail_transaction_log_file_create(log, path,
						      st.st_dev, st.st_ino,
						      st.st_size);
		if (fd == -1)
			return -1;

		file = mail_transaction_log_file_fd_open(log, path, fd);
		if (file == NULL)
			return -1;
	}

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

static int mail_transaction_log_refresh(struct mail_transaction_log *log)
{
        struct mail_transaction_log_file *file;
	struct stat st;
	const char *path;

	if (MAIL_TRANSACTION_LOG_FILE_IN_MEMORY(log->head))
		return 0;

	path = t_strconcat(log->index->filepath,
			   MAIL_TRANSACTION_LOG_PREFIX, NULL);
	if (stat(path, &st) < 0) {
		mail_index_file_set_syscall_error(log->index, path, "stat()");
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

	if (file->sync_offset < file->buffer_offset)
		file->sync_offset = file->buffer_offset;

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

		if (file->sync_offset - file->buffer_offset + hdr_size > size) {
			/* record goes outside the file we've seen. or if
			   we're accessing the log file via unlocked mmaped
			   memory, it may be just that the memory was updated
			   after we checked the file size. */
			if (file->locked || file->mmap_base == NULL) {
				mail_transaction_log_file_set_corrupted(file,
					"hdr.size too large (%u)", hdr_size);
				return -1;
			}
			break;
		}
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

	if (MAIL_TRANSACTION_LOG_FILE_IN_MEMORY(file))
		return 1;

	if (start_offset < file->hdr.hdr_size) {
		mail_transaction_log_file_set_corrupted(file,
			"offset (%"PRIuUOFF_T") < header size (%"PRIuSIZE_T")",
			start_offset, file->hdr.hdr_size);
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

	if (fstat(file->fd, &st) < 0) {
		mail_index_file_set_syscall_error(index, file->filepath,
						  "fstat()");
		return -1;
	}
	if (start_offset > (uoff_t)st.st_size) {
		mail_transaction_log_file_set_corrupted(file,
			"start_offset (%"PRIuUOFF_T") > file size "
			"(%"PRIuUOFF_T")", start_offset, (uoff_t)st.st_size);
		return -1;
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

int mail_transaction_log_lock_head(struct mail_transaction_log *log)
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
