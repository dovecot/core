/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "buffer.h"
#include "file-dotlock.h"
#include "nfs-workarounds.h"
#include "close-keep-errno.h"
#include "read-full.h"
#include "write-full.h"
#include "mmap-util.h"
#include "mail-index-private.h"
#include "mail-index-view-private.h"
#include "mail-transaction-log-private.h"
#include "mail-transaction-util.h"
#include "mail-index-transaction-private.h"

#include <stddef.h>
#include <stdio.h>
#include <sys/stat.h>

/* this lock should never exist for a long time.. */
#define LOG_DOTLOCK_TIMEOUT 60
#define LOG_DOTLOCK_STALE_TIMEOUT 60

#define MAIL_TRANSACTION_LOG_SUFFIX ".log"
#define LOG_NEW_DOTLOCK_SUFFIX ".newlock"

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

static struct mail_transaction_log *
mail_transaction_log_open_int(struct mail_index *index, bool create)
{
	struct mail_transaction_log *log;
	struct mail_transaction_log_file *file;
	const char *path;

	log = i_new(struct mail_transaction_log, 1);
	log->index = index;

	log->dotlock_settings.use_excl_lock = index->use_excl_dotlocks;
	log->dotlock_settings.timeout = LOG_DOTLOCK_TIMEOUT;
	log->dotlock_settings.stale_timeout = LOG_DOTLOCK_STALE_TIMEOUT;

	log->new_dotlock_settings = log->dotlock_settings;
	log->new_dotlock_settings.lock_suffix = LOG_NEW_DOTLOCK_SUFFIX;

	path = t_strconcat(index->filepath,
			   MAIL_TRANSACTION_LOG_SUFFIX, NULL);
	if (MAIL_INDEX_IS_IN_MEMORY(index))
		file = mail_transaction_log_file_alloc_in_memory(log);
	else if (create) {
		struct stat st;

		file = mail_transaction_log_file_alloc(log, path);
		if (stat(path, &st) < 0)
			memset(&st, 0, sizeof(st));
		if (mail_transaction_log_file_create(file, FALSE,
						     st.st_dev, st.st_ino,
						     st.st_size) < 0 ||
		    mail_transaction_log_file_fd_open_or_create(file,
								FALSE) < 0) {
			mail_transaction_log_file_free(file);
			file = NULL;
		}
	} else {
		file = mail_transaction_log_file_open_or_create(log, path);
	}

	if (file == NULL) {
		/* fallback to in-memory indexes */
		if (mail_index_move_to_memory(index) < 0) {
			mail_transaction_log_close(&log);
			return NULL;
		}
		file = mail_transaction_log_file_open_or_create(log, path);
		i_assert(file != NULL);
	}
	file->refcount++;
	log->head = file;
	i_assert(log->files != NULL);

	if (index->fd != -1 &&
	    INDEX_HAS_MISSING_LOGS(index, log->head)) {
		/* head log file isn't same as head index file -
		   shouldn't happen except in race conditions.
		   lock them and check again */
		if (mail_transaction_log_check_file_seq(log) < 0) {
			mail_transaction_log_close(&log);
			return NULL;
		}
	}
	return log;
}

struct mail_transaction_log *
mail_transaction_log_open_or_create(struct mail_index *index)
{
	return mail_transaction_log_open_int(index, FALSE);
}

struct mail_transaction_log *
mail_transaction_log_create(struct mail_index *index)
{
	return mail_transaction_log_open_int(index, TRUE);
}

void mail_transaction_log_close(struct mail_transaction_log **_log)
{
	struct mail_transaction_log *log = *_log;

	mail_transaction_log_views_close(log);

	if (log->head != NULL)
		log->head->refcount--;
	mail_transaction_logs_clean(log);
	i_assert(log->files == NULL);

	*_log = NULL;
	log->index->log = NULL;
	i_free(log);
}

int mail_transaction_log_move_to_memory(struct mail_transaction_log *log)
{
	struct mail_transaction_log_file *file = log->head;

	if (file == NULL || MAIL_TRANSACTION_LOG_FILE_IN_MEMORY(file))
		return 0;

	/* read the whole file to memory. we might currently be appending
	   data into it, so we want to read it up to end of file */
        file->buffer_offset = 0;

	if (file->buffer != NULL) {
		buffer_free(file->buffer);
		file->buffer = NULL;
	}

	if (file->mmap_base != NULL) {
		if (munmap(file->mmap_base, file->mmap_size) < 0) {
			mail_index_file_set_syscall_error(file->log->index,
							  file->filepath,
							  "munmap()");
		}
		file->mmap_base = NULL;
	}

	if (mail_transaction_log_file_read(file, 0) <= 0)
		return -1;

	/* after we've read the file into memory, make it into in-memory
	   log file */
	if (close(file->fd) < 0) {
		mail_index_file_set_syscall_error(file->log->index,
						  file->filepath, "close()");
	}
	file->fd = -1;
	return 0;
}

void mail_transaction_logs_clean(struct mail_transaction_log *log)
{
	struct mail_transaction_log_file *file, *next;

	for (file = log->files; file != NULL; file = next) {
		next = file->next;

		i_assert(file->refcount >= 0);
		if (file->refcount == 0)
			mail_transaction_log_file_free(file);
	}
}

int mail_transaction_log_rotate(struct mail_transaction_log *log, bool lock)
{
	struct mail_transaction_log_file *file;
	const char *path = log->head->filepath;
        struct stat st;
	int ret;

	i_assert(log->head->locked);

	if (MAIL_INDEX_IS_IN_MEMORY(log->index)) {
		file = mail_transaction_log_file_alloc_in_memory(log);
		if (lock)
			file->locked = TRUE;
	} else {
                /* we're locked, we shouldn't need to worry about ESTALE
                   problems in here. */
		if (fstat(log->head->fd, &st) < 0) {
			mail_index_file_set_syscall_error(log->index, path,
							  "fstat()");
			return -1;
		}

		file = mail_transaction_log_file_alloc(log, path);
		if (mail_transaction_log_file_create(file, lock, st.st_dev,
						     st.st_ino,
						     st.st_size) < 0) {
			mail_transaction_log_file_free(file);
			return -1;
		}

                ret = mail_transaction_log_file_fd_open_or_create(file, FALSE);
		if (ret <= 0) {
			i_assert(ret != 0);
			mail_transaction_log_file_free(file);
			return -1;
		}
	}

	i_assert(file->locked == lock);

	if (--log->head->refcount == 0)
		mail_transaction_logs_clean(log);
	else
		mail_transaction_log_file_unlock(log->head);

	i_assert(log->head != file);
	i_assert(log->files != NULL);
	log->head = file;
	log->head->refcount++;
	return 0;
}

static int mail_transaction_log_refresh(struct mail_transaction_log *log,
					bool create_if_needed)
{
        struct mail_transaction_log_file *file;
	struct stat st;
	const char *path;

	i_assert(log->head != NULL);

	if (MAIL_TRANSACTION_LOG_FILE_IN_MEMORY(log->head))
		return 0;

	path = t_strconcat(log->index->filepath,
			   MAIL_TRANSACTION_LOG_SUFFIX, NULL);
	if (nfs_safe_stat(path, &st) < 0) {
		if (errno != ENOENT) {
			mail_index_file_set_syscall_error(log->index, path,
							  "stat()");
			return -1;
		}
		/* log was deleted. just reopen/recreate it. */
	} else {
		if (log->head->st_ino == st.st_ino &&
		    CMP_DEV_T(log->head->st_dev, st.st_dev)) {
			/* same file */
			return 0;
		}
	}

	file = create_if_needed ?
		mail_transaction_log_file_open_or_create(log, path) :
		mail_transaction_log_file_open(log, path);
	if (file == NULL)
		return -1;

	i_assert(!file->locked);

	if (--log->head->refcount == 0)
		mail_transaction_logs_clean(log);

	i_assert(log->files != NULL);
	log->head = file;
	log->head->refcount++;
	return 0;
}

int mail_transaction_log_file_find(struct mail_transaction_log *log,
				   uint32_t file_seq,
				   struct mail_transaction_log_file **file_r)
{
	struct mail_transaction_log_file *file;
	struct stat st;
	const char *path;
	int ret, fd;

	if (file_seq > log->head->hdr.file_seq) {
		/* don't try to recreate log file if it gets lost. we're
		   already in trouble and with mmap_disable the creation
		   could cause a recursive mail_index_map() call */
		if (mail_transaction_log_refresh(log, FALSE) < 0)
			return -1;
	}

	for (file = log->files; file != NULL; file = file->next) {
		if (file->hdr.file_seq == file_seq) {
			*file_r = file;
			return 1;
		}
	}

	if (MAIL_INDEX_IS_IN_MEMORY(log->index))
		return 0;

	/* see if we have it in log.2 file */
	path = t_strconcat(log->index->filepath,
			   MAIL_TRANSACTION_LOG_SUFFIX".2", NULL);
	fd = nfs_safe_open(path, O_RDWR);
	if (fd == -1) {
		if (errno == ENOENT)
			return 0;

		mail_index_file_set_syscall_error(log->index, path, "open()");
		return -1;
	}

	if (fstat(fd, &st) < 0) {
		close_keep_errno(fd);
                if (errno == ESTALE) {
                        /* treat as "doesn't exist" */
                        return 0;
                }
                mail_index_file_set_syscall_error(log->index, path, "fstat()");
		return -1;
	}

	/* see if we have it already opened */
	for (file = log->files; file != NULL; file = file->next) {
		if (file->st_ino == st.st_ino &&
		    CMP_DEV_T(file->st_dev, st.st_dev)) {
			if (close(fd) < 0)
				i_error("close() failed: %m");
			return 0;
		}
	}


	file = mail_transaction_log_file_alloc(log, path);
	file->fd = fd;

	ret = mail_transaction_log_file_fd_open(file, FALSE, TRUE);
	if (ret <= 0) {
		bool stale = errno == ESTALE;

		if (ret == 0) {
			/* corrupted, delete it */
			if (unlink(file->filepath) < 0 && errno != ENOENT) {
				i_error("unlink(%s) failed: %m",
					file->filepath);
			}
			mail_transaction_log_file_free(file);
			return 0;
                }
		mail_transaction_log_file_free(file);

		if (stale) {
                        /* treat as "doesn't exist" */
                        return 0;
                }
		return -1;
	}

	/* got it */
	mail_transaction_log_file_add_to_list(file);

	/* but is it what we expected? */
	if (file->hdr.file_seq != file_seq)
		return 0;

	*file_r = file;
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
		ret = mail_transaction_log_refresh(log, TRUE);
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

bool mail_transaction_log_is_head_prev(struct mail_transaction_log *log,
				       uint32_t file_seq, uoff_t file_offset)
{
	return log->head->hdr.prev_file_seq == file_seq &&
		log->head->hdr.prev_file_offset == file_offset;
}
