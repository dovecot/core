/* Copyright (C) 2003-2007 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "buffer.h"
#include "file-dotlock.h"
#include "nfs-workarounds.h"
#include "read-full.h"
#include "write-full.h"
#include "mmap-util.h"
#include "mail-index-private.h"
#include "mail-transaction-log-private.h"

#define LOG_PREFETCH 1024

void
mail_transaction_log_file_set_corrupted(struct mail_transaction_log_file *file,
					const char *fmt, ...)
{
	va_list va;

	file->hdr.indexid = 0;
	if (!MAIL_TRANSACTION_LOG_FILE_IN_MEMORY(file)) {
		if (pwrite_full(file->fd, &file->hdr.indexid,
				sizeof(file->hdr.indexid),
				offsetof(struct mail_transaction_log_header,
					 indexid)) < 0) {
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

	if (file->log->index->log != NULL && file->log->index->map != NULL) {
		/* this may have happened because of broken index.
		   make sure it's ok. */
		(void)mail_index_fsck(file->log->index);
	}
}

struct mail_transaction_log_file *
mail_transaction_log_file_alloc(struct mail_transaction_log *log,
				const char *path)
{
	struct mail_transaction_log_file *file;

	file = i_new(struct mail_transaction_log_file, 1);
	file->log = log;
	file->filepath = i_strdup(path);
	file->fd = -1;
	return file;
}

void mail_transaction_log_file_free(struct mail_transaction_log_file *file)
{
	struct mail_transaction_log_file **p;
	int old_errno = errno;

	mail_transaction_log_file_unlock(file);

	for (p = &file->log->files; *p != NULL; p = &(*p)->next) {
		if (*p == file) {
			*p = file->next;
			break;
		}
	}

	if (file == file->log->head)
		file->log->head = NULL;

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

        errno = old_errno;
}

void
mail_transaction_log_file_add_to_list(struct mail_transaction_log_file *file)
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

	/* insert it to correct position */
	for (p = &log->files; *p != NULL; p = &(*p)->next) {
		if ((*p)->hdr.file_seq > file->hdr.file_seq)
			break;
		i_assert((*p)->hdr.file_seq < file->hdr.file_seq);
	}

	file->next = *p;
	*p = file;
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

struct mail_transaction_log_file *
mail_transaction_log_file_alloc_in_memory(struct mail_transaction_log *log)
{
	struct mail_transaction_log_file *file;

	file = i_new(struct mail_transaction_log_file, 1);
	file->log = log;
	file->filepath = i_strdup("(in-memory transaction log file)");
	file->fd = -1;

	if (mail_transaction_log_init_hdr(log, &file->hdr) < 0) {
		i_free(file);
		return NULL;
	}

	file->buffer = buffer_create_dynamic(default_pool, 4096);
	file->buffer_offset = sizeof(file->hdr);

	mail_transaction_log_file_add_to_list(file);
	return file;
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

int mail_transaction_log_file_lock(struct mail_transaction_log_file *file)
{
	int ret;

	if (file->locked)
		return 0;

	if (MAIL_TRANSACTION_LOG_FILE_IN_MEMORY(file)) {
		file->locked = TRUE;
		return 0;
	}

	if (file->log->index->lock_method == FILE_LOCK_METHOD_DOTLOCK)
		return mail_transaction_log_file_dotlock(file);

	i_assert(file->file_lock == NULL);
	ret = mail_index_lock_fd(file->log->index, file->filepath, file->fd,
				 F_WRLCK, MAIL_INDEX_LOCK_SECS,
				 &file->file_lock);
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
		"Timeout while waiting for lock for transaction log file %s",
		file->filepath);
	file->log->index->index_lock_timeout = TRUE;
	return -1;
}

void mail_transaction_log_file_unlock(struct mail_transaction_log_file *file)
{
	if (!file->locked)
		return;

	file->locked = FALSE;

	if (MAIL_TRANSACTION_LOG_FILE_IN_MEMORY(file))
		return;

	if (file->log->index->lock_method == FILE_LOCK_METHOD_DOTLOCK) {
		mail_transaction_log_file_undotlock(file);
		return;
	}

	file_unlock(&file->file_lock);
}

static int
mail_transaction_log_file_read_hdr(struct mail_transaction_log_file *file,
				   int head, bool ignore_estale)
{
        struct mail_transaction_log_file *f;
	int ret;

	i_assert(!MAIL_INDEX_IS_IN_MEMORY(file->log->index));

	ret = pread_full(file->fd, &file->hdr, sizeof(file->hdr), 0);
	if (ret < 0) {
                if (errno != ESTALE || !ignore_estale) {
                        mail_index_file_set_syscall_error(file->log->index,
                                                          file->filepath,
                                                          "pread_full()");
                }
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
		if (file->log->index->fd != -1) {
			/* index file was probably just rebuilt and we don't
			   know about it yet */
			mail_transaction_log_file_set_corrupted(file,
				"invalid indexid (%u != %u)",
				file->hdr.indexid, file->log->index->indexid);
			return 0;
		}

		/* creating index file. since transaction log is created
		   first, use the indexid in it to create the main index
		   to avoid races. */
		file->log->index->indexid = file->hdr.indexid;
	}

	/* make sure we already don't have a file with the same sequence
	   opened. it shouldn't happen unless the old log file was
	   corrupted.

	   If we're opening head log file, make sure the sequence is larger
	   than any existing one. */
	if (head) {
		for (f = file->log->files; f != NULL; f = f->next) {
			if (f->hdr.file_seq >= file->hdr.file_seq) {
				mail_transaction_log_file_set_corrupted(file,
					"invalid new transaction log sequence "
					"(%u >= %u)",
					f->hdr.file_seq, file->hdr.file_seq);
				return 0;
			}
		}
	} else {
		for (f = file->log->files; f != NULL; f = f->next) {
			if (f->hdr.file_seq == file->hdr.file_seq) {
				mail_transaction_log_file_set_corrupted(file,
					"old transaction log already opened "
					"(%u == %u)",
					f->hdr.file_seq, file->hdr.file_seq);
				return 0;
			}
		}
	}

	return 1;
}

static int
mail_transaction_log_file_create2(struct mail_transaction_log_file *file,
				  bool lock, int new_fd,
				  struct dotlock **dotlock,
				  dev_t dev, ino_t ino, uoff_t file_size)
{
	struct mail_index *index = file->log->index;
	struct mail_transaction_log_header hdr;
	struct stat st;
	const char *path2;
	int old_fd, ret;
	bool rename_existing;

	i_assert(!lock || file->log->head->locked);

	/* log creation is locked now - see if someone already created it */
	if (lock) {
		/* don't even bother checking the existing file, but rename it
		   if it exists */
		rename_existing = TRUE;
	} else if ((old_fd = nfs_safe_open(file->filepath, O_RDWR)) != -1) {
		if ((ret = fstat(old_fd, &st)) < 0) {
                        mail_index_file_set_syscall_error(index, file->filepath,
                                                          "fstat()");
		} else if (st.st_ino == ino && CMP_DEV_T(st.st_dev, dev) &&
			   (uoff_t)st.st_size == file_size) {
			/* same file, still broken */
		} else {
                        /* file changed, use the new file */
			(void)file_dotlock_delete(dotlock);
			file->fd = old_fd;
			return 0;
		}

		(void)close(old_fd);
		old_fd = -1;

                if (ret < 0) {
                        /* fstat() failure, return after closing fd.. */
                        return -1;
                }
		rename_existing = TRUE;
	} else if (errno != ENOENT) {
		mail_index_file_set_syscall_error(index, file->filepath,
						  "open()");
		return -1;
	} else {
		rename_existing = FALSE;
	}

	if (mail_transaction_log_init_hdr(file->log, &hdr) < 0)
		return -1;

	if (write_full(new_fd, &hdr, sizeof(hdr)) < 0) {
		mail_index_file_set_syscall_error(index, file->filepath,
						  "write_full()");
		return -1;
	}

	if (lock) {
		file->fd = new_fd;
		ret = mail_transaction_log_file_lock(file);
		file->fd = -1;
		if (ret < 0)
			return -1;
	}

	/* keep two log files */
	if (rename_existing) {
		/* rename() would be nice and easy way to do this, except then
		   there's a race condition between the rename and
		   file_dotlock_replace(). during that time the log file
		   doesn't exist, which could cause problems. */
		path2 = t_strconcat(file->filepath, ".2", NULL);
		if (unlink(path2) < 0 && errno != ENOENT) {
                        mail_index_set_error(index, "unlink(%s) failed: %m",
					     path2);
			/* try to link() anyway */
		}
		if (link(file->filepath, path2) < 0 &&
		    errno != ENOENT && errno != EEXIST) {
                        mail_index_set_error(index, "link(%s, %s) failed: %m",
					     file->filepath, path2);
			/* ignore the error. we don't care that much about the
			   second log file and we're going to overwrite this
			   first one. */
		}
	}

	if (file_dotlock_replace(dotlock,
				 DOTLOCK_REPLACE_FLAG_DONT_CLOSE_FD) <= 0)
		return -1;

	/* success */
	file->fd = new_fd;
	return 0;
}

int mail_transaction_log_file_create(struct mail_transaction_log_file *file,
				     bool lock, dev_t dev, ino_t ino,
				     uoff_t file_size)
{
	struct mail_index *index = file->log->index;
	struct dotlock *dotlock;
	struct stat st;
	mode_t old_mask;
	int fd;

	i_assert(!MAIL_INDEX_IS_IN_MEMORY(index));

	if (stat(index->dir, &st) < 0) {
		if (ENOTFOUND(errno)) {
			/* the whole index directory was deleted, which means
			   the mailbox was deleted by another process.
			   fail silently. */
			mail_index_mark_corrupted(index);
			return -1;
		}
		mail_index_file_set_syscall_error(index, index->dir, "stat()");
		return -1;
	}

	/* With dotlocking we might already have path.lock created, so this
	   filename has to be different. */
	old_mask = umask(index->mode ^ 0666);
	fd = file_dotlock_open(&file->log->new_dotlock_settings,
			       file->filepath, 0, &dotlock);
	umask(old_mask);

	if (fd == -1) {
		mail_index_file_set_syscall_error(index, file->filepath,
						  "file_dotlock_open()");
		return -1;
	}

	if (index->gid != (gid_t)-1 &&
	    fchown(fd, (uid_t)-1, index->gid) < 0) {
		mail_index_file_set_syscall_error(index, file->filepath,
						  "fchown()");
		(void)file_dotlock_delete(&dotlock);
		return -1;
	}

        /* either fd gets used or the dotlock gets deleted and returned fd
           is for the existing file */
        if (mail_transaction_log_file_create2(file, lock, fd, &dotlock,
					      dev, ino, file_size) < 0) {
		if (dotlock != NULL)
			(void)file_dotlock_delete(&dotlock);
		return -1;
	}
	return 0;
}

int mail_transaction_log_file_fd_open(struct mail_transaction_log_file *file,
				      bool head, bool ignore_estale)
{
	struct stat st;

	i_assert(!MAIL_INDEX_IS_IN_MEMORY(file->log->index));

	if (fstat(file->fd, &st) < 0) {
                if (errno != ESTALE || !ignore_estale) {
			mail_index_file_set_syscall_error(file->log->index,
							  file->filepath,
							  "fstat()");
                }
		return -1;
	}

	file->st_dev = st.st_dev;
	file->st_ino = st.st_ino;
	file->last_mtime = st.st_mtime;
	file->last_size = st.st_size;

	return mail_transaction_log_file_read_hdr(file, head, ignore_estale);
}

int mail_transaction_log_file_fd_open_or_create(struct mail_transaction_log_file
						*file, bool try_retry)
{
	int ret;

	ret = mail_transaction_log_file_fd_open(file, TRUE, !try_retry);
	if (ret == 0) {
		/* corrupted header, recreate the file */
		if (mail_transaction_log_file_create(file, FALSE,
						     file->st_dev,
						     file->st_ino,
						     file->last_size) < 0)
			ret = -1;
		else {
			ret = mail_transaction_log_file_fd_open(file, TRUE,
								FALSE);
			if (ret == 0) {
				/* newly created transaction log corrupted */
				return -1;
			}
		}
	}
	if (ret < 0)
		return errno == ENOENT && try_retry ? 0 : -1;

        mail_transaction_log_file_add_to_list(file);
	return 1;
}

struct mail_transaction_log_file *
mail_transaction_log_file_open_or_create(struct mail_transaction_log *log,
					 const char *path)
{
        struct mail_transaction_log_file *file;
        unsigned int i;
	int ret;

	if (MAIL_INDEX_IS_IN_MEMORY(log->index))
		return mail_transaction_log_file_alloc_in_memory(log);

	file = mail_transaction_log_file_alloc(log, path);

        for (i = 0; ; i++) {
                file->fd = nfs_safe_open(path, O_RDWR);
                if (file->fd == -1) {
                        if (errno != ENOENT) {
				mail_index_file_set_syscall_error(log->index,
                                                                  path,
                                                                  "open()");
				break;
                        }

                        /* doesn't exist, try creating it */
			if (mail_transaction_log_file_create(file, FALSE,
							     0, 0, 0) < 0)
				break;
                }

		ret = mail_transaction_log_file_fd_open_or_create(file,
                		i == MAIL_INDEX_ESTALE_RETRY_COUNT);
		if (ret > 0)
			return file;
		if (ret < 0)
			break;

                /* ESTALE - retry */
	}

	mail_transaction_log_file_free(file);
	return NULL;
}

struct mail_transaction_log_file *
mail_transaction_log_file_open(struct mail_transaction_log *log,
			       const char *path)
{
	struct mail_transaction_log_file *file;
        unsigned int i;
        int ret;

	file = mail_transaction_log_file_alloc(log, path);
        for (i = 0;; i++) {
                file->fd = nfs_safe_open(path, O_RDWR);
                if (file->fd == -1) {
                        mail_index_file_set_syscall_error(log->index, path,
                                                          "open()");
			break;
                }

		ret = mail_transaction_log_file_fd_open(file,
                		TRUE, i < MAIL_INDEX_ESTALE_RETRY_COUNT);
		if (ret > 0) {
			/* success */
			mail_transaction_log_file_add_to_list(file);
			return file;
		}

		if (ret == 0) {
			/* corrupted */
			break;
		}
		if (errno != ESTALE ||
		    i == MAIL_INDEX_ESTALE_RETRY_COUNT) {
			/* syscall error */
			break;
		}

		/* ESTALE - try again */
        }

	mail_transaction_log_file_free(file);
	return NULL;
}

static int
mail_transaction_log_file_sync(struct mail_transaction_log_file *file)
{
        const struct mail_transaction_header *hdr;
	const void *data;
	size_t size, avail;
	uint32_t hdr_size = 0;

	data = buffer_get_data(file->buffer, &size);

	if (file->sync_offset < file->buffer_offset)
		file->sync_offset = file->buffer_offset;

	while (file->sync_offset - file->buffer_offset + sizeof(*hdr) <= size) {
		hdr = CONST_PTR_OFFSET(data, file->sync_offset -
				       file->buffer_offset);
		hdr_size = mail_index_offset_to_uint32(hdr->size);
		if (hdr_size == 0) {
			/* unfinished */
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

	avail = file->sync_offset - file->buffer_offset;
	if (avail != size && avail >= sizeof(*hdr)) {
		/* record goes outside the file we've seen. or if
		   we're accessing the log file via unlocked mmaped
		   memory, it may be just that the memory was updated
		   after we checked the file size. */
		if (file->locked || file->mmap_base == NULL) {
			if (hdr_size != 0) {
				mail_transaction_log_file_set_corrupted(file,
					"hdr.size too large (%u)", hdr_size);
			} else {
				mail_transaction_log_file_set_corrupted(file,
					"Unexpected garbage at EOF");
			}
			return -1;
		}
	}
	return 0;
}

int mail_transaction_log_file_read(struct mail_transaction_log_file *file,
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

	file->last_size = read_offset;

	if (mail_transaction_log_file_sync(file) < 0)
		return -1;

	if (ret == 0) {
		/* EOF */
		i_assert(file->sync_offset >= file->buffer_offset);
		buffer_set_used_size(file->buffer,
				     file->sync_offset - file->buffer_offset);
		return 1;
	}

	if (errno == ESTALE) {
		/* log file was deleted in NFS server, fail silently */
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
	int ret;

	i_assert(start_offset <= end_offset);

	if (file->hdr.indexid == 0) {
		/* corrupted */
		return 0;
	}

	if (start_offset < file->hdr.hdr_size) {
		mail_transaction_log_file_set_corrupted(file,
			"offset (%"PRIuUOFF_T") < header size (%u)",
			start_offset, file->hdr.hdr_size);
		return -1;
	}

	if (MAIL_TRANSACTION_LOG_FILE_IN_MEMORY(file))
		return 1;

	if (file->buffer != NULL && file->buffer_offset <= start_offset) {
		/* see if we already have it */
		size = buffer_get_used_size(file->buffer);
		if (file->buffer_offset + size >= end_offset)
			return 1;
	}

	if (!index->mmap_disable) {
		if (fstat(file->fd, &st) < 0) {
			mail_index_file_set_syscall_error(index, file->filepath,
							  "fstat()");
			return -1;
		}
		file->last_size = st.st_size;

		if (start_offset > (uoff_t)st.st_size) {
			mail_transaction_log_file_set_corrupted(file,
				"start_offset (%"PRIuUOFF_T") > file size "
				"(%"PRIuUOFF_T")", start_offset,
				(uoff_t)st.st_size);
			return -1;
		}

		if (file->mmap_base != NULL &&
		    (uoff_t)st.st_size == file->mmap_size &&
		    file->buffer_offset <= start_offset &&
		    end_offset == (uoff_t)-1) {
			/* it's all mmaped already */
			if (mail_transaction_log_file_sync(file) < 0)
				return -1;
			return 1;
		}
	}

	if (file->buffer != NULL &&
	    (file->mmap_base != NULL || !index->mmap_disable)) {
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

	if (index->mmap_disable) {
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

	if (start_offset > file->sync_offset) {
		mail_transaction_log_file_set_corrupted(file,
			"start_offset (%"PRIuUOFF_T") > current sync_offset "
			"(%"PRIuUOFF_T")", start_offset, file->sync_offset);
		return -1;
	}
	if (end_offset != (uoff_t)-1 && end_offset > file->sync_offset) {
		mail_transaction_log_file_set_corrupted(file,
			"end_offset (%"PRIuUOFF_T") > current sync_offset "
			"(%"PRIuUOFF_T")", end_offset, file->sync_offset);
		return -1;
	}

	return 1;
}
