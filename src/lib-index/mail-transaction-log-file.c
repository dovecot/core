/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "file-dotlock.h"
#include "nfs-workarounds.h"
#include "read-full.h"
#include "write-full.h"
#include "mmap-util.h"
#include "mail-index-private.h"
#include "mail-index-modseq.h"
#include "mail-transaction-log-private.h"

#define LOG_PREFETCH IO_BLOCK_SIZE
#define MEMORY_LOG_NAME "(in-memory transaction log file)"
#define LOG_NEW_DOTLOCK_SUFFIX ".newlock"

static int
mail_transaction_log_file_sync(struct mail_transaction_log_file *file,
			       bool *retry_r, const char **reason_r);

static void
log_file_set_syscall_error(struct mail_transaction_log_file *file,
			   const char *function)
{
	mail_index_file_set_syscall_error(file->log->index,
					  file->filepath, function);
}

static void
mail_transaction_log_mark_corrupted(struct mail_transaction_log_file *file)
{
	unsigned int offset =
		offsetof(struct mail_transaction_log_header, indexid);
	int flags;

	if (MAIL_TRANSACTION_LOG_FILE_IN_MEMORY(file) ||
	    file->log->index->readonly)
		return;

	/* indexid=0 marks the log file as corrupted. we opened the file with
	   O_APPEND, and now we need to drop it for pwrite() to work (at least
	   in Linux) */
	flags = fcntl(file->fd, F_GETFL, 0);
	if (flags < 0) {
		mail_index_file_set_syscall_error(file->log->index,
			file->filepath, "fcntl(F_GETFL)");
		return;
	}
	if (fcntl(file->fd, F_SETFL, flags & ~O_APPEND) < 0) {
		mail_index_file_set_syscall_error(file->log->index,
			file->filepath, "fcntl(F_SETFL)");
		return;
	}
	if (pwrite_full(file->fd, &file->hdr.indexid,
			sizeof(file->hdr.indexid), offset) < 0) {
		mail_index_file_set_syscall_error(file->log->index,
						  file->filepath, "pwrite()");
	}
}

void
mail_transaction_log_file_set_corrupted(struct mail_transaction_log_file *file,
					const char *fmt, ...)
{
	va_list va;

	file->corrupted = TRUE;
	file->hdr.indexid = 0;
	mail_transaction_log_mark_corrupted(file);

	va_start(va, fmt);
	T_BEGIN {
		mail_index_set_error(file->log->index,
			"Corrupted transaction log file %s seq %u: %s "
			"(sync_offset=%"PRIuUOFF_T")",
			file->filepath, file->hdr.file_seq,
			t_strdup_vprintf(fmt, va), file->sync_offset);
	} T_END;
	va_end(va);
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

void mail_transaction_log_file_free(struct mail_transaction_log_file **_file)
{
	struct mail_transaction_log_file *file = *_file;
	struct mail_transaction_log_file **p;
	int old_errno = errno;

	*_file = NULL;

	i_assert(!file->locked);

	for (p = &file->log->files; *p != NULL; p = &(*p)->next) {
		if (*p == file) {
			*p = file->next;
			break;
		}
	}

	if (file == file->log->head)
		file->log->head = NULL;

	buffer_free(&file->buffer);

	if (file->mmap_base != NULL) {
		if (munmap(file->mmap_base, file->mmap_size) < 0)
			log_file_set_syscall_error(file, "munmap()");
	}

	if (file->fd != -1) {
		if (close(file->fd) < 0)
			log_file_set_syscall_error(file, "close()");
	}

	i_free(file->filepath);
	i_free(file->need_rotate);
        i_free(file);

        errno = old_errno;
}

static void
mail_transaction_log_file_skip_to_head(struct mail_transaction_log_file *file)
{
	struct mail_transaction_log *log = file->log;
	struct mail_index_map *map = log->index->map;
	const struct mail_index_modseq_header *modseq_hdr;
	uoff_t head_offset;

	if (map == NULL || file->hdr.file_seq != map->hdr.log_file_seq ||
	    map->hdr.log_file_head_offset == 0)
		return;

	/* we can get a valid log offset from index file. initialize
	   sync_offset from it so we don't have to read the whole log
	   file from beginning. */
	head_offset = map->hdr.log_file_head_offset;

	modseq_hdr = mail_index_map_get_modseq_header(map);
	if (head_offset < file->hdr.hdr_size) {
		mail_index_set_error(log->index,
				     "%s: log_file_head_offset too small",
				     log->index->filepath);
		file->sync_offset = file->hdr.hdr_size;
		file->sync_highest_modseq = file->hdr.initial_modseq;
	} else if (modseq_hdr == NULL && file->hdr.initial_modseq == 0) {
		/* modseqs not used yet */
		file->sync_offset = head_offset;
		file->sync_highest_modseq = 0;
	} else if (modseq_hdr == NULL ||
		   modseq_hdr->log_seq != file->hdr.file_seq) {
		/* highest_modseq not synced, start from beginning */
		file->sync_offset = file->hdr.hdr_size;
		file->sync_highest_modseq = file->hdr.initial_modseq;
	} else if (modseq_hdr->log_offset > head_offset) {
		mail_index_set_error(log->index,
				     "%s: modseq_hdr.log_offset too large",
				     log->index->filepath);
		file->sync_offset = file->hdr.hdr_size;
		file->sync_highest_modseq = file->hdr.initial_modseq;
	} else {
		/* start from where we last stopped tracking modseqs */
		file->sync_offset = modseq_hdr->log_offset;
		file->sync_highest_modseq = modseq_hdr->highest_modseq;
	}
	if (file->hdr.file_seq == log->index->map->hdr.log_file_seq) {
		file->saved_tail_offset =
			log->index->map->hdr.log_file_tail_offset;
		file->saved_tail_sync_offset = file->saved_tail_offset;
	}
	if (file->saved_tail_offset > file->max_tail_offset)
		file->max_tail_offset = file->saved_tail_offset;
}

static void
mail_transaction_log_file_add_to_list(struct mail_transaction_log_file *file)
{
	struct mail_transaction_log_file **p;
	const char *reason;
	bool retry;

	file->sync_offset = file->hdr.hdr_size;
	file->sync_highest_modseq = file->hdr.initial_modseq;
	mail_transaction_log_file_skip_to_head(file);

	/* insert it to correct position */
	for (p = &file->log->files; *p != NULL; p = &(*p)->next) {
		if ((*p)->hdr.file_seq > file->hdr.file_seq)
			break;
		i_assert((*p)->hdr.file_seq < file->hdr.file_seq);
	}

	file->next = *p;
	*p = file;

	if (file->buffer != NULL) {
		/* if we read any unfinished data, make sure the buffer gets
		   truncated. */
		(void)mail_transaction_log_file_sync(file, &retry, &reason);
		buffer_set_used_size(file->buffer,
				     file->sync_offset - file->buffer_offset);
	}
}

static int
mail_transaction_log_init_hdr(struct mail_transaction_log *log,
			      struct mail_transaction_log_header *hdr)
{
	struct mail_index *index = log->index;
	struct mail_transaction_log_file *file;

	i_assert(index->indexid != 0);

	i_zero(hdr);
	hdr->major_version = MAIL_TRANSACTION_LOG_MAJOR_VERSION;
	hdr->minor_version = MAIL_TRANSACTION_LOG_MINOR_VERSION;
	hdr->hdr_size = sizeof(struct mail_transaction_log_header);
	hdr->indexid = log->index->indexid;
	hdr->create_stamp = ioloop_time;
#ifndef WORDS_BIGENDIAN
	hdr->compat_flags |= MAIL_INDEX_COMPAT_LITTLE_ENDIAN;
#endif

	if (index->fd != -1) {
		/* not creating index - make sure we have latest header */
		if (!index->mapping) {
			if (mail_index_map(index,
					   MAIL_INDEX_SYNC_HANDLER_HEAD) <= 0)
				return -1;
		} else {
			/* if we got here from mapping, the .log file is
			   corrupted. use whatever values we got from index
			   file */
		}
	}
	if (index->map != NULL) {
		hdr->prev_file_seq = index->map->hdr.log_file_seq;
		hdr->prev_file_offset = index->map->hdr.log_file_head_offset;
		hdr->file_seq = index->map->hdr.log_file_seq + 1;
		hdr->initial_modseq =
			mail_index_map_modseq_get_highest(index->map);
	} else {
		hdr->file_seq = 1;
	}
	if (hdr->initial_modseq == 0) {
		/* modseq tracking in log files is required for many reasons
		   nowadays, even if per-message modseqs aren't enabled in
		   dovecot.index. */
		hdr->initial_modseq = 1;
	}

	if (log->head != NULL) {
		/* make sure the sequence always increases to avoid crashes
		   later. this catches the buggy case where two processes
		   happen to replace the same log file. */
		for (file = log->head->next; file != NULL; file = file->next) {
			if (hdr->file_seq <= file->hdr.file_seq)
				hdr->file_seq = file->hdr.file_seq + 1;
		}

		if (hdr->file_seq <= log->head->hdr.file_seq) {
			/* make sure the sequence grows */
			hdr->file_seq = log->head->hdr.file_seq+1;
		}
		if (hdr->initial_modseq < log->head->sync_highest_modseq) {
			/* this should be always up-to-date */
			hdr->initial_modseq = log->head->sync_highest_modseq;
		}
	}
	return 0;
}

struct mail_transaction_log_file *
mail_transaction_log_file_alloc_in_memory(struct mail_transaction_log *log)
{
	struct mail_transaction_log_file *file;

	file = mail_transaction_log_file_alloc(log, MEMORY_LOG_NAME);
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
	struct dotlock_settings dotlock_set;
	int ret;

	if (file->log->dotlock_count > 0)
		ret = 1;
	else {
		mail_transaction_log_get_dotlock_set(file->log, &dotlock_set);
		ret = file_dotlock_create(&dotlock_set, file->filepath, 0,
					  &file->log->dotlock);
	}
	if (ret > 0) {
		file->log->dotlock_count++;
		file->locked = TRUE;
		file->lock_created = time(NULL);
		return 0;
	}
	if (ret < 0) {
		log_file_set_syscall_error(file, "file_dotlock_create()");
		return -1;
	}

	mail_index_set_error(file->log->index,
			     "Timeout (%us) while waiting for "
			     "dotlock for transaction log file %s",
			     dotlock_set.timeout, file->filepath);
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
		log_file_set_syscall_error(file, "file_dotlock_delete()");
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
	unsigned int lock_timeout_secs;
	int ret;

	if (file->locked)
		return 0;

	if (MAIL_TRANSACTION_LOG_FILE_IN_MEMORY(file)) {
		file->locked = TRUE;
		return 0;
	}

	if (file->log->index->lock_method == FILE_LOCK_METHOD_DOTLOCK)
		return mail_transaction_log_file_dotlock(file);

	if (file->log->index->readonly) {
		mail_index_set_error(file->log->index,
			"Index is read-only, can't write-lock %s",
			file->filepath);
		return -1;
	}

	i_assert(file->file_lock == NULL);
	lock_timeout_secs = I_MIN(MAIL_TRANSACTION_LOG_LOCK_TIMEOUT,
				  file->log->index->max_lock_timeout_secs);
	ret = mail_index_lock_fd(file->log->index, file->filepath, file->fd,
				 F_WRLCK, lock_timeout_secs,
				 &file->file_lock);
	if (ret > 0) {
		file->locked = TRUE;
		file->lock_created = time(NULL);
		return 0;
	}
	if (ret < 0) {
		log_file_set_syscall_error(file, "mail_index_wait_lock_fd()");
		return -1;
	}

	mail_index_set_error(file->log->index,
		"Timeout (%us) while waiting for lock for "
		"transaction log file %s%s",
		lock_timeout_secs, file->filepath,
		file_lock_find(file->fd, file->log->index->lock_method, F_WRLCK));
	file->log->index->index_lock_timeout = TRUE;
	return -1;
}

void mail_transaction_log_file_unlock(struct mail_transaction_log_file *file,
				      const char *lock_reason)
{
	unsigned int lock_time;

	if (!file->locked)
		return;

	file->locked = FALSE;
	file->locked_sync_offset_updated = FALSE;

	if (MAIL_TRANSACTION_LOG_FILE_IN_MEMORY(file))
		return;

	lock_time = time(NULL) - file->lock_created;
	if (lock_time >= MAIL_TRANSACTION_LOG_LOCK_WARN_SECS && lock_reason != NULL) {
		i_warning("Transaction log file %s was locked for %u seconds (%s)",
			  file->filepath, lock_time, lock_reason);
	}

	if (file->log->index->lock_method == FILE_LOCK_METHOD_DOTLOCK) {
		(void)mail_transaction_log_file_undotlock(file);
		return;
	}

	file_unlock(&file->file_lock);
}

static ssize_t
mail_transaction_log_file_read_header(struct mail_transaction_log_file *file)
{
	void *dest;
	size_t pos, dest_size;
	ssize_t ret;

	i_assert(file->buffer == NULL && file->mmap_base == NULL);

	i_zero(&file->hdr);
	if (file->last_size < mmap_get_page_size() && file->last_size > 0) {
		/* just read the entire transaction log to memory.
		   note that if some of the data hasn't been fully committed
		   yet (hdr.size=0), the buffer must be truncated later */
		file->buffer = buffer_create_dynamic(default_pool, 4096);
		file->buffer_offset = 0;
		dest_size = file->last_size;
		dest = buffer_append_space_unsafe(file->buffer, dest_size);
	} else {
		/* read only the header */
		dest = &file->hdr;
		dest_size = sizeof(file->hdr);
	}

	/* it's not necessarily an error to read less than wanted header size,
	   since older versions of the log format used smaller headers. */
        pos = 0;
	do {
		ret = pread(file->fd, PTR_OFFSET(dest, pos),
			    dest_size - pos, pos);
		if (ret > 0)
			pos += ret;
	} while (ret > 0 && pos < dest_size);

	if (file->buffer != NULL) {
		buffer_set_used_size(file->buffer, pos);
		memcpy(&file->hdr, file->buffer->data,
		       I_MIN(pos, sizeof(file->hdr)));
	}

	return ret < 0 ? -1 : (ssize_t)pos;
}

static int
mail_transaction_log_file_fail_dupe(struct mail_transaction_log_file *file)
{
	int ret;

	/* mark the old file corrupted. we can't safely remove
	   it from the list however, so return failure. */
	file->hdr.indexid = 0;
	if (strcmp(file->filepath, file->log->head->filepath) != 0) {
		/* only mark .2 corrupted, just to make sure we don't lose any
		   changes from .log in case we're somehow wrong */
		mail_transaction_log_mark_corrupted(file);
		ret = 0;
	} else {
		ret = -1;
	}
	if (!file->corrupted) {
		file->corrupted = TRUE;
		mail_index_set_error(file->log->index,
				     "Transaction log %s: "
				     "duplicate transaction log sequence (%u)",
				     file->filepath, file->hdr.file_seq);
	}
	return ret;
}

static int
mail_transaction_log_file_read_hdr(struct mail_transaction_log_file *file,
				   bool ignore_estale)
{
        struct mail_transaction_log_file *f;
	int ret;

	i_assert(!MAIL_TRANSACTION_LOG_FILE_IN_MEMORY(file));

	if (file->corrupted)
		return 0;

	ret = mail_transaction_log_file_read_header(file);
	if (ret < 0) {
                if (errno != ESTALE || !ignore_estale)
			log_file_set_syscall_error(file, "pread()");
		return -1;
	}
	if (file->hdr.major_version != MAIL_TRANSACTION_LOG_MAJOR_VERSION) {
		/* incompatible version - fix silently */
		return 0;
	}
	if (ret < MAIL_TRANSACTION_LOG_HEADER_MIN_SIZE) {
		mail_transaction_log_file_set_corrupted(file,
			"unexpected end of file while reading header");
		return 0;
	}

	const unsigned int hdr_version =
		MAIL_TRANSACTION_LOG_HDR_VERSION(&file->hdr);
	if (MAIL_TRANSACTION_LOG_VERSION_HAVE(hdr_version, COMPAT_FLAGS)) {
		/* we have compatibility flags */
		enum mail_index_header_compat_flags compat_flags = 0;

#ifndef WORDS_BIGENDIAN
		compat_flags |= MAIL_INDEX_COMPAT_LITTLE_ENDIAN;
#endif
		if (file->hdr.compat_flags != compat_flags) {
			/* architecture change */
			mail_index_set_error(file->log->index,
					     "Rebuilding index file %s: "
					     "CPU architecture changed",
					     file->log->index->filepath);
			return 0;
		}
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
		file->corrupted = TRUE;
		mail_index_set_error(file->log->index,
			"Transaction log file %s: marked corrupted",
			file->filepath);
		return 0;
	}
	if (file->hdr.indexid != file->log->index->indexid) {
		if (file->log->index->indexid != 0 &&
		    !file->log->index->initial_create) {
			/* index file was probably just rebuilt and we don't
			   know about it yet */
			mail_transaction_log_file_set_corrupted(file,
				"indexid changed: %u -> %u",
				file->log->index->indexid, file->hdr.indexid);
			return 0;
		}

		/* creating index file. since transaction log is created
		   first, use the indexid in it to create the main index
		   to avoid races. */
		file->log->index->indexid = file->hdr.indexid;
	}

	/* make sure we already don't have a file with the same sequence
	   opened. it shouldn't happen unless the old log file was
	   corrupted. */
	for (f = file->log->files; f != NULL; f = f->next) {
		if (f->hdr.file_seq == file->hdr.file_seq) {
			if (strcmp(f->filepath, f->log->head->filepath) != 0) {
				/* old "f" is the .log.2 */
				return mail_transaction_log_file_fail_dupe(f);
			} else {
				/* new "file" is probably the .log.2 */
				return mail_transaction_log_file_fail_dupe(file);
			}
		}
	}

	file->sync_highest_modseq = file->hdr.initial_modseq;
	return 1;
}

static int
mail_transaction_log_file_stat(struct mail_transaction_log_file *file,
			       bool ignore_estale)
{
	struct stat st;

	if (fstat(file->fd, &st) < 0) {
                if (!ESTALE_FSTAT(errno) || !ignore_estale)
			log_file_set_syscall_error(file, "fstat()");
		return -1;
	}

	file->st_dev = st.st_dev;
	file->st_ino = st.st_ino;
	file->last_mtime = st.st_mtime;
	file->last_size = st.st_size;
	return 0;
}

static bool
mail_transaction_log_file_is_dupe(struct mail_transaction_log_file *file)
{
	struct mail_transaction_log_file *tmp;

	for (tmp = file->log->files; tmp != NULL; tmp = tmp->next) {
		if (tmp->st_ino == file->st_ino &&
		    CMP_DEV_T(tmp->st_dev, file->st_dev))
			return TRUE;
	}
	return FALSE;
}

static void log_write_ext_hdr_init_data(struct mail_index *index, buffer_t *buf)
{
	const struct mail_index_registered_ext *rext;
	struct mail_transaction_header *hdr;
	struct mail_transaction_ext_intro *intro;
	struct mail_transaction_ext_hdr_update *ext_hdr;
	unsigned int hdr_offset;

	rext = array_idx(&index->extensions, index->ext_hdr_init_id);

	/* introduce the extension */
	hdr_offset = buf->used;
	hdr = buffer_append_space_unsafe(buf, sizeof(*hdr));
	hdr->type = MAIL_TRANSACTION_EXT_INTRO;

	intro = buffer_append_space_unsafe(buf, sizeof(*intro));
	intro->ext_id = (uint32_t)-1;
	intro->hdr_size = rext->hdr_size;
	intro->record_size = rext->record_size;
	intro->record_align = rext->record_align;
	intro->name_size = strlen(rext->name);
	buffer_append(buf, rext->name, intro->name_size);
	if (buf->used % 4 != 0)
		buffer_append_zero(buf, 4 - buf->used % 4);

	hdr = buffer_get_space_unsafe(buf, hdr_offset, sizeof(*hdr));
	hdr->size = mail_index_uint32_to_offset(buf->used - hdr_offset);

	/* add the extension header data */
	hdr_offset = buf->used;
	hdr = buffer_append_space_unsafe(buf, sizeof(*hdr));
	hdr->type = MAIL_TRANSACTION_EXT_HDR_UPDATE;

	ext_hdr = buffer_append_space_unsafe(buf, sizeof(*ext_hdr));
	ext_hdr->size = rext->hdr_size;
	buffer_append(buf, index->ext_hdr_init_data, rext->hdr_size);

	hdr = buffer_get_space_unsafe(buf, hdr_offset, sizeof(*hdr));
	hdr->size = mail_index_uint32_to_offset(buf->used - hdr_offset);
}

static int
mail_transaction_log_file_create2(struct mail_transaction_log_file *file,
				  int new_fd, bool reset,
				  struct dotlock **dotlock)
{
	struct mail_index *index = file->log->index;
	struct stat st;
	const char *path2;
	buffer_t *writebuf;
	int fd, ret;
	bool rename_existing, need_lock;

	need_lock = file->log->head != NULL && file->log->head->locked;

	if (fcntl(new_fd, F_SETFL, O_APPEND) < 0) {
		log_file_set_syscall_error(file, "fcntl(O_APPEND)");
		return -1;
	}

	if (file->log->nfs_flush) {
		/* although we check also mtime and file size below, it's done
		   only to fix broken log files. we don't bother flushing
		   attribute cache just for that. */
		nfs_flush_file_handle_cache(file->filepath);
	}

	/* log creation is locked now - see if someone already created it.
	   note that if we're rotating, we need to keep the log locked until
	   the file has been rewritten. and because fcntl() locks are stupid,
	   if we go and open()+close() the file and we had it already opened,
	   its locks are lost. so we use stat() to check if the file has been
	   recreated, although it almost never is. */
	if (reset)
		rename_existing = FALSE;
	else if (nfs_safe_stat(file->filepath, &st) < 0) {
		if (errno != ENOENT) {
			log_file_set_syscall_error(file, "stat()");
			return -1;
		}
		rename_existing = FALSE;
	} else if (st.st_ino == file->st_ino &&
		   CMP_DEV_T(st.st_dev, file->st_dev) &&
		   /* inode/dev checks are enough when we're rotating the file,
		      but not when we're replacing a broken log file */
		   st.st_mtime == file->last_mtime &&
		   (uoff_t)st.st_size == file->last_size) {
		/* no-one else recreated the file */
		rename_existing = TRUE;
	} else {
		/* recreated. use the file if its header is ok */
		fd = nfs_safe_open(file->filepath, O_RDWR | O_APPEND);
		if (fd == -1) {
			if (errno != ENOENT) {
				log_file_set_syscall_error(file, "open()");
				return -1;
			}
		} else {
			file->fd = fd;
			file->last_size = 0;
			if (mail_transaction_log_file_read_hdr(file,
							       FALSE) > 0 &&
			    mail_transaction_log_file_stat(file, FALSE) == 0) {
				/* yes, it was ok */
				file_dotlock_delete(dotlock);
				mail_transaction_log_file_add_to_list(file);
				return 0;
			}
			file->fd = -1;
			if (close(fd) < 0)
				log_file_set_syscall_error(file, "close()");
		}
		rename_existing = FALSE;
	}

	if (index->fd == -1 && !rename_existing) {
		/* creating the initial index */
		reset = TRUE;
	}

	if (mail_transaction_log_init_hdr(file->log, &file->hdr) < 0)
		return -1;

	if (reset) {
		/* don't reset modseqs. if we're resetting due to rebuilding
		   indexes we'll probably want to keep uidvalidity and in such
		   cases we really don't want to shrink modseqs. */
		file->hdr.prev_file_seq = 0;
		file->hdr.prev_file_offset = 0;
	}

	writebuf = t_buffer_create(128);
	buffer_append(writebuf, &file->hdr, sizeof(file->hdr));

	if (index->ext_hdr_init_data != NULL && reset)
		log_write_ext_hdr_init_data(index, writebuf);
	if (write_full(new_fd, writebuf->data, writebuf->used) < 0) {
		log_file_set_syscall_error(file, "write_full()");
		return -1;
	}

	if (file->log->index->fsync_mode == FSYNC_MODE_ALWAYS) {
		/* the header isn't important, so don't bother calling
		   fdatasync() unless it's required */
		if (fdatasync(new_fd) < 0) {
			log_file_set_syscall_error(file, "fdatasync()");
			return -1;
		}
	}

	file->fd = new_fd;
	ret = mail_transaction_log_file_stat(file, FALSE);

	if (need_lock && ret == 0) {
		/* we'll need to preserve the lock */
		if (mail_transaction_log_file_lock(file) < 0)
			ret = -1;
	}

	/* if we return -1 the dotlock deletion code closes the fd */
	file->fd = -1;
	if (ret < 0)
		return -1;

	/* keep two log files */
	if (rename_existing) {
		/* rename() would be nice and easy way to do this, except then
		   there's a race condition between the rename and
		   file_dotlock_replace(). during that time the log file
		   doesn't exist, which could cause problems. */
		path2 = t_strconcat(file->filepath, ".2", NULL);
		if (i_unlink_if_exists(path2) < 0) {
			/* try to link() anyway */
		}
		if (nfs_safe_link(file->filepath, path2, FALSE) < 0 &&
		    errno != ENOENT && errno != EEXIST) {
                        mail_index_set_error(index, "link(%s, %s) failed: %m",
					     file->filepath, path2);
			/* ignore the error. we don't care that much about the
			   second log file and we're going to overwrite this
			   first one. */
		}
		/* NOTE: here's a race condition where both .log and .log.2
		   point to the same file. our reading code should ignore that
		   though by comparing the inodes. */
	}

	if (file_dotlock_replace(dotlock,
				 DOTLOCK_REPLACE_FLAG_DONT_CLOSE_FD) <= 0) {
		/* need to unlock to avoid assert-crash in
		   mail_transaction_log_file_free() */
		mail_transaction_log_file_unlock(file, "creation failed");
		return -1;
	}

	/* success */
	file->fd = new_fd;
	mail_transaction_log_file_add_to_list(file);

	i_assert(!need_lock || file->locked);
	return 1;
}

int mail_transaction_log_file_create(struct mail_transaction_log_file *file,
				     bool reset)
{
	struct mail_index *index = file->log->index;
	struct dotlock_settings new_dotlock_set;
	struct dotlock *dotlock;
	mode_t old_mask;
	int fd, ret;

	i_assert(!MAIL_INDEX_IS_IN_MEMORY(index));

	if (file->log->index->readonly) {
		mail_index_set_error(index,
			"Can't create log file %s: Index is read-only",
			file->filepath);
		return -1;
	}

	if (index->indexid == 0) {
		mail_index_set_error(index,
			"Can't create log file %s: Index is marked corrupted",
			file->filepath);
		return -1;
	}

	mail_transaction_log_get_dotlock_set(file->log, &new_dotlock_set);
	new_dotlock_set.lock_suffix = LOG_NEW_DOTLOCK_SUFFIX;

	/* With dotlocking we might already have path.lock created, so this
	   filename has to be different. */
	old_mask = umask(index->mode ^ 0666);
	fd = file_dotlock_open(&new_dotlock_set, file->filepath, 0, &dotlock);
	umask(old_mask);

	if (fd == -1) {
		log_file_set_syscall_error(file, "file_dotlock_open()");
		return -1;
	}
	mail_index_fchown(index, fd, file_dotlock_get_lock_path(dotlock));

        /* either fd gets used or the dotlock gets deleted and returned fd
           is for the existing file */
	ret = mail_transaction_log_file_create2(file, fd, reset, &dotlock);
	if (ret < 0) {
		if (dotlock != NULL)
			file_dotlock_delete(&dotlock);
		return -1;
	}
	return ret;
}

int mail_transaction_log_file_open(struct mail_transaction_log_file *file,
				   const char **reason_r)
{
	struct mail_index *index = file->log->index;
        unsigned int i;
	bool ignore_estale;
	int ret;

        for (i = 0;; i++) {
		if (!index->readonly) {
			file->fd = nfs_safe_open(file->filepath,
						 O_RDWR | O_APPEND);
		} else {
			file->fd = nfs_safe_open(file->filepath, O_RDONLY);
		}
		if (file->fd == -1 && errno == EACCES) {
			file->fd = nfs_safe_open(file->filepath, O_RDONLY);
			index->readonly = TRUE;
		}
		if (file->fd == -1) {
			if (errno == ENOENT) {
				*reason_r = "File doesn't exist";
				return 0;
			}

			log_file_set_syscall_error(file, "open()");
			*reason_r = t_strdup_printf("open() failed: %m");
			return -1;
                }

		ignore_estale = i < MAIL_INDEX_ESTALE_RETRY_COUNT;
		if (mail_transaction_log_file_stat(file, ignore_estale) < 0)
			ret = -1;
		else if (mail_transaction_log_file_is_dupe(file)) {
			/* probably our already opened .log file has been
			   renamed to .log.2 and we're trying to reopen it.
			   also possible that hit a race condition where .log
			   and .log.2 are linked. */
			*reason_r = "File is already open";
			return 0;
		} else {
			ret = mail_transaction_log_file_read_hdr(file,
								 ignore_estale);
		}
		if (ret > 0) {
			/* success */
			break;
		}

		if (ret == 0) {
			/* corrupted */
			if (index->readonly) {
				/* don't delete */
			} else {
				i_unlink_if_exists(file->filepath);
			}
			*reason_r = "File is corrupted";
			return 0;
		}
		if (errno != ESTALE ||
		    i == MAIL_INDEX_ESTALE_RETRY_COUNT) {
			/* syscall error */
			*reason_r = t_strdup_printf("fstat() failed: %m");
			return -1;
		}

		/* ESTALE - try again */
		buffer_free(&file->buffer);
        }

	mail_transaction_log_file_add_to_list(file);
	return 1;
}

static int
log_file_track_mailbox_sync_offset_hdr(struct mail_transaction_log_file *file,
				       const void *data, unsigned int trans_size,
				       const char **error_r)
{
	const struct mail_transaction_header_update *u = data;
	const struct mail_index_header *ihdr;
	const unsigned int size = trans_size - sizeof(struct mail_transaction_header);
	const unsigned int offset_pos =
		offsetof(struct mail_index_header, log_file_tail_offset);
	const unsigned int offset_size = sizeof(ihdr->log_file_tail_offset);
	uint32_t tail_offset;

	i_assert(offset_size == sizeof(tail_offset));

	if (size < sizeof(*u) || size < sizeof(*u) + u->size) {
		*error_r = "header update extends beyond record size";
		mail_transaction_log_file_set_corrupted(file, "%s", *error_r);
		return -1;
	}

	if (u->offset <= offset_pos &&
	    u->offset + u->size >= offset_pos + offset_size) {
		memcpy(&tail_offset,
		       CONST_PTR_OFFSET(u + 1, offset_pos - u->offset),
		       sizeof(tail_offset));

		if (tail_offset < file->saved_tail_offset) {
			/* ignore shrinking tail offsets */
			return 1;
		} else if (tail_offset > file->sync_offset + trans_size) {
			mail_transaction_log_file_set_corrupted(file,
				"log_file_tail_offset %u goes past sync offset %"PRIuUOFF_T,
				tail_offset, file->sync_offset + trans_size);
		} else {
			file->saved_tail_offset = tail_offset;
			if (tail_offset > file->max_tail_offset)
				file->max_tail_offset = tail_offset;
			return 1;
		}
	}
	return 0;
}

static bool
flag_updates_have_non_internal(const struct mail_transaction_flag_update *u,
			       unsigned int count, unsigned int version)
{
	/* Hide internal flags from modseqs if the log file's version
	   is new enough. This allows upgrading without the modseqs suddenly
	   shrinking. */
	if (!MAIL_TRANSACTION_LOG_VERSION_HAVE(version, HIDE_INTERNAL_MODSEQS))
		return TRUE;

	for (unsigned int i = 0; i < count; i++) {
		if (!MAIL_TRANSACTION_FLAG_UPDATE_IS_INTERNAL(&u[i]))
			return TRUE;
	}
	return FALSE;
}

void mail_transaction_update_modseq(const struct mail_transaction_header *hdr,
				    const void *data, uint64_t *cur_modseq,
				    unsigned int version)
{
	uint32_t trans_size;

	trans_size = mail_index_offset_to_uint32(hdr->size);
	i_assert(trans_size != 0);

	if (*cur_modseq != 0) {
		/* tracking modseqs */
	} else if ((hdr->type & MAIL_TRANSACTION_TYPE_MASK) ==
		   MAIL_TRANSACTION_EXT_INTRO) {
		/* modseqs not tracked yet. see if this is a modseq
		   extension introduction. */
		const struct mail_transaction_ext_intro *intro = data;
		const unsigned int modseq_ext_len =
			strlen(MAIL_INDEX_MODSEQ_EXT_NAME);

		if (intro->name_size == modseq_ext_len &&
		    memcmp(intro + 1, MAIL_INDEX_MODSEQ_EXT_NAME,
			   modseq_ext_len) == 0) {
			/* modseq tracking started */
			*cur_modseq += 1;
		}
		return;
	} else {
		/* not tracking modseqs */
		return;
	}

	/* NOTE: keep in sync with mail_index_transaction_get_highest_modseq() */
	switch (hdr->type & MAIL_TRANSACTION_TYPE_MASK) {
	case MAIL_TRANSACTION_EXPUNGE | MAIL_TRANSACTION_EXPUNGE_PROT:
	case MAIL_TRANSACTION_EXPUNGE_GUID | MAIL_TRANSACTION_EXPUNGE_PROT:
		if ((hdr->type & MAIL_TRANSACTION_EXTERNAL) == 0) {
			/* ignore expunge requests */
			break;
		}
		/* fall through */
	case MAIL_TRANSACTION_APPEND:
	case MAIL_TRANSACTION_KEYWORD_UPDATE:
	case MAIL_TRANSACTION_KEYWORD_RESET:
	case MAIL_TRANSACTION_ATTRIBUTE_UPDATE:
		/* these changes increase modseq */
		*cur_modseq += 1;
		break;
	case MAIL_TRANSACTION_FLAG_UPDATE: {
		const struct mail_transaction_flag_update *rec = data;
		unsigned int count;

		count = (trans_size - sizeof(*hdr)) / sizeof(*rec);
		if (flag_updates_have_non_internal(rec, count, version))
			*cur_modseq += 1;
		break;
	}
	case MAIL_TRANSACTION_MODSEQ_UPDATE: {
		const struct mail_transaction_modseq_update *rec, *end;

		end = CONST_PTR_OFFSET(data, trans_size - sizeof(*hdr));
		for (rec = data; rec < end; rec++) {
			uint64_t modseq = ((uint64_t)rec->modseq_high32 << 32) |
				rec->modseq_low32;
			if (*cur_modseq < modseq)
				*cur_modseq = modseq;
		}
	}
	}
}

static struct modseq_cache *
modseq_cache_hit(struct mail_transaction_log_file *file, unsigned int idx)
{
	struct modseq_cache cache;

	if (idx > 0) {
		/* @UNSAFE: move it to top */
		cache = file->modseq_cache[idx];
		memmove(file->modseq_cache + 1, file->modseq_cache,
			sizeof(*file->modseq_cache) * idx);
		file->modseq_cache[0] = cache;
	}
	return &file->modseq_cache[0];
}

static struct modseq_cache *
modseq_cache_get_offset(struct mail_transaction_log_file *file, uoff_t offset)
{
	unsigned int i, best = UINT_MAX;

	for (i = 0; i < N_ELEMENTS(file->modseq_cache); i++) {
		if (offset < file->modseq_cache[i].offset)
			continue;

		if (file->modseq_cache[i].offset == 0)
			return NULL;

		if (offset == file->modseq_cache[i].offset) {
			/* exact cache hit */
			return modseq_cache_hit(file, i);
		}

		if (best == UINT_MAX ||
		    file->modseq_cache[i].offset <
		    file->modseq_cache[best].offset)
			best = i;
	}
	if (best == UINT_MAX)
		return NULL;
	return &file->modseq_cache[best];
}

static struct modseq_cache *
modseq_cache_get_modseq(struct mail_transaction_log_file *file, uint64_t modseq)
{
	unsigned int i, best = UINT_MAX;

	for (i = 0; i < N_ELEMENTS(file->modseq_cache); i++) {
		if (modseq < file->modseq_cache[i].highest_modseq)
			continue;

		if (file->modseq_cache[i].offset == 0)
			return NULL;

		if (modseq == file->modseq_cache[i].highest_modseq) {
			/* exact cache hit */
			return modseq_cache_hit(file, i);
		}

		if (best == UINT_MAX ||
		    file->modseq_cache[i].highest_modseq <
		    file->modseq_cache[best].highest_modseq)
			best = i;
	}
	if (best == UINT_MAX)
		return NULL;
	return &file->modseq_cache[best];
}

static int
log_get_synced_record(struct mail_transaction_log_file *file, uoff_t *offset,
		      const struct mail_transaction_header **hdr_r,
		      const char **error_r)
{
	const struct mail_transaction_header *hdr;
	uint32_t trans_size;

	hdr = CONST_PTR_OFFSET(file->buffer->data,
			       *offset - file->buffer_offset);

	/* we've already synced this record at some point. it should
	   be valid. */
	trans_size = mail_index_offset_to_uint32(hdr->size);
	if (trans_size < sizeof(*hdr) ||
	    *offset - file->buffer_offset + trans_size > file->buffer->used) {
		*error_r = t_strdup_printf(
			"Transaction log corrupted unexpectedly at "
			"%"PRIuUOFF_T": Invalid size %u (type=%x)",
			*offset, trans_size, hdr->type);
		mail_transaction_log_file_set_corrupted(file, "%s", *error_r);
		return -1;
	}
	*offset += trans_size;
	*hdr_r = hdr;
	return 0;
}

int mail_transaction_log_file_get_highest_modseq_at(
		struct mail_transaction_log_file *file,
		uoff_t offset, uint64_t *highest_modseq_r,
		const char **error_r)
{
	const struct mail_transaction_header *hdr;
	struct modseq_cache *cache;
	uoff_t cur_offset;
	uint64_t cur_modseq;
	const char *reason;
	int ret;

	i_assert(offset <= file->sync_offset);

	if (offset == file->sync_offset) {
		*highest_modseq_r = file->sync_highest_modseq;
		return 0;
	}

	cache = modseq_cache_get_offset(file, offset);
	if (cache == NULL) {
		/* nothing usable in cache - scan from beginning */
		cur_offset = file->hdr.hdr_size;
		cur_modseq = file->hdr.initial_modseq;
	} else if (cache->offset == offset) {
		/* exact cache hit */
		*highest_modseq_r = cache->highest_modseq;
		return 0;
	} else {
		/* use cache to skip over some records */
		cur_offset = cache->offset;
		cur_modseq = cache->highest_modseq;
	}

	ret = mail_transaction_log_file_map(file, cur_offset, offset, &reason);
	if (ret <= 0) {
		*error_r = t_strdup_printf(
			"Failed to map transaction log %s for getting modseq "
			"at offset=%"PRIuUOFF_T" with start_offset=%"PRIuUOFF_T": %s",
			file->filepath, offset, cur_offset, reason);
		return -1;
	}

	i_assert(cur_offset >= file->buffer_offset);
	i_assert(cur_offset + file->buffer->used >= offset);
	while (cur_offset < offset) {
		if (log_get_synced_record(file, &cur_offset, &hdr, error_r) < 0)
			return- 1;
		mail_transaction_update_modseq(hdr, hdr + 1, &cur_modseq,
			MAIL_TRANSACTION_LOG_HDR_VERSION(&file->hdr));
	}

	/* @UNSAFE: cache the value */
	memmove(file->modseq_cache + 1, file->modseq_cache,
		sizeof(*file->modseq_cache) *
		(N_ELEMENTS(file->modseq_cache) - 1));
	file->modseq_cache[0].offset = cur_offset;
	file->modseq_cache[0].highest_modseq = cur_modseq;

	*highest_modseq_r = cur_modseq;
	return 0;
}

static int
get_modseq_next_offset_at(struct mail_transaction_log_file *file,
			  uint64_t modseq, bool use_highest,
			  uoff_t *cur_offset, uint64_t *cur_modseq,
			  uoff_t *next_offset_r)
{
	const struct mail_transaction_header *hdr;
	const char *reason;
	int ret;

	/* make sure we've read until end of file. this is especially important
	   with non-head logs which might only have been opened without being
	   synced. */
	ret = mail_transaction_log_file_map(file, *cur_offset, (uoff_t)-1, &reason);
	if (ret <= 0) {
		mail_index_set_error(file->log->index,
			"Failed to map transaction log %s for getting offset "
			"for modseq=%"PRIu64" with start_offset=%"PRIuUOFF_T": %s",
			file->filepath, modseq, *cur_offset, reason);
		return -1;
	}

	/* check sync_highest_modseq again in case sync_offset was updated */
	if (modseq >= file->sync_highest_modseq && use_highest) {
		*next_offset_r = file->sync_offset;
		return 0;
	}

	i_assert(*cur_offset >= file->buffer_offset);
	while (*cur_offset < file->sync_offset) {
		if (log_get_synced_record(file, cur_offset, &hdr, &reason) < 0) {
			mail_index_set_error(file->log->index,
				"%s: %s", file->filepath, reason);
			return -1;
		}
		mail_transaction_update_modseq(hdr, hdr + 1, cur_modseq,
			MAIL_TRANSACTION_LOG_HDR_VERSION(&file->hdr));
		if (*cur_modseq >= modseq)
			break;
	}
	return 1;
}

int mail_transaction_log_file_get_modseq_next_offset(
		struct mail_transaction_log_file *file,
		uint64_t modseq, uoff_t *next_offset_r)
{
	struct modseq_cache *cache;
	uoff_t cur_offset;
	uint64_t cur_modseq;
	int ret;

	if (modseq == file->sync_highest_modseq) {
		*next_offset_r = file->sync_offset;
		return 0;
	}
	if (modseq == file->hdr.initial_modseq) {
		*next_offset_r = file->hdr.hdr_size;
		return 0;
	}

	cache = modseq_cache_get_modseq(file, modseq);
	if (cache == NULL) {
		/* nothing usable in cache - scan from beginning */
		cur_offset = file->hdr.hdr_size;
		cur_modseq = file->hdr.initial_modseq;
	} else if (cache->highest_modseq == modseq) {
		/* exact cache hit */
		*next_offset_r = cache->offset;
		return 0;
	} else {
		/* use cache to skip over some records */
		cur_offset = cache->offset;
		cur_modseq = cache->highest_modseq;
	}

	if ((ret = get_modseq_next_offset_at(file, modseq, TRUE, &cur_offset,
					     &cur_modseq, next_offset_r)) <= 0)
		return ret;
	if (cur_offset == file->sync_offset) {
		/* if we got to sync_offset, cur_modseq should be
		   sync_highest_modseq */
		mail_index_set_error(file->log->index,
			"%s: Transaction log modseq tracking is corrupted - fixing",
			file->filepath);
		/* retry getting the offset by reading from the beginning
		   of the file */
		cur_offset = file->hdr.hdr_size;
		cur_modseq = file->hdr.initial_modseq;
		ret = get_modseq_next_offset_at(file, modseq, FALSE,
						&cur_offset, &cur_modseq,
						next_offset_r);
		if (ret < 0)
			return -1;
		i_assert(ret != 0);
		/* get it fixed on the next sync */
		if (file->log->index->need_recreate == NULL) {
			file->log->index->need_recreate =
				i_strdup("modseq tracking is corrupted");
		}
		if (file->need_rotate == NULL) {
			file->need_rotate =
				i_strdup("modseq tracking is corrupted");
		}
		/* clear cache, since it's unreliable */
		memset(file->modseq_cache, 0, sizeof(file->modseq_cache));
	}

	/* @UNSAFE: cache the value */
	memmove(file->modseq_cache + 1, file->modseq_cache,
		sizeof(*file->modseq_cache) *
		(N_ELEMENTS(file->modseq_cache) - 1));
	file->modseq_cache[0].offset = cur_offset;
	file->modseq_cache[0].highest_modseq = cur_modseq;

	*next_offset_r = cur_offset;
	return 0;
}

static int
log_file_track_sync(struct mail_transaction_log_file *file,
		    const struct mail_transaction_header *hdr,
		    unsigned int trans_size, const char **error_r)
{
	const void *data = hdr + 1;
	int ret;

	mail_transaction_update_modseq(hdr, hdr + 1, &file->sync_highest_modseq,
		MAIL_TRANSACTION_LOG_HDR_VERSION(&file->hdr));
	if ((hdr->type & MAIL_TRANSACTION_EXTERNAL) == 0)
		return 1;

	/* external transactions: */
	switch (hdr->type & MAIL_TRANSACTION_TYPE_MASK) {
	case MAIL_TRANSACTION_HEADER_UPDATE:
		/* see if this updates mailbox_sync_offset */
		ret = log_file_track_mailbox_sync_offset_hdr(file, data,
							     trans_size, error_r);
		if (ret != 0)
			return ret < 0 ? -1 : 1;
		break;
	case MAIL_TRANSACTION_INDEX_DELETED:
		if (file->sync_offset < file->index_undeleted_offset)
			break;
		file->log->index->index_deleted = TRUE;
		file->log->index->index_delete_requested = FALSE;
		file->index_deleted_offset = file->sync_offset + trans_size;
		break;
	case MAIL_TRANSACTION_INDEX_UNDELETED:
		if (file->sync_offset < file->index_deleted_offset)
			break;
		file->log->index->index_deleted = FALSE;
		file->log->index->index_delete_requested = FALSE;
		file->index_undeleted_offset = file->sync_offset + trans_size;
		break;
	case MAIL_TRANSACTION_BOUNDARY: {
		const struct mail_transaction_boundary *boundary =
			(const void *)(hdr + 1);
		size_t wanted_buffer_size;

		wanted_buffer_size = file->sync_offset - file->buffer_offset +
			boundary->size;
		if (wanted_buffer_size > file->buffer->used) {
			/* the full transaction hasn't been written yet */
			return 0;
		}
		break;
	}
	}

	if (file->max_tail_offset == file->sync_offset) {
		/* external transactions aren't synced to mailbox. we can
		   update mailbox sync offset to skip this transaction to
		   avoid re-reading it at the next sync. */
		file->max_tail_offset += trans_size;
	}
	return 1;
}

static int
mail_transaction_log_file_sync(struct mail_transaction_log_file *file,
			       bool *retry_r, const char **reason_r)
{
        const struct mail_transaction_header *hdr;
	const void *data;
	struct stat st;
	size_t size, avail;
	uint32_t trans_size = 0;
	int ret;

	i_assert(file->sync_offset >= file->buffer_offset);

	*retry_r = FALSE;

	data = buffer_get_data(file->buffer, &size);
	if (file->buffer_offset + size < file->sync_offset) {
		*reason_r = t_strdup_printf(
			"log file shrank (%"PRIuUOFF_T" < %"PRIuUOFF_T")",
			file->buffer_offset + (uoff_t)size, file->sync_offset);
		mail_transaction_log_file_set_corrupted(file, "%s", *reason_r);
		/* fix the sync_offset to avoid crashes later on */
		file->sync_offset = file->buffer_offset + size;
		return 0;
	}
	while (file->sync_offset - file->buffer_offset + sizeof(*hdr) <= size) {
		hdr = CONST_PTR_OFFSET(data, file->sync_offset -
				       file->buffer_offset);
		trans_size = mail_index_offset_to_uint32(hdr->size);
		if (trans_size == 0) {
			/* unfinished */
			return 1;
		}
		if (trans_size < sizeof(*hdr)) {
			*reason_r = t_strdup_printf(
				"hdr.size too small (%u)", trans_size);
			mail_transaction_log_file_set_corrupted(file, "%s", *reason_r);
			return 0;
		}

		if (file->sync_offset - file->buffer_offset + trans_size > size)
			break;

		/* transaction has been fully written */
		if ((ret = log_file_track_sync(file, hdr, trans_size, reason_r)) <= 0) {
			if (ret < 0)
				return 0;
			break;
		}

		file->sync_offset += trans_size;
	}

	if (file->mmap_base != NULL && !file->locked) {
		/* Now that all the mmaped pages have page faulted, check if
		   the file had changed while doing that. Only after the last
		   page has faulted, the size returned by fstat() can be
		   trusted. Otherwise it might point to a page boundary while
		   the next page is still being written.

		   Without this check we might see partial transactions,
		   sometimes causing "Extension record updated without intro
		   prefix" errors. */
		if (fstat(file->fd, &st) < 0) {
			log_file_set_syscall_error(file, "fstat()");
			*reason_r = t_strdup_printf("fstat() failed: %m");
			return -1;
		}
		if ((uoff_t)st.st_size != file->last_size) {
			file->last_size = st.st_size;
			*retry_r = TRUE;
			*reason_r = "File size changed - retrying";
			return 0;
		}
	}

	avail = file->sync_offset - file->buffer_offset;
	if (avail != size) {
		/* There's more data than we could sync at the moment. If the
		   last record's size wasn't valid, we can't know if it will
		   be updated unless we've locked the log. */
		if (file->locked) {
			*reason_r = "Unexpected garbage at EOF";
			mail_transaction_log_file_set_corrupted(file, "%s", *reason_r);
			return 0;
		}
		/* The size field will be updated soon */
		mail_index_flush_read_cache(file->log->index, file->filepath,
					    file->fd, file->locked);
	}

	if (file->next != NULL &&
	    file->hdr.file_seq == file->next->hdr.prev_file_seq &&
	    file->next->hdr.prev_file_offset != file->sync_offset) {
		*reason_r = t_strdup_printf(
			"Invalid transaction log size "
			"(%"PRIuUOFF_T" vs %u): %s", file->sync_offset,
			file->log->head->hdr.prev_file_offset, file->filepath);
		mail_transaction_log_file_set_corrupted(file, "%s", *reason_r);
		return 0;
	}

	return 1;
}

static int
mail_transaction_log_file_insert_read(struct mail_transaction_log_file *file,
				      uoff_t offset, const char **reason_r)
{
	void *data;
	size_t size;
	ssize_t ret;

	size = file->buffer_offset - offset;
	buffer_copy(file->buffer, size, file->buffer, 0, (size_t)-1);

	data = buffer_get_space_unsafe(file->buffer, 0, size);
	ret = pread_full(file->fd, data, size, offset);
	if (ret > 0) {
		/* success */
		file->buffer_offset -= size;
		return 1;
	}

	/* failure. don't leave ourself to inconsistent state */
	buffer_copy(file->buffer, 0, file->buffer, size, (size_t)-1);
	buffer_set_used_size(file->buffer, file->buffer->used - size);

	if (ret == 0) {
		*reason_r = "file shrank unexpectedly";
		mail_transaction_log_file_set_corrupted(file, "%s", *reason_r);
		return 0;
	} else if (errno == ESTALE) {
		/* log file was deleted in NFS server, fail silently */
		*reason_r = t_strdup_printf("read() failed: %m");
		return 0;
	} else {
		log_file_set_syscall_error(file, "pread()");
		*reason_r = t_strdup_printf("read() failed: %m");
		return -1;
	}
}

static int
mail_transaction_log_file_read_more(struct mail_transaction_log_file *file,
				    const char **reason_r)
{
	void *data;
	size_t size;
	uint32_t read_offset;
	ssize_t ret;

	read_offset = file->buffer_offset + file->buffer->used;

	do {
		data = buffer_append_space_unsafe(file->buffer, LOG_PREFETCH);
		ret = pread(file->fd, data, LOG_PREFETCH, read_offset);
		if (ret > 0)
			read_offset += ret;

		size = read_offset - file->buffer_offset;
		buffer_set_used_size(file->buffer, size);
	} while (ret > 0 || (ret < 0 && errno == EINTR));

	file->last_size = read_offset;

	if (ret < 0) {
		*reason_r = t_strdup_printf("pread() failed: %m");
		if (errno == ESTALE) {
			/* log file was deleted in NFS server, fail silently */
			return 0;
		}
		log_file_set_syscall_error(file, "pread()");
		return -1;
	}
	return 1;
}

static bool
mail_transaction_log_file_need_nfs_flush(struct mail_transaction_log_file *file)
{
	const struct mail_index_header *hdr = &file->log->index->map->hdr;
	uoff_t max_offset = file->last_size;

	if (file->next != NULL &&
	    file->hdr.file_seq == file->next->hdr.prev_file_seq &&
	    file->next->hdr.prev_file_offset != max_offset) {
		/* we already have a newer log file which says that we haven't
		   synced the entire file. */
		return TRUE;
	}

	if (file->hdr.file_seq == hdr->log_file_seq &&
	    max_offset < hdr->log_file_head_offset)
		return TRUE;

	return FALSE;
}

static int
mail_transaction_log_file_read(struct mail_transaction_log_file *file,
			       uoff_t start_offset, bool nfs_flush,
			       const char **reason_r)
{
	bool retry;
	int ret;

	i_assert(file->mmap_base == NULL);

	/* NFS: if file isn't locked, we're optimistic that we can read enough
	   data without flushing attribute cache. if after reading we notice
	   that we really should have read more, flush the cache and try again.
	   if file is locked, the attribute cache was already flushed when
	   refreshing the log. */
	if (file->log->nfs_flush && nfs_flush) {
		if (!file->locked)
			nfs_flush_attr_cache_unlocked(file->filepath);
		else
			nfs_flush_attr_cache_fd_locked(file->filepath, file->fd);
	}

	if (file->buffer != NULL && file->buffer_offset > start_offset) {
		/* we have to insert missing data to beginning of buffer */
		ret = mail_transaction_log_file_insert_read(file, start_offset, reason_r);
		if (ret <= 0)
			return ret;
	}

	if (file->buffer == NULL) {
		file->buffer =
			buffer_create_dynamic(default_pool, LOG_PREFETCH);
		file->buffer_offset = start_offset;
	}

	if ((ret = mail_transaction_log_file_read_more(file, reason_r)) <= 0)
		;
	else if (file->log->nfs_flush && !nfs_flush &&
		 mail_transaction_log_file_need_nfs_flush(file)) {
		/* we didn't read enough data. flush and try again. */
		return mail_transaction_log_file_read(file, start_offset, TRUE, reason_r);
	} else if ((ret = mail_transaction_log_file_sync(file, &retry, reason_r)) == 0) {
		i_assert(!retry); /* retry happens only with mmap */
	}
	i_assert(file->sync_offset >= file->buffer_offset);
	buffer_set_used_size(file->buffer,
			     file->sync_offset - file->buffer_offset);
	return ret;
}

static bool
log_file_map_check_offsets(struct mail_transaction_log_file *file,
			   uoff_t start_offset, uoff_t end_offset,
			   const char **reason_r)
{
	struct stat st, st2;

	if (start_offset > file->sync_offset) {
		/* broken start offset */
		if (MAIL_TRANSACTION_LOG_FILE_IN_MEMORY(file)) {
			*reason_r = t_strdup_printf(
				"%s: start_offset (%"PRIuUOFF_T") > "
				"current sync_offset (%"PRIuUOFF_T")",
				file->filepath, start_offset, file->sync_offset);
			return FALSE;
		}

		if (fstat(file->fd, &st) < 0) {
			log_file_set_syscall_error(file, "fstat()");
			st.st_size = -1;
		}
		*reason_r = t_strdup_printf(
			"%s: start_offset (%"PRIuUOFF_T") > "
			"current sync_offset (%"PRIuUOFF_T"), file size=%"PRIuUOFF_T,
			file->filepath, start_offset, file->sync_offset,
			st.st_size);
		if (stat(file->filepath, &st2) == 0) {
			if (st.st_ino != st2.st_ino) {
				*reason_r = t_strdup_printf(
					"%s, file unexpectedly replaced", *reason_r);
			}
		} else if (errno == ENOENT) {
			*reason_r = t_strdup_printf(
				"%s, file unexpectedly deleted", *reason_r);
		} else {
			log_file_set_syscall_error(file, "stat()");
		}
		return FALSE;
	}
	if (end_offset != (uoff_t)-1 && end_offset > file->sync_offset) {
		*reason_r = t_strdup_printf(
			"%s: end_offset (%"PRIuUOFF_T") > "
			"current sync_offset (%"PRIuUOFF_T")",
			file->filepath, start_offset, file->sync_offset);
		return FALSE;
	}

	return TRUE;
}

static int
mail_transaction_log_file_mmap(struct mail_transaction_log_file *file,
			       const char **reason_r)
{
	/* we may have switched to mmaping */
	buffer_free(&file->buffer);

	file->mmap_size = file->last_size;
	file->mmap_base = mmap(NULL, file->mmap_size, PROT_READ, MAP_SHARED,
			       file->fd, 0);
	if (file->mmap_base == MAP_FAILED) {
		file->mmap_base = NULL;
		if (ioloop_time != file->last_mmap_error_time) {
			file->last_mmap_error_time = ioloop_time;
			log_file_set_syscall_error(file, t_strdup_printf(
				"mmap(size=%zu)", file->mmap_size));
		}
		*reason_r = t_strdup_printf("mmap(size=%zu) failed: %m",
					    file->mmap_size);
		file->mmap_size = 0;
		return -1;
	}

	if (file->mmap_size > mmap_get_page_size()) {
		if (madvise(file->mmap_base, file->mmap_size,
			    MADV_SEQUENTIAL) < 0)
			log_file_set_syscall_error(file, "madvise()");
	}

	buffer_create_from_const_data(&file->mmap_buffer,
				      file->mmap_base, file->mmap_size);
	file->buffer = &file->mmap_buffer;
	file->buffer_offset = 0;
	return 0;
}

static void
mail_transaction_log_file_munmap(struct mail_transaction_log_file *file)
{
	if (file->mmap_base == NULL)
		return;

	i_assert(file->buffer != NULL);
	if (munmap(file->mmap_base, file->mmap_size) < 0)
		log_file_set_syscall_error(file, "munmap()");
	file->mmap_base = NULL;
	file->mmap_size = 0;
	buffer_free(&file->buffer);
}

static int
mail_transaction_log_file_map_mmap(struct mail_transaction_log_file *file,
				   uoff_t start_offset, const char **reason_r)
{
	struct stat st;
	bool retry;
	int ret;

	/* we are going to mmap() this file, but it's not necessarily
	   mmaped currently. */
	i_assert(file->buffer_offset == 0 || file->mmap_base == NULL);
	i_assert(file->mmap_size == 0 || file->mmap_base != NULL);

	if (fstat(file->fd, &st) < 0) {
		log_file_set_syscall_error(file, "fstat()");
		*reason_r = t_strdup_printf("fstat() failed: %m");
		return -1;
	}
	file->last_size = st.st_size;

	if ((uoff_t)st.st_size < file->sync_offset) {
		*reason_r = t_strdup_printf(
			"file size shrank (%"PRIuUOFF_T" < %"PRIuUOFF_T")",
			(uoff_t)st.st_size, file->sync_offset);
		mail_transaction_log_file_set_corrupted(file, "%s", *reason_r);
		return 0;
	}

	if (file->buffer != NULL && file->buffer_offset <= start_offset &&
	    (uoff_t)st.st_size == file->buffer_offset + file->buffer->used) {
		/* we already have the whole file mapped */
		if ((ret = mail_transaction_log_file_sync(file, &retry, reason_r)) != 0 ||
		    !retry)
			return ret;
		/* size changed, re-mmap */
	}

	do {
		mail_transaction_log_file_munmap(file);

		if (file->last_size - start_offset < mmap_get_page_size()) {
			/* just reading the file is probably faster */
			return mail_transaction_log_file_read(file,
							      start_offset,
							      FALSE, reason_r);
		}

		if (mail_transaction_log_file_mmap(file, reason_r) < 0)
			return -1;
		ret = mail_transaction_log_file_sync(file, &retry, reason_r);
	} while (retry);

	return ret;
}

int mail_transaction_log_file_map(struct mail_transaction_log_file *file,
				  uoff_t start_offset, uoff_t end_offset,
				  const char **reason_r)
{
	uoff_t map_start_offset = start_offset;
	size_t size;
	int ret;

	if (file->hdr.indexid == 0) {
		/* corrupted */
		*reason_r = "corrupted, indexid=0";
		return 0;
	}

	i_assert(start_offset >= file->hdr.hdr_size);
	i_assert(start_offset <= end_offset);
	i_assert(file->buffer == NULL || file->mmap_base != NULL ||
		 file->sync_offset >= file->buffer_offset + file->buffer->used);

	if (file->locked_sync_offset_updated && file == file->log->head &&
	    end_offset == (uoff_t)-1) {
		/* we're not interested of going further than sync_offset */
		if (!log_file_map_check_offsets(file, start_offset,
						end_offset, reason_r))
			return 0;
		i_assert(start_offset <= file->sync_offset);
		end_offset = file->sync_offset;
	}

	if (file->buffer != NULL && file->buffer_offset <= start_offset) {
		/* see if we already have it */
		size = file->buffer->used;
		if (file->buffer_offset + size >= end_offset)
			return 1;
	}

	if (file->locked) {
		/* set this only when we've synced to end of file while locked
		   (either end_offset=(uoff_t)-1 or we had to read anyway) */
		file->locked_sync_offset_updated = TRUE;
	}

	if (MAIL_TRANSACTION_LOG_FILE_IN_MEMORY(file)) {
		if (start_offset < file->buffer_offset || file->buffer == NULL) {
			/* we had moved the log to memory but failed to read
			   the beginning of the log file */
			*reason_r = "Beginning of the log isn't available";
			return 0;
		}
		return log_file_map_check_offsets(file, start_offset,
						  end_offset, reason_r) ? 1 : 0;
	}

	if (start_offset > file->sync_offset)
		mail_transaction_log_file_skip_to_head(file);
	if (start_offset > file->sync_offset) {
		/* although we could just skip over the unwanted data, we have
		   to sync everything so that modseqs are calculated
		   correctly */
		map_start_offset = file->sync_offset;
	}

	if ((file->log->index->flags & MAIL_INDEX_OPEN_FLAG_MMAP_DISABLE) == 0)
		ret = mail_transaction_log_file_map_mmap(file, map_start_offset, reason_r);
	else {
		mail_transaction_log_file_munmap(file);
		ret = mail_transaction_log_file_read(file, map_start_offset, FALSE, reason_r);
	}

	i_assert(file->buffer == NULL || file->mmap_base != NULL ||
		 file->sync_offset >= file->buffer_offset + file->buffer->used);
	if (ret <= 0)
		return ret;

	i_assert(file->buffer != NULL);
	return log_file_map_check_offsets(file, start_offset, end_offset,
					  reason_r) ? 1 : 0;
}

int mail_transaction_log_file_move_to_memory(struct mail_transaction_log_file *file)
{
	const char *error;
	buffer_t *buf;
	int ret = 0;

	if (MAIL_TRANSACTION_LOG_FILE_IN_MEMORY(file))
		return 0;

	if (file->mmap_base != NULL) {
		/* just copy to memory */
		i_assert(file->buffer_offset == 0);

		buf = buffer_create_dynamic(default_pool, file->mmap_size);
		buffer_append(buf, file->mmap_base, file->mmap_size);
		buffer_free(&file->buffer);
		file->buffer = buf;

		/* and lose the mmap */
		if (munmap(file->mmap_base, file->mmap_size) < 0)
			log_file_set_syscall_error(file, "munmap()");
		file->mmap_base = NULL;
	} else if (file->buffer_offset != 0) {
		/* we don't have the full log in the memory. read it. */
		ret = mail_transaction_log_file_read(file, 0, FALSE, &error);
		if (ret <= 0) {
			mail_index_set_error(file->log->index,
				"%s: Failed to read into memory: %s", file->filepath, error);
		}
	}
	file->last_size = 0;

	if (close(file->fd) < 0)
		log_file_set_syscall_error(file, "close()");
	file->fd = -1;

	i_free(file->filepath);
	file->filepath = i_strdup(file->log->filepath);
	return ret < 0 ? -1 : 0;
}
