/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "file-lock.h"
#include "file-set-size.h"
#include "mmap-util.h"
#include "write-full.h"
#include "mail-index.h"
#include "mail-index-util.h"
#include "mail-modifylog.h"

#include <stddef.h>
#include <stdlib.h>
#include <fcntl.h>

/* Maximum size for modify log (isn't exact) */
#define MAX_MODIFYLOG_SIZE (4096*8)

/* How large chunks to use to grow log file */
#define MODIFYLOG_GROW_SIZE (sizeof(struct modify_log_record) * 128)

#define MODIFY_LOG_INITIAL_SIZE \
	(sizeof(struct modify_log_header) + MODIFYLOG_GROW_SIZE)

#define MODIFYLOG_FILE_POSITION(log, ptr) \
	((size_t) ((char *) (ptr) - (char *) (log)->mmap_base))

/* FIXME: not ANSI-C */
#define IS_PTR_IN_RANGE(ptr, area_ptr, area_size) \
	((char *) (ptr) >= (char *) (area_ptr) && \
	 (char *) (ptr) < (char *) (area_ptr) + (area_size))

struct modify_log_file {
	struct mail_modify_log *log;

	int fd;
	char *filepath;

	void *mmap_base;
	size_t mmap_used_length;
	size_t mmap_full_length;

	struct modify_log_record *last_expunge, *last_flags;
	int last_expunge_external, last_flags_external;

	struct modify_log_header *header;
	uoff_t synced_position;
	unsigned int synced_id;

	unsigned int anon_mmap:1;
	unsigned int modified:1;
	unsigned int second_log:1;
};

struct mail_modify_log {
	struct mail_index *index;

	struct modify_log_record *iterator_end;

	struct modify_log_file file1, file2;
	struct modify_log_file *head, *tail;

	int cache_have_others;
	unsigned int cache_lock_counter;
};

static const struct modify_log_expunge no_expunges = { 0, 0, 0 };

static int modifylog_set_syscall_error(struct modify_log_file *file,
				       const char *function)
{
	i_assert(function != NULL);

	if (ENOSPACE(errno)) {
		file->log->index->nodiskspace = TRUE;
		return FALSE;
	}

	index_set_error(file->log->index,
			"%s failed with modify log file %s: %m",
			function, file->filepath);
	return FALSE;
}

static int modifylog_set_corrupted(struct modify_log_file *file,
				   const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	t_push();

	index_set_error(file->log->index, "Corrupted modify log file %s: %s",
			file->filepath, t_strdup_vprintf(fmt, va));

	t_pop();
	va_end(va);

	/* make sure we don't get back here */
	file->log->index->inconsistent = TRUE;
	(void)unlink(file->filepath);

	return FALSE;
}

static int modifylog_drop_lock(struct modify_log_file *file)
{
	int ret;

	/* revert back to shared lock */
	ret = file_try_lock(file->fd, F_RDLCK);
	if (ret < 0) {
		modifylog_set_syscall_error(file, "file_try_lock()");
		return -1;
	}

	if (ret == 0) {
		/* shouldn't happen */
		index_set_error(file->log->index,
				"file_try_lock(F_WRLCK -> F_RDLCK) "
				"failed with file %s", file->filepath);
		return -1;
	}

	return 1;
}

static int modifylog_file_have_other_users(struct modify_log_file *file,
					   int keep_lock)
{
	int ret;

	if (file->anon_mmap)
		return 0;

	/* try grabbing exclusive lock */
	ret = file_try_lock(file->fd, F_WRLCK);
	if (ret <= 0) {
		if (ret < 0)
			modifylog_set_syscall_error(file, "file_try_lock()");
		return ret < 0 ? -1 : 1;
	}

	if (keep_lock)
		return 0;
	else
		return modifylog_drop_lock(file) < 0 ? -1 : 0;
}

/* returns 1 = yes, 0 = no, -1 = error */
static int modifylog_have_other_users(struct mail_modify_log *log,
				      int keep_lock)
{
	struct modify_log_file *file;
	int ret;

	ret = modifylog_file_have_other_users(log->head, keep_lock);
	if (ret == 0) {
		/* check the other file too */
		file = log->head == &log->file1 ? &log->file2 : &log->file1;

		ret = file->fd == -1 ? 0 :
			modifylog_file_have_other_users(file, FALSE);
		if (keep_lock && ret != 0) {
			if (modifylog_drop_lock(log->head) < 0)
				return -1;
		}
	}

	return ret;
}

static int mmap_update(struct modify_log_file *file, int forced)
{
	struct modify_log_header *hdr;
	unsigned int extra;

	if (file->log->index->mmap_invalidate && file->mmap_base != NULL) {
		if (msync(file->mmap_base, file->mmap_used_length,
			  MS_SYNC | MS_INVALIDATE) < 0)
			return modifylog_set_syscall_error(file, "msync()");
	}

	if (!forced && file->header != NULL &&
	    file->mmap_full_length >= file->header->used_file_size) {
		file->mmap_used_length = file->header->used_file_size;
		debug_mprotect(file->mmap_base, file->mmap_full_length,
			       file->log->index);
		return TRUE;
	}

	i_assert(!file->anon_mmap);

	if (file->mmap_base != NULL) {
		/* make sure we're synced before munmap() */
		if (file->modified &&
		    msync(file->mmap_base, file->mmap_used_length, MS_SYNC) < 0)
			return modifylog_set_syscall_error(file, "msync()");
		file->modified = FALSE;

		if (munmap(file->mmap_base, file->mmap_full_length) < 0)
			modifylog_set_syscall_error(file, "munmap()");
	}

	file->log->iterator_end = NULL;

	file->mmap_used_length = 0;
	file->header = NULL;

	file->last_expunge = NULL;
	file->last_flags = NULL;

	file->mmap_base = mmap_rw_file(file->fd, &file->mmap_full_length);
	if (file->mmap_base == MAP_FAILED) {
		file->mmap_base = NULL;
		return modifylog_set_syscall_error(file, "mmap()");
	}

	if (file->mmap_full_length < sizeof(struct modify_log_header)) {
		index_set_error(file->log->index, "Too small modify log %s",
				file->filepath);
		(void)unlink(file->filepath);
		return FALSE;
	}

	extra = (file->mmap_full_length - sizeof(struct modify_log_header)) %
		sizeof(struct modify_log_record);

	if (extra != 0) {
		/* partial write or corrupted -
		   truncate the file to valid length */
		file->mmap_full_length -= extra;
		if (ftruncate(file->fd, (off_t)file->mmap_full_length) < 0)
			modifylog_set_syscall_error(file, "ftruncate()");
	}

	hdr = file->mmap_base;
	if (hdr->used_file_size > file->mmap_full_length) {
		modifylog_set_corrupted(file,
			"used_file_size larger than real file size "
			"(%"PRIuUOFF_T" vs %"PRIuSIZE_T")",
			hdr->used_file_size, file->mmap_full_length);
		return FALSE;
	}

	if (hdr->used_file_size < sizeof(struct modify_log_header) ||
	    (hdr->used_file_size - sizeof(struct modify_log_header)) %
	    sizeof(struct modify_log_record) != 0) {
		modifylog_set_corrupted(file,
			"Invalid used_file_size in header (%"PRIuUOFF_T")",
			hdr->used_file_size);
		return FALSE;
	}

	file->header = file->mmap_base;
	file->mmap_used_length = hdr->used_file_size;
	debug_mprotect(file->mmap_base, file->mmap_full_length,
		       file->log->index);
	return TRUE;
}

static int mmap_init_update(struct modify_log_file *file)
{
	if (!mmap_update(file, TRUE))
		return FALSE;

	file->synced_id = file->header->sync_id;
	file->synced_position = file->mmap_used_length;
	return TRUE;
}

static struct mail_modify_log *mail_modifylog_new(struct mail_index *index)
{
	struct mail_modify_log *log;

	log = i_new(struct mail_modify_log, 1);
	log->index = index;

	log->file1.fd = -1;
	log->file2.fd = -1;

	log->file1.log = log;
	log->file2.log = log;

	log->file1.filepath = i_strconcat(index->filepath, ".log", NULL);
	log->file2.filepath = i_strconcat(index->filepath, ".log.2", NULL);

	index->modifylog = log;
	return log;
}

static void modifylog_munmap(struct modify_log_file *file)
{
	if (file->anon_mmap) {
		if (munmap_anon(file->mmap_base, file->mmap_full_length) < 0)
			modifylog_set_syscall_error(file, "munmap_anon()");
	} else if (file->mmap_base != NULL) {
		if (munmap(file->mmap_base, file->mmap_full_length) < 0)
			modifylog_set_syscall_error(file, "munmap()");
	}
	file->mmap_base = NULL;
	file->mmap_full_length = 0;
	file->mmap_used_length = 0;
	file->header = NULL;

	file->last_expunge = NULL;
	file->last_flags = NULL;
}

static void modifylog_close_file(struct modify_log_file *file)
{
	modifylog_munmap(file);

	if (file->fd != -1) {
		if (close(file->fd) < 0)
			modifylog_set_syscall_error(file, "close()");
		file->fd = -1;
	}
}

static void mail_modifylog_init_header(struct mail_modify_log *log,
				       struct modify_log_header *hdr)
{
	memset(hdr, 0, sizeof(struct modify_log_header));
	hdr->indexid = log->index->indexid;
	hdr->used_file_size = sizeof(struct modify_log_header);
}

static int mail_modifylog_init_fd(struct modify_log_file *file, int fd)
{
        struct modify_log_header hdr;

        mail_modifylog_init_header(file->log, &hdr);

	if (write_full(fd, &hdr, sizeof(hdr)) < 0)
		return modifylog_set_syscall_error(file, "write_full()");

	if (file_set_size(fd, MODIFY_LOG_INITIAL_SIZE) < 0)
		return modifylog_set_syscall_error(file, "file_set_size()");

	return TRUE;
}

static int modifylog_mark_full(struct modify_log_file *file)
{
	unsigned int sync_id = SYNC_ID_FULL;

	if (file->mmap_base != NULL) {
		file->header->sync_id = SYNC_ID_FULL;

		if (msync(file->mmap_base, sizeof(struct modify_log_header),
			  MS_SYNC) < 0)
			return modifylog_set_syscall_error(file, "msync()");
	} else {
		off_t offset = offsetof(struct modify_log_header, sync_id);

		if (lseek(file->fd, offset, SEEK_SET) < 0)
			return modifylog_set_syscall_error(file, "lseek()");

		if (write_full(file->fd, &sync_id, sizeof(sync_id)) < 0) {
			modifylog_set_syscall_error(file, "write_full()");
			return FALSE;
		}
	}

	return TRUE;
}

/* Returns 1 = ok, 0 = can't lock file, -1 = error */
static int modifylog_reuse_or_create_file(struct modify_log_file *file)
{
	struct mail_index *index = file->log->index;
	int fd, ret;

	if (INDEX_IS_IN_MEMORY(index))
		return -1;

	fd = open(file->filepath, O_RDWR | O_CREAT, 0660);
	if (fd == -1) {
		modifylog_set_syscall_error(file, "open()");
		return -1;
	}

	/* 1) there's race condition between open() and file_try_lock(), so
	      if we can't get a lock it means the other process did
	   2) this function is also called by try_switch_log() which uses
	      this check to make sure it's not locked by others. */
	ret = file_try_lock(fd, F_WRLCK);
	if (ret < 0)
		modifylog_set_syscall_error(file, "file_try_lock()");

	if (ret > 0 && mail_modifylog_init_fd(file, fd)) {
		/* drop back to read lock */
		if (file_try_lock(fd, F_RDLCK) <= 0) {
			modifylog_set_syscall_error(file, "file_try_lock()");
			ret = -1;
		}

		if (ret > 0) {
			file->fd = fd;
			return 1;
		}
	}

	if (close(fd) < 0)
		modifylog_set_syscall_error(file, "close()");
	return ret;
}

/* Returns 1 = ok, 0 = full, -1 = error */
static int mail_modifylog_open_and_verify(struct modify_log_file *file)
{
	struct mail_index *index = file->log->index;
	struct modify_log_header hdr;
	ssize_t ret;
	int fd;

	fd = open(file->filepath, O_RDWR);
	if (fd == -1) {
		if (errno != ENOENT)
			modifylog_set_syscall_error(file, "open()");
		return -1;
	}

	if (file_wait_lock(fd, F_RDLCK) <= 0) {
		modifylog_set_syscall_error(file, "file_wait_lock()");
		(void)close(fd);
		return -1;
	}

	ret = read(fd, &hdr, sizeof(hdr));
	if (ret < 0)
		modifylog_set_syscall_error(file, "read()");
	else if (ret != sizeof(hdr)) {
		index_set_error(index, "Corrupted modify log %s: "
				"File too small", file->filepath);
		ret = -1;

		(void)unlink(file->filepath);
	} else {
		ret = 1;
	}

	if (ret > 0 && hdr.indexid != index->indexid) {
		index_set_error(index, "IndexID mismatch for modify log file "
				"%s", file->filepath);
		ret = -1;

		/* we have to rebuild it, make sure it's deleted. */
		(void)unlink(file->filepath);
	}

	if (ret > 0 && hdr.sync_id == SYNC_ID_FULL) {
		/* full */
		ret = 0;
	}

	if (ret > 0)
		file->fd = fd;
	else
		(void)close(fd);

	return ret;
}

static int modifylog_files_open_or_create(struct mail_modify_log *log)
{
	int i, ret1, ret2;

	for (i = 0; i < 2; i++) {
		ret1 = mail_modifylog_open_and_verify(&log->file1);
		ret2 = mail_modifylog_open_and_verify(&log->file2);

		if (ret1 == 1 && ret2 != 1) {
			log->head = log->tail = &log->file1;
			return TRUE;
		}

		if (ret1 != 1 && ret2 == 1) {
			log->head = log->tail = &log->file2;
			return TRUE;
		}

		if (ret1 == 1 && ret2 == 1) {
			/* both logs were opened ok, which shouldn't happen.
			   safest thing to do is to mark both closed,
			   delete them and recreate */
			index_set_error(log->index,
					"Index %s has both modify logs open",
					log->index->filepath);
			(void)modifylog_mark_full(&log->file1);
			(void)modifylog_mark_full(&log->file2);

			(void)unlink(log->file1.filepath);
			(void)unlink(log->file2.filepath);

			modifylog_close_file(&log->file1);
			modifylog_close_file(&log->file2);
		}

		ret1 = modifylog_reuse_or_create_file(&log->file1);
		if (ret1 == 1) {
			log->head = log->tail = &log->file1;
			return TRUE;
		}
		if (ret1 == -1)
			break;

		/* someone else probably just created the file */
	}

	if (ret1 == 0) {
		/* we tried twice */
		index_set_error(log->index, "Couldn't lock modify log file %s",
				log->file1.filepath);
	}
	return FALSE;
}

static int modifylog_create_anon(struct modify_log_file *file)
{
	file->mmap_full_length = MODIFY_LOG_INITIAL_SIZE;
	file->mmap_base = mmap_anon(file->mmap_full_length);
	file->header = file->mmap_base;

	if (file->mmap_base == MAP_FAILED)
		return modifylog_set_syscall_error(file, "mmap_anon()");

	mail_modifylog_init_header(file->log, file->mmap_base);

	file->mmap_used_length = file->header->used_file_size;
	file->synced_position = file->mmap_used_length;

	file->anon_mmap = TRUE;
	file->filepath = i_strdup_printf("(in-memory modify log for %s)",
					 file->log->index->mailbox_path);
	return TRUE;
}

int mail_modifylog_create(struct mail_index *index)
{
	struct mail_modify_log *log;
	int ret;

	i_assert(index->lock_type == MAIL_LOCK_EXCLUSIVE);

	log = mail_modifylog_new(index);

	if (INDEX_IS_IN_MEMORY(index)) {
		if (!modifylog_create_anon(&log->file1)) {
			mail_modifylog_free(log);
			return FALSE;
		}
	} else {
		ret = modifylog_reuse_or_create_file(&log->file1);
		if (ret == 0) {
			index_set_error(log->index,
				"Couldn't lock created modify log file %s",
				log->file1.filepath);
		}

		if (ret <= 0 || !mmap_init_update(&log->file1)) {
			/* fatal failure */
			mail_modifylog_free(log);
			return FALSE;
		}
	}

	log->head = log->tail = &log->file1;
	return TRUE;
}

int mail_modifylog_open_or_create(struct mail_index *index)
{
	struct mail_modify_log *log;

	log = mail_modifylog_new(index);

	if (!modifylog_files_open_or_create(log) ||
	    !mmap_init_update(log->head)) {
		/* fatal failure */
		mail_modifylog_free(log);
		return FALSE;
	}

	return TRUE;
}

void mail_modifylog_free(struct mail_modify_log *log)
{
	log->index->modifylog = NULL;

	modifylog_close_file(&log->file1);
	modifylog_close_file(&log->file2);

	i_free(log->file1.filepath);
	i_free(log->file2.filepath);
	i_free(log);
}

int mail_modifylog_sync_file(struct mail_modify_log *log, int *fsync_fd)
{
	struct modify_log_file *file = log->head;

	*fsync_fd = -1;

	if (!file->modified || file->anon_mmap)
		return TRUE;

	i_assert(file->mmap_base != NULL);

	if (msync(file->mmap_base, file->mmap_used_length, MS_SYNC) < 0)
		return modifylog_set_syscall_error(file, "msync()");

	*fsync_fd = file->fd;
	file->modified = FALSE;
	return TRUE;
}

void mail_modifylog_notify_lock_drop(struct mail_modify_log *log)
{
	log->head->last_expunge = NULL;
	log->head->last_flags = NULL;
}

/* if head file is closed, change it */
static int modifylog_update_head(struct mail_modify_log *log)
{
	struct modify_log_file *file;

	if (!mmap_update(log->head, FALSE))
		return FALSE;

	if (log->head->header->sync_id != SYNC_ID_FULL)
		return TRUE;

	i_assert(log->head == log->tail);

	/* switch file */
	file = log->head == &log->file1 ? &log->file2 : &log->file1;
	if (file->fd == -1) {
		if (mail_modifylog_open_and_verify(file) <= 0) {
			modifylog_set_corrupted(file,
				"Can't switch to open log file");
			return FALSE;
		}
	}

	if (!mmap_update(file, TRUE))
		return FALSE;

	/* we're non-synced */
	file->synced_id = 0;
	file->synced_position = sizeof(struct modify_log_header);
	log->head = file;
	return TRUE;
}

static int mmap_update_both(struct mail_modify_log *log)
{
	if (!modifylog_update_head(log))
		return FALSE;

	if (log->head != log->tail) {
		if (!mmap_update(log->tail, FALSE))
			return FALSE;
	}

	return TRUE;
}

static int mail_modifylog_grow(struct modify_log_file *file)
{
	uoff_t new_fsize;
	void *base;

	new_fsize = (uoff_t)file->mmap_full_length + MODIFYLOG_GROW_SIZE;
	i_assert(new_fsize < OFF_T_MAX);

	if (file->anon_mmap) {
		i_assert(new_fsize < SSIZE_T_MAX);

		base = mremap_anon(file->mmap_base, file->mmap_full_length,
				   (size_t)new_fsize, MREMAP_MAYMOVE);
		if (base == MAP_FAILED) {
			modifylog_set_syscall_error(file, "mremap_anon()");
			return FALSE;
		}

		file->mmap_base = base;
		file->mmap_full_length = (size_t)new_fsize;
		return TRUE;
	}

	if (file_set_size(file->fd, (off_t)new_fsize) < 0)
		return modifylog_set_syscall_error(file, "file_set_size()");

	if (!mmap_update(file, TRUE))
		return FALSE;

	return TRUE;
}

static int mail_modifylog_append(struct modify_log_file *file,
				 struct modify_log_record **rec,
				 int external_change)
{
	struct modify_log_record *destrec;

	i_assert(file->log->index->lock_type == MAIL_LOCK_EXCLUSIVE);
	i_assert(file->header->sync_id != SYNC_ID_FULL);
	i_assert((*rec)->seq1 != 0);
	i_assert((*rec)->uid1 != 0);

	if (!external_change) {
		if (file->log->cache_lock_counter !=
		    file->log->index->excl_lock_counter) {
			switch (modifylog_have_other_users(file->log, FALSE)) {
			case 0:
				/* we're the only one having this log open,
				   no need for modify log. */
				file->log->cache_have_others = FALSE;
				file->log->cache_lock_counter =
					file->log->index->excl_lock_counter;

				*rec = NULL;
				return TRUE;
			case -1:
				return FALSE;
			default:
				file->log->cache_have_others = TRUE;
				file->log->cache_lock_counter =
					file->log->index->excl_lock_counter;
				break;
			}
		}

		if (!file->log->cache_have_others) {
			*rec = NULL;
			return TRUE;
		}
	}

	if (file->mmap_used_length == file->mmap_full_length) {
		if (!mail_modifylog_grow(file))
			return FALSE;
	}

	i_assert(file->header->used_file_size == file->mmap_used_length);
	i_assert(file->mmap_used_length + sizeof(struct modify_log_record) <=
		 file->mmap_full_length);

	destrec = (struct modify_log_record *) ((char *) file->mmap_base +
						file->mmap_used_length);
	memcpy(destrec, *rec, sizeof(struct modify_log_record));

	if (!external_change && file->header->sync_id == file->synced_id) {
		file->synced_position += sizeof(struct modify_log_record);
		file->synced_id++;
	}

	file->header->used_file_size += sizeof(struct modify_log_record);
	file->mmap_used_length += sizeof(struct modify_log_record);

	file->header->sync_id++;
	file->modified = TRUE;

	*rec = destrec;
	return TRUE;
}

int mail_modifylog_add_expunge(struct mail_modify_log *log, unsigned int seq,
			       unsigned int uid, int external_change)
{
	struct modify_log_file *file;
	struct modify_log_record rec, *recp;

	if (!modifylog_update_head(log))
		return FALSE;

	file = log->head;

	/* expunges must not be added when log isn't synced */
	i_assert(external_change || file->synced_id == file->header->sync_id);

	if (file->last_expunge != NULL &&
	    file->last_expunge_external == external_change) {
		if (seq+1 == file->last_expunge->seq1) {
			i_assert(uid < file->last_expunge->uid1);
			file->last_expunge->seq1 = seq;
			file->last_expunge->uid1 = uid;
			return TRUE;
		} else if (seq == file->last_expunge->seq1) {
			/* note the different weirder logic than with
			   flag changing, because of reordered seq numbers. */
			i_assert(uid > file->last_expunge->uid2);
			file->last_expunge->seq2++;
			file->last_expunge->uid2 = uid;
			return TRUE;
		}
	}

	rec.type = RECORD_TYPE_EXPUNGE;
	rec.seq1 = rec.seq2 = seq;
	rec.uid1 = rec.uid2 = uid;

	recp = &rec;
	if (!mail_modifylog_append(file, &recp, external_change))
		return FALSE;

        file->last_expunge_external = external_change;
	file->last_expunge = recp;
	return TRUE;
}

int mail_modifylog_add_flags(struct mail_modify_log *log, unsigned int seq,
			     unsigned int uid, int external_change)
{
	struct modify_log_file *file;
	struct modify_log_record rec, *recp;

	if (!modifylog_update_head(log))
		return FALSE;

	file = log->head;

	if (file->last_flags != NULL &&
	    file->last_flags_external == external_change) {
		if (seq+1 == file->last_flags->seq1) {
			file->last_flags->seq1 = seq;
			file->last_flags->uid1 = uid;
			return TRUE;
		} else if (seq-1 == file->last_flags->seq2) {
			file->last_flags->seq2 = seq;
			file->last_flags->uid2 = uid;
			return TRUE;
		}
	}

	rec.type = RECORD_TYPE_FLAGS_CHANGED;
	rec.seq1 = rec.seq2 = seq;
	rec.uid1 = rec.uid2 = uid;

	recp = &rec;
	if (!mail_modifylog_append(file, &recp, external_change))
		return FALSE;

        file->last_flags_external = external_change;
	file->last_flags = recp;
	return TRUE;
}

static void
mail_modifylog_get_nonsynced_file(struct modify_log_file *file,
				  const struct modify_log_record **arr,
				  unsigned int *count)
{
	struct modify_log_record *end_rec;

	i_assert(file->synced_position <= file->mmap_used_length);
	i_assert(file->synced_position >= sizeof(struct modify_log_header));

	*arr = (struct modify_log_record *) ((char *) file->mmap_base +
					     file->synced_position);
	end_rec = (struct modify_log_record *) ((char *) file->mmap_base +
						file->mmap_used_length);
	*count = (unsigned int) (end_rec - *arr);
}

int mail_modifylog_get_nonsynced(struct mail_modify_log *log,
				 const struct modify_log_record **arr1,
				 unsigned int *count1,
				 const struct modify_log_record **arr2,
				 unsigned int *count2)
{
	i_assert(log->index->lock_type != MAIL_LOCK_UNLOCK);

	*arr1 = *arr2 = NULL;
	*count1 = *count2 = 0;

	if (!mmap_update_both(log))
		return FALSE;

	mail_modifylog_get_nonsynced_file(log->tail, arr1, count1);
	if (log->head != log->tail)
		mail_modifylog_get_nonsynced_file(log->head, arr2, count2);

	return TRUE;
}

static int mail_modifylog_try_truncate(struct modify_log_file *file)
{
	if (modifylog_have_other_users(file->log, TRUE) != 0)
		return FALSE;

#ifdef DEBUG
	mprotect(file->mmap_base, sizeof(struct modify_log_header),
		 PROT_READ | PROT_WRITE);
#endif
	file->header->sync_id = 0;
	file->header->used_file_size = sizeof(struct modify_log_header);

	if (msync(file->mmap_base,
		  sizeof(struct modify_log_header), MS_SYNC) < 0) {
		modifylog_set_syscall_error(file, "msync()");
		return FALSE;
	}

	file->synced_id = 0;
	file->synced_position = sizeof(struct modify_log_header);

	if (file_set_size(file->fd, MODIFY_LOG_INITIAL_SIZE) < 0)
		modifylog_set_syscall_error(file, "file_set_size()");

	return TRUE;
}

/* switches to active modify log, updating our sync mark to end of it */
static int mail_modifylog_switch_file(struct mail_modify_log *log)
{
	struct modify_log_file *file;

	(void)mail_modifylog_try_truncate(log->tail);

	file = log->tail == &log->file1 ? &log->file2 : &log->file1;
	if (file->fd == -1) {
		if (mail_modifylog_open_and_verify(file) <= 0) {
			modifylog_set_corrupted(file,
				"Can't switch to open log file");
			return FALSE;
		}
	}

	modifylog_munmap(log->tail);

	log->head = log->tail = file;
	return mmap_init_update(log->head);
}

static int mail_modifylog_try_switch_file(struct mail_modify_log *log)
{
	struct modify_log_file *file;

	if (log->head->anon_mmap)
		return TRUE;

	if (mail_modifylog_try_truncate(log->tail)) {
		/* no need to switch, we're the only user and we just
		   truncated it  */
		return TRUE;
	}

	file = log->head == &log->file1 ? &log->file2 : &log->file1;
	if (modifylog_reuse_or_create_file(file) != 1) {
		/* locked or error, keep using the old log */
		return TRUE;
	}

	if (!modifylog_mark_full(log->head))
		return FALSE;

	modifylog_munmap(log->head);

	log->head = log->tail = file;
	return mmap_init_update(log->head);
}

int mail_modifylog_mark_synced(struct mail_modify_log *log)
{
	i_assert(log->index->lock_type != MAIL_LOCK_UNLOCK);

	if (!mmap_update_both(log))
		return FALSE;

	if (log->tail->header->sync_id == SYNC_ID_FULL) {
		/* tail file is full, switch to next one */
		return mail_modifylog_switch_file(log);
	}

	log->tail = log->head;
	if (log->head->synced_id != log->head->header->sync_id) {
		log->head->synced_id = log->head->header->sync_id;
		log->head->synced_position = log->head->mmap_used_length;
	}

	if (log->head->mmap_used_length > MAX_MODIFYLOG_SIZE) {
		/* if the other file isn't locked, switch to it */
		return mail_modifylog_try_switch_file(log);
	}

	return TRUE;
}

static int compare_expunge(const void *p1, const void *p2)
{
	const struct modify_log_expunge *e1 = p1;
	const struct modify_log_expunge *e2 = p2;

	return e1->uid1 < e2->uid1 ? -1 : e1->uid1 > e2->uid1 ? 1 : 0;
}

static struct modify_log_record *modifylog_first(struct mail_modify_log *log)
{
	struct modify_log_file *file;
        struct modify_log_record *rec;

	file = log->tail;
	rec = (struct modify_log_record *) ((char *) file->mmap_base +
					    file->synced_position);
	log->iterator_end = (struct modify_log_record *)
		((char *) file->mmap_base + file->mmap_used_length);
	return rec < log->iterator_end ? rec : NULL;
}

static struct modify_log_record *
modifylog_next(struct mail_modify_log *log, struct modify_log_record *rec)
{
	struct modify_log_file *file;

	rec++;
	if (rec < log->iterator_end)
		return rec;

	file = log->head;
	if ((char *) rec == (char *) file->mmap_base + file->mmap_used_length)
		return NULL; /* end of head */

	/* end of tail, jump to beginning of head */
	rec = (struct modify_log_record *) ((char *) file->mmap_base +
					    sizeof(struct modify_log_header));
	log->iterator_end = (struct modify_log_record *)
		((char *) file->mmap_base + file->mmap_used_length);
	return rec < log->iterator_end ? rec : NULL;
}

static unsigned int
modifylog_get_record_count_after(struct mail_modify_log *log,
				 struct modify_log_record *rec)
{
	unsigned int count = 0;

	if (log->head == log->tail ||
	    IS_PTR_IN_RANGE(rec, log->head->mmap_base,
			    log->head->mmap_used_length)) {
		/* only head */
		count = (log->head->mmap_used_length -
			 MODIFYLOG_FILE_POSITION(log->head, rec)) /
			sizeof(struct modify_log_record);
	} else {
		/* tail */
		count = (log->tail->mmap_used_length -
			 MODIFYLOG_FILE_POSITION(log->tail, rec)) /
			sizeof(struct modify_log_record);

		if (log->head != log->tail) {
			/* + head */
			count += (log->tail->mmap_used_length -
				  sizeof(struct modify_log_header)) /
				sizeof(struct modify_log_record);
		}
	}

	return count;
}

const struct modify_log_expunge *
mail_modifylog_seq_get_expunges(struct mail_modify_log *log,
				unsigned int first_seq,
				unsigned int last_seq,
				unsigned int *expunges_before)
{
	struct modify_log_record *rec;
	struct modify_log_expunge expunge, *expunges;
	buffer_t *buf;
	size_t count;
	unsigned int before, max_records;

	i_assert(log->index->lock_type != MAIL_LOCK_UNLOCK);

	*expunges_before = 0;

	if (!mmap_update_both(log))
		return NULL;

	/* find the first expunged message that affects our range */
	rec = modifylog_first(log);
	while (rec != NULL) {
		if (rec->type == RECORD_TYPE_EXPUNGE && rec->seq1 <= last_seq)
			break;

		rec = modifylog_next(log, rec);
	}

	if (rec == NULL) {
		/* none found */
		return &no_expunges;
	}

	/* allocate memory for the returned array. the file size - synced
	   position should be quite near the amount of memory we need, unless
	   there's lots of FLAGS_CHANGED records which is why there's the
	   second check to make sure it's not unneededly large. */
	max_records = modifylog_get_record_count_after(log, rec);
	if (max_records > last_seq - first_seq + 1)
		max_records = last_seq - first_seq + 1;

	i_assert((max_records+1) <
		 SSIZE_T_MAX / sizeof(struct modify_log_expunge));
	buf = buffer_create_static_hard(data_stack_pool, (max_records+1) *
					sizeof(struct modify_log_expunge));

	before = 0;
	for (; rec != NULL; rec = modifylog_next(log, rec)) {
		if (rec->type != RECORD_TYPE_EXPUNGE)
			continue;

		if (rec->seq2 < first_seq) {
			/* before our range */
			before += rec->seq2 - rec->seq1 + 1;
		} else if (rec->seq1 <= last_seq && rec->seq2 >= first_seq) {
			/* within our range, at least partially */
			if (max_records-- == 0) {
				/* log contains more data than it should
				   have - must be corrupted. */
				modifylog_set_corrupted(log->tail,
					"Contains more data than expected");
				return NULL;
			}

			if (rec->seq1 < first_seq) {
				/* partial initial match, update
				   before-counter */
				before += first_seq - rec->seq1;
				expunge.seq_count = rec->seq2 - first_seq + 1;
			} else {
				expunge.seq_count = rec->seq2 - rec->seq1 + 1;
			}

			expunge.uid1 = rec->uid1;
			expunge.uid2 = rec->uid2;
			buffer_append(buf, &expunge, sizeof(expunge));
		}

		if (rec->seq1 <= last_seq) {
			/* update the seq. numbers so they can be compared */
			last_seq -= I_MIN(rec->seq2, last_seq) -
				rec->seq1 + 1;

			if (rec->seq1 < first_seq) {
				first_seq -= I_MIN(rec->seq2, first_seq-1) -
					rec->seq1 + 1;
			}
		}
	}

	/* terminate the array */
	buffer_set_used_size(buf, buffer_get_used_size(buf) + sizeof(expunge));

	/* extract the array from buffer */
	count = buffer_get_used_size(buf) / sizeof(expunge);
	expunges = buffer_free_without_data(buf);

	/* sort the UID array, not including the terminating 0 */
	qsort(expunges, count-1, sizeof(expunge), compare_expunge);

	*expunges_before = before;
	return expunges;
}

const struct modify_log_expunge *
mail_modifylog_uid_get_expunges(struct mail_modify_log *log,
				unsigned int first_uid,
				unsigned int last_uid,
				unsigned int *expunges_before)
{
	/* pretty much copy&pasted from sequence code above ..
	   kind of annoying */
	struct modify_log_record *rec;
	struct modify_log_expunge expunge, *expunges;
	buffer_t *buf;
	size_t count;
	unsigned int before, max_records;

	i_assert(log->index->lock_type != MAIL_LOCK_UNLOCK);

	*expunges_before = 0;

	if (!mmap_update_both(log))
		return NULL;

	/* find the first expunged message that affects our range */
	rec = modifylog_first(log);
	while (rec != NULL) {
		if (rec->type == RECORD_TYPE_EXPUNGE && rec->uid1 <= last_uid)
			break;

		rec = modifylog_next(log, rec);
	}

	if (rec == NULL) {
		/* none found */
		return &no_expunges;
	}

	/* allocate memory for the returned array. the file size - synced
	   position should be quite near the amount of memory we need, unless
	   there's lots of FLAGS_CHANGED records which is why there's the
	   second check to make sure it's not unneededly large. */
	max_records = modifylog_get_record_count_after(log, rec);
	if (max_records > last_uid - first_uid + 1)
		max_records = last_uid - first_uid + 1;

	i_assert((max_records+1) <
		 SSIZE_T_MAX / sizeof(struct modify_log_expunge));
	buf = buffer_create_static_hard(data_stack_pool, (max_records+1) *
					sizeof(struct modify_log_expunge));

	before = 0;
	for (; rec != NULL; rec = modifylog_next(log, rec)) {
		if (rec->type != RECORD_TYPE_EXPUNGE)
			continue;

                if (rec->uid2 < first_uid) {
			/* before our range */
			before += rec->seq2 - rec->seq1 + 1;
		} else if (rec->uid1 <= last_uid && rec->uid2 >= first_uid) {
			/* within our range, at least partially */
			if (max_records-- == 0) {
				/* log contains more data than it should
				   have - must be corrupted. */
				modifylog_set_corrupted(log->tail,
					"Contains more data than expected");
				return NULL;
			}

			expunge.uid1 = rec->uid1;
			expunge.uid2 = rec->uid2;
			expunge.seq_count = rec->seq2 -rec->seq1 + 1;
			buffer_append(buf, &expunge, sizeof(expunge));
		}
	}

	/* terminate the array */
	buffer_set_used_size(buf, buffer_get_used_size(buf) + sizeof(expunge));

	/* extract the array from buffer */
	count = buffer_get_used_size(buf) / sizeof(expunge);
	expunges = buffer_free_without_data(buf);

	/* sort the UID array, not including the terminating 0 */
	qsort(expunges, count-1, sizeof(expunge), compare_expunge);

	*expunges_before = before;
	return expunges;
}

static unsigned int
modifylog_file_get_expunge_count(struct modify_log_file *file)
{
	struct modify_log_record *rec, *end_rec;
	unsigned int expunges;

	/* find the first expunged message that affects our range */
	rec = (struct modify_log_record *) ((char *) file->mmap_base +
					    file->synced_position);
	end_rec = (struct modify_log_record *) ((char *) file->mmap_base +
						file->mmap_used_length);

	expunges = 0;
	while (rec < end_rec) {
		if (rec->type == RECORD_TYPE_EXPUNGE)
			expunges += rec->seq2 - rec->seq1 + 1;
		rec++;
	}

	return expunges;
}

unsigned int mail_modifylog_get_expunge_count(struct mail_modify_log *log)
{
	unsigned int expunges;

	i_assert(log->index->lock_type != MAIL_LOCK_UNLOCK);

	if (!mmap_update_both(log))
		return 0;

	expunges = modifylog_file_get_expunge_count(log->tail);
	if (log->tail != log->head)
		expunges += modifylog_file_get_expunge_count(log->head);

	return expunges;
}
