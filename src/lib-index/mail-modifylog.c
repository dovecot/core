/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "file-lock.h"
#include "file-set-size.h"
#include "mmap-util.h"
#include "write-full.h"
#include "mail-index.h"
#include "mail-index-util.h"
#include "mail-modifylog.h"

#include <stdlib.h>
#include <fcntl.h>

/* Maximum size for modify log (isn't exact) */
#define MAX_MODIFYLOG_SIZE 10240

#define MODIFYLOG_GROW_SIZE (sizeof(ModifyLogRecord) * 128)

#define MODIFY_LOG_INITIAL_SIZE (sizeof(ModifyLogHeader) + MODIFYLOG_GROW_SIZE)

#define MODIFYLOG_FILE_POSITION(log, ptr) \
	((int) ((char *) (ptr) - (char *) (log)->mmap_base))

struct _MailModifyLog {
	MailIndex *index;

	int fd;
	char *filepath;

	void *mmap_base;
	size_t mmap_used_length;
	size_t mmap_full_length;

	ModifyLogRecord *last_expunge, *last_flags;
	int last_expunge_external, last_flags_external;

	ModifyLogHeader *header;
	uoff_t synced_position;
	unsigned int synced_id;

	unsigned int anon_mmap:1;
	unsigned int modified:1;
	unsigned int second_log:1;
};

static const ModifyLogExpunge no_expunges = { 0, 0, 0 };

static int modifylog_set_syscall_error(MailModifyLog *log,
				       const char *function)
{
	i_assert(function != NULL);

	index_set_error(log->index, "%s failed with modify log file %s: %m",
			function, log->filepath);
	return FALSE;
}

static int modifylog_set_corrupted(MailModifyLog *log, const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	t_push();

	index_set_error(log->index, "Corrupted modify log file %s: %s",
			log->filepath, t_strdup_vprintf(fmt, va));

	t_pop();
	va_end(va);

	/* make sure we don't get back here */
	log->index->inconsistent = TRUE;
	(void)unlink(log->filepath);

	return FALSE;
}

/* returns 1 = yes, 0 = no, -1 = error */
static int mail_modifylog_have_other_users(MailModifyLog *log)
{
	int ret;

	if (log->anon_mmap)
		return 0;

	/* try grabbing exclusive lock */
	ret = file_try_lock(log->fd, F_WRLCK);
	if (ret <= 0) {
		if (ret < 0)
			modifylog_set_syscall_error(log, "file_try_lock()");
		return ret < 0 ? -1 : 1;
	}

	/* revert back to shared lock */
	ret = file_try_lock(log->fd, F_RDLCK);
	if (ret < 0) {
		modifylog_set_syscall_error(log, "file_try_lock()");
		return -1;
	}

	if (ret == 0) {
		/* shouldn't happen */
		index_set_error(log->index, "file_try_lock(F_WRLCK -> F_RDLCK) "
				"failed with file %s", log->filepath);
		return -1;
	}

	return 0;
}

static int mmap_update(MailModifyLog *log, int forced)
{
	ModifyLogHeader *hdr;
	unsigned int extra;

	if (!forced && log->header != NULL &&
	    log->mmap_full_length >= log->header->used_file_size) {
		log->mmap_used_length = log->header->used_file_size;
		return TRUE;
	}

	i_assert(!log->anon_mmap);

	if (log->mmap_base != NULL) {
		/* make sure we're synced before munmap() */
		if (log->modified &&
		    msync(log->mmap_base, log->mmap_used_length, MS_SYNC) < 0)
			return modifylog_set_syscall_error(log, "msync()");

		if (munmap(log->mmap_base, log->mmap_full_length) < 0)
			modifylog_set_syscall_error(log, "munmap()");
	}

	log->mmap_used_length = 0;
	log->header = NULL;

	log->last_expunge = NULL;
	log->last_flags = NULL;

	log->mmap_base = mmap_rw_file(log->fd, &log->mmap_full_length);
	if (log->mmap_base == MAP_FAILED) {
		log->mmap_base = NULL;
		return modifylog_set_syscall_error(log, "mmap()");
	}

	if (log->mmap_full_length < sizeof(ModifyLogHeader)) {
		index_set_error(log->index, "Too small modify log %s",
				log->filepath);
		(void)unlink(log->filepath);
		return FALSE;
	}

	extra = (log->mmap_full_length - sizeof(ModifyLogHeader)) %
		sizeof(ModifyLogRecord);

	if (extra != 0) {
		/* partial write or corrupted -
		   truncate the file to valid length */
		log->mmap_full_length -= extra;
		if (ftruncate(log->fd, (off_t)log->mmap_full_length) < 0)
			modifylog_set_syscall_error(log, "ftruncate()");
	}

	hdr = log->mmap_base;
	if (hdr->used_file_size > log->mmap_full_length) {
		modifylog_set_corrupted(log,
			"used_file_size larger than real file size "
			"(%"PRIuUOFF_T" vs %"PRIuSIZE_T")",
			hdr->used_file_size, log->mmap_full_length);
		return FALSE;
	}

	if ((hdr->used_file_size - sizeof(ModifyLogHeader)) %
	    sizeof(ModifyLogRecord) != 0) {
		modifylog_set_corrupted(log,
			"Invalid used_file_size in header (%"PRIuUOFF_T")",
			hdr->used_file_size);
		return FALSE;
	}

	log->header = log->mmap_base;
	log->mmap_used_length = hdr->used_file_size;
	return TRUE;
}

static MailModifyLog *mail_modifylog_new(MailIndex *index)
{
	MailModifyLog *log;

	log = i_new(MailModifyLog, 1);
	log->fd = -1;
	log->index = index;

	index->modifylog = log;
	return log;
}

static void mail_modifylog_close(MailModifyLog *log)
{
	if (log->anon_mmap) {
		if (munmap_anon(log->mmap_base, log->mmap_full_length) < 0)
			modifylog_set_syscall_error(log, "munmap_anon()");
	} else if (log->mmap_base != NULL) {
		if (munmap(log->mmap_base, log->mmap_full_length) < 0)
			modifylog_set_syscall_error(log, "munmap()");
	}
	log->mmap_base = NULL;
	log->mmap_full_length = 0;
	log->mmap_used_length = 0;
	log->header = NULL;

	log->last_expunge = NULL;
	log->last_flags = NULL;

	if (log->fd != -1) {
		if (close(log->fd) < 0)
			modifylog_set_syscall_error(log, "close()");
		log->fd = -1;
	}

	i_free(log->filepath);
}

static void mail_modifylog_init_header(MailModifyLog *log, ModifyLogHeader *hdr)
{
	memset(hdr, 0, sizeof(ModifyLogHeader));
	hdr->indexid = log->index->indexid;
	hdr->used_file_size = sizeof(ModifyLogHeader);
}

static int mail_modifylog_init_fd(MailModifyLog *log, int fd,
				  const char *path)
{
        ModifyLogHeader hdr;

        mail_modifylog_init_header(log, &hdr);
	if (write_full(fd, &hdr, sizeof(hdr)) < 0) {
		if (errno == ENOSPC)
			log->index->nodiskspace = TRUE;

		index_file_set_syscall_error(log->index, path, "write_full()");
		return FALSE;
	}

	if (file_set_size(fd, MODIFY_LOG_INITIAL_SIZE) < 0) {
		if (errno == ENOSPC)
			log->index->nodiskspace = TRUE;

		index_file_set_syscall_error(log->index, path,
					     "file_set_size()");
		return FALSE;
	}

	return TRUE;
}

static int modifylog_mark_full(MailModifyLog *log)
{
	log->header->sync_id = SYNC_ID_FULL;

	if (msync(log->mmap_base, sizeof(ModifyLogHeader), MS_SYNC) < 0)
		return modifylog_set_syscall_error(log, "msync()");

	return TRUE;
}

static int modifylog_open_and_init_file(MailModifyLog *log, const char *path)
{
	int fd, ret;

	if (log->index->nodiskspace)
		return FALSE;

	fd = open(path, O_RDWR | O_CREAT, 0660);
	if (fd == -1) {
		if (errno == ENOSPC)
			log->index->nodiskspace = TRUE;

		return index_file_set_syscall_error(log->index, path, "open()");
	}

	/* if we can't get the lock, we fail. it shouldn't happen. */
	ret = file_try_lock(fd, F_WRLCK);
	if (ret < 0) {
		index_file_set_syscall_error(log->index, path,
					     "file_wait_lock()");
	} else if (ret == 0) {
		index_set_error(log->index, "Couldn't get exclusive lock for "
				"created modify log %s", path);
	}

	if (ret > 0 && mail_modifylog_init_fd(log, fd, path)) {
		/* drop back to read lock */
		if (file_wait_lock(fd, F_RDLCK) < 0) {
			modifylog_set_syscall_error(log, "file_wait_lock()");
			ret = -1;
		}

		if (ret > 0 && (log->header == NULL ||
				modifylog_mark_full(log))) {
			mail_modifylog_close(log);

			log->fd = fd;
			log->filepath = i_strdup(path);
			return TRUE;
		}
	}

	if (close(fd) < 0)
		index_file_set_syscall_error(log->index, path, "close()");
	return FALSE;
}

int mail_modifylog_create(MailIndex *index)
{
	MailModifyLog *log;
	const char *path;

	i_assert(index->lock_type == MAIL_LOCK_EXCLUSIVE);

	log = mail_modifylog_new(index);

	if (index->nodiskspace) {
		log->mmap_full_length = MODIFY_LOG_INITIAL_SIZE;
		log->mmap_base = mmap_anon(log->mmap_full_length);

		mail_modifylog_init_header(log, log->mmap_base);
		log->header = log->mmap_base;
		log->mmap_used_length = log->header->used_file_size;

		log->anon_mmap = TRUE;
		log->filepath = i_strdup("(in-memory modify log)");
	} else {
		path = t_strconcat(log->index->filepath, ".log", NULL);

		if (!modifylog_open_and_init_file(log, path) ||
		    !mmap_update(log, TRUE)) {
			/* fatal failure */
			mail_modifylog_free(log);
			return FALSE;
		}
	}

	log->synced_id = log->header->sync_id;
	log->synced_position = log->mmap_used_length;
	return TRUE;
}

/* Returns 1 = ok, 0 = full, -1 = error */
static int mail_modifylog_open_and_verify(MailModifyLog *log, const char *path)
{
	ModifyLogHeader hdr;
	ssize_t ret;
	int fd;

	fd = open(path, O_RDWR);
	if (fd == -1) {
		if (errno != ENOENT) {
			index_file_set_syscall_error(log->index, path,
						     "open()");
		}
		return -1;
	}

	if (file_wait_lock(fd, F_RDLCK) < 0) {
		modifylog_set_syscall_error(log, "file_wait_lock()");
		(void)close(fd);
		return -1;
	}

	ret = read(fd, &hdr, sizeof(hdr));
	if (ret < 0)
		index_file_set_syscall_error(log->index, path, "read()");
	else if (ret != sizeof(hdr)) {
		index_set_error(log->index, "Corrupted modify log %s ", path);
		ret = -1;

		(void)unlink(path);
	}

	if (ret > 0 && hdr.indexid != log->index->indexid) {
		index_set_error(log->index, "IndexID mismatch for modify log "
				"file %s", path);
		ret = -1;

		/* we have to rebuild it, make sure it's deleted. */
		(void)unlink(path);
	}

	if (ret > 0 && hdr.sync_id == SYNC_ID_FULL) {
		/* full */
		ret = 0;
	}

	if (ret > 0) {
		log->fd = fd;
		log->filepath = i_strdup(path);
	} else {
		(void)close(fd);
	}

	return ret > 0;
}

static int mail_modifylog_find_or_create(MailModifyLog *log)
{
	const char *path1, *path2;
	int i, ret;

	for (i = 0; i < 2; i++) {
		/* first try <index>.log */
		path1 = t_strconcat(log->index->filepath, ".log", NULL);
		path2 = t_strconcat(log->index->filepath, ".log.2", NULL);

		ret = mail_modifylog_open_and_verify(log, path1);
		if (ret == 1)
			return TRUE;

		if (ret == 0) {
			/* then <index>.log.2 */
			if (mail_modifylog_open_and_verify(log, path2) == 1)
				return TRUE;
		}

		/* try creating/reusing them */
		if (modifylog_open_and_init_file(log, path1))
			return TRUE;

		if (modifylog_open_and_init_file(log, path2))
			return TRUE;

		/* maybe the file was just switched, check the logs again */
	}

	if (!log->index->nodiskspace) {
		index_set_error(log->index, "We could neither use nor create "
				"the modify log for index %s",
				log->index->filepath);
	}
	return FALSE;
}

int mail_modifylog_open_or_create(MailIndex *index)
{
	MailModifyLog *log;

	log = mail_modifylog_new(index);

	if (!mail_modifylog_find_or_create(log) ||
	    !mmap_update(log, TRUE)) {
		/* fatal failure */
		mail_modifylog_free(log);
		return FALSE;
	}

	log->synced_id = log->header->sync_id;
	log->synced_position = log->mmap_used_length;
	return TRUE;
}

void mail_modifylog_free(MailModifyLog *log)
{
	log->index->modifylog = NULL;

	mail_modifylog_close(log);
	i_free(log);
}

int mail_modifylog_sync_file(MailModifyLog *log)
{
	if (!log->modified || log->anon_mmap)
		return TRUE;

	if (log->mmap_base != NULL) {
		if (msync(log->mmap_base, log->mmap_used_length, MS_SYNC) < 0)
			return modifylog_set_syscall_error(log, "msync()");
	}

	if (fsync(log->fd) < 0)
		return modifylog_set_syscall_error(log, "fsync()");

	log->modified = FALSE;
	return TRUE;
}

void mail_modifylog_notify_lock_drop(MailModifyLog *log)
{
	log->last_expunge = NULL;
	log->last_flags = NULL;
}

static int mail_modifylog_grow(MailModifyLog *log)
{
	uoff_t new_fsize;
	void *base;

	new_fsize = (uoff_t)log->mmap_full_length + MODIFYLOG_GROW_SIZE;
	i_assert(new_fsize < OFF_T_MAX);

	if (log->anon_mmap) {
		i_assert(new_fsize < SSIZE_T_MAX);

		base = mremap_anon(log->mmap_base, log->mmap_full_length,
				   (size_t)new_fsize, MREMAP_MAYMOVE);
		if (base == MAP_FAILED) {
			modifylog_set_syscall_error(log, "mremap_anon()");
			return FALSE;
		}

		log->mmap_base = base;
		log->mmap_full_length = (size_t)new_fsize;
		return TRUE;
	}

	if (file_set_size(log->fd, (off_t)new_fsize) < 0) {
		if (errno == ENOSPC)
			log->index->nodiskspace = TRUE;
		return modifylog_set_syscall_error(log, "file_set_size()");
	}

	if (!mmap_update(log, TRUE))
		return FALSE;

	return TRUE;
}

static int mail_modifylog_append(MailModifyLog *log, ModifyLogRecord **rec,
				 int external_change)
{
	ModifyLogRecord *destrec;

	i_assert(log->index->lock_type == MAIL_LOCK_EXCLUSIVE);
	i_assert((*rec)->seq1 != 0);
	i_assert((*rec)->uid1 != 0);

	if (!external_change) {
		switch (mail_modifylog_have_other_users(log)) {
		case 0:
			/* we're the only one having this log open,
			   no need for modify log. */
			*rec = NULL;
			return TRUE;
		case -1:
			return FALSE;
		}
	}

	if (!mmap_update(log, FALSE))
		return FALSE;

	if (log->mmap_used_length == log->mmap_full_length) {
		if (!mail_modifylog_grow(log))
			return FALSE;
	}

	i_assert(log->header->used_file_size == log->mmap_used_length);
	i_assert(log->mmap_used_length + sizeof(ModifyLogRecord) <=
		 log->mmap_full_length);

	destrec = (ModifyLogRecord *) ((char *) log->mmap_base +
				       log->mmap_used_length);
	memcpy(destrec, *rec, sizeof(ModifyLogRecord));

	if (!external_change && log->header->sync_id == log->synced_id) {
		log->synced_position += sizeof(ModifyLogRecord);
		log->synced_id++;
	}

	log->header->used_file_size += sizeof(ModifyLogRecord);
	log->mmap_used_length += sizeof(ModifyLogRecord);

	log->header->sync_id++;
	log->modified = TRUE;

	*rec = destrec;
	return TRUE;
}

int mail_modifylog_add_expunge(MailModifyLog *log, unsigned int seq,
			       unsigned int uid, int external_change)
{
	ModifyLogRecord rec, *recp;

	/* expunges must not be added when log isn't synced */
	i_assert(external_change || log->synced_id == log->header->sync_id);

	if (log->last_expunge != NULL &&
	    log->last_expunge_external == external_change) {
		if (seq+1 == log->last_expunge->seq1) {
			i_assert(uid < log->last_expunge->uid1);
			log->last_expunge->seq1 = seq;
			log->last_expunge->uid1 = uid;
			return TRUE;
		} else if (seq == log->last_expunge->seq1) {
			/* note the different weirder logic than with
			   flag changing, because of reordered seq numbers. */
			i_assert(uid > log->last_expunge->uid2);
			log->last_expunge->seq2++;
			log->last_expunge->uid2 = uid;
			return TRUE;
		}
	}

	rec.type = RECORD_TYPE_EXPUNGE;
	rec.seq1 = rec.seq2 = seq;
	rec.uid1 = rec.uid2 = uid;

	recp = &rec;
	if (!mail_modifylog_append(log, &recp, external_change))
		return FALSE;

        log->last_expunge_external = external_change;
	log->last_expunge = recp;
	return TRUE;
}

int mail_modifylog_add_flags(MailModifyLog *log, unsigned int seq,
			     unsigned int uid, int external_change)
{
	ModifyLogRecord rec, *recp;

	if (log->last_flags != NULL &&
	    log->last_flags_external == external_change) {
		if (seq+1 == log->last_flags->seq1) {
			log->last_flags->seq1 = seq;
			log->last_flags->uid1 = uid;
			return TRUE;
		} else if (seq-1 == log->last_flags->seq2) {
			log->last_flags->seq2 = seq;
			log->last_flags->uid2 = uid;
			return TRUE;
		}
	}

	rec.type = RECORD_TYPE_FLAGS_CHANGED;
	rec.seq1 = rec.seq2 = seq;
	rec.uid1 = rec.uid2 = uid;

	recp = &rec;
	if (!mail_modifylog_append(log, &recp, external_change))
		return FALSE;

        log->last_flags_external = external_change;
	log->last_flags = recp;
	return TRUE;
}

ModifyLogRecord *mail_modifylog_get_nonsynced(MailModifyLog *log,
					      unsigned int *count)
{
	ModifyLogRecord *rec, *end_rec;

	i_assert(log->index->lock_type != MAIL_LOCK_UNLOCK);

	*count = 0;
	if (!mmap_update(log, FALSE))
		return NULL;

	i_assert(log->synced_position <= log->mmap_used_length);
	i_assert(log->synced_position >= sizeof(ModifyLogHeader));

	rec = (ModifyLogRecord *) ((char *) log->mmap_base +
				   log->synced_position);
	end_rec = (ModifyLogRecord *) ((char *) log->mmap_base +
				       log->mmap_used_length);
	*count = (unsigned int) (end_rec - rec);
	return rec;
}

static int mail_modifylog_switch_file(MailModifyLog *log)
{
	MailIndex *index = log->index;

	mail_modifylog_free(log);
	return mail_modifylog_open_or_create(index);
}

static int mail_modifylog_try_switch_file(MailModifyLog *log)
{
	const char *path;

	if (log->anon_mmap)
		return TRUE;

	path = t_strconcat(log->index->filepath,
			   log->second_log ? ".log" : ".log.2", NULL);

	if (!modifylog_open_and_init_file(log, path)) {
		/* old log file is still open */
		return TRUE;
	}

	if (!mmap_update(log, TRUE))
		return FALSE;

	log->synced_id = log->header->sync_id;
	log->synced_position = log->mmap_used_length;
	return TRUE;
}

int mail_modifylog_mark_synced(MailModifyLog *log)
{
	i_assert(log->index->lock_type != MAIL_LOCK_UNLOCK);

	if (!mmap_update(log, FALSE))
		return FALSE;

	if (log->header->sync_id == SYNC_ID_FULL) {
		/* log file is full, switch to next one */
		return mail_modifylog_switch_file(log);
	}

	if (log->synced_id == log->header->sync_id) {
		/* we are already synced */
		return TRUE;
	}

	log->synced_id = log->header->sync_id;
	log->synced_position = log->mmap_used_length;

	log->modified = TRUE;

	if (log->mmap_used_length > MAX_MODIFYLOG_SIZE) {
		/* if the other file isn't locked, switch to it */
		return mail_modifylog_try_switch_file(log);
	}

	return TRUE;
}

static int compare_expunge(const void *p1, const void *p2)
{
	const ModifyLogExpunge *e1 = p1;
	const ModifyLogExpunge *e2 = p2;

	return e1->uid1 < e2->uid1 ? -1 : e1->uid1 > e2->uid1 ? 1 : 0;
}

const ModifyLogExpunge *
mail_modifylog_seq_get_expunges(MailModifyLog *log,
				unsigned int first_seq,
				unsigned int last_seq,
				unsigned int *expunges_before)
{
	ModifyLogRecord *rec, *end_rec;
	ModifyLogExpunge *expunges, *arr;
	unsigned int last_pos_seq, before, max_records;

	i_assert(log->index->lock_type != MAIL_LOCK_UNLOCK);

	*expunges_before = 0;

	if (!mmap_update(log, FALSE))
		return NULL;

	/* find the first expunged message that affects our range */
	rec = (ModifyLogRecord *) ((char *) log->mmap_base +
				   log->synced_position);
	end_rec = (ModifyLogRecord *) ((char *) log->mmap_base +
				       log->mmap_used_length);

	while (rec < end_rec) {
		if (rec->type == RECORD_TYPE_EXPUNGE && rec->seq1 <= last_seq)
			break;
		rec++;
	}

	if (rec >= end_rec) {
		/* none found */
		return &no_expunges;
	}

	/* allocate memory for the returned array. the file size - synced
	   position should be quite near the amount of memory we need, unless
	   there's lots of FLAGS_CHANGED records which is why there's the
	   second check to make sure it's not unneededly large. */
	max_records = (log->mmap_used_length -
		       MODIFYLOG_FILE_POSITION(log, rec)) /
		sizeof(ModifyLogRecord);
	if (max_records > last_seq - first_seq + 1)
		max_records = last_seq - first_seq + 1;

	expunges = arr = t_malloc((max_records+1) * sizeof(ModifyLogExpunge));

	/* last_pos_seq is updated all the time to contain the last_seq
	   comparable to current record's seq. number */
	last_pos_seq = last_seq;

	before = 0;
	for (; rec < end_rec; rec++) {
		if (rec->type != RECORD_TYPE_EXPUNGE)
			continue;

		if (rec->seq1 + before < first_seq) {
			/* before our range */
			before += rec->seq2 - rec->seq1 + 1;
		} else if (rec->seq1 + before <= last_seq &&
			   rec->seq2 + before >= first_seq) {
			/* within our range, at least partially */
			if (max_records-- == 0) {
				/* log contains more data than it should
				   have - must be corrupted. */
				modifylog_set_corrupted(log,
					"Contains more data than expected");
				return NULL;
			}

			arr->uid1 = rec->uid1;
			arr->uid2 = rec->uid2;
			arr->seq_count = rec->seq2 -rec->seq1 + 1;
			arr++;
		}
	}

	arr->uid1 = arr->uid2 = 0;

	/* sort the UID array, not including the terminating 0 */
	qsort(expunges, (unsigned int) (arr - expunges),
	      sizeof(ModifyLogExpunge), compare_expunge);

	*expunges_before = before;
	return expunges;
}

const ModifyLogExpunge *
mail_modifylog_uid_get_expunges(MailModifyLog *log,
				unsigned int first_uid,
				unsigned int last_uid,
				unsigned int *expunges_before)
{
	/* pretty much copy&pasted from sequence code above ..
	   kind of annoying */
	ModifyLogRecord *rec, *end_rec;
	ModifyLogExpunge *expunges, *arr;
	unsigned int before, max_records;

	i_assert(log->index->lock_type != MAIL_LOCK_UNLOCK);

	*expunges_before = 0;

	if (!mmap_update(log, FALSE))
		return NULL;

	/* find the first expunged message that affects our range */
	rec = (ModifyLogRecord *) ((char *) log->mmap_base +
				   log->synced_position);
	end_rec = (ModifyLogRecord *) ((char *) log->mmap_base +
				       log->mmap_used_length);

	while (rec < end_rec) {
		if (rec->type == RECORD_TYPE_EXPUNGE && rec->uid1 <= last_uid)
			break;
		rec++;
	}

	if (rec >= end_rec) {
		/* none found */
		return &no_expunges;
	}

	/* allocate memory for the returned array. the file size - synced
	   position should be quite near the amount of memory we need, unless
	   there's lots of FLAGS_CHANGED records which is why there's the
	   second check to make sure it's not unneededly large. */
	max_records = (log->mmap_used_length -
		       MODIFYLOG_FILE_POSITION(log, rec)) /
		sizeof(ModifyLogRecord);
	if (max_records > last_uid - first_uid + 1)
		max_records = last_uid - first_uid + 1;

	expunges = arr = t_malloc((max_records+1) * sizeof(ModifyLogExpunge));

	before = 0;
	for (; rec < end_rec; rec++) {
		if (rec->type != RECORD_TYPE_EXPUNGE)
			continue;

                if (rec->uid1 < first_uid) {
			/* before our range */
			before += rec->seq2 - rec->seq1 + 1;
		} else if (rec->uid1 <= last_uid && rec->uid2 >= first_uid) {
			/* within our range */
			if (max_records-- == 0) {
				/* log contains more data than it should
				   have - must be corrupted. */
				modifylog_set_corrupted(log,
					"Contains more data than expected");
				return NULL;
			}

			arr->uid1 = rec->uid1;
			arr->uid2 = rec->uid2;
			arr->seq_count = rec->seq2 -rec->seq1 + 1;
			arr++;
		}
	}

	arr->uid1 = arr->uid2 = 0;

	/* sort the UID array, not including the terminating 0 */
	qsort(expunges, (unsigned int) (arr - expunges),
	      sizeof(ModifyLogExpunge), compare_expunge);

	*expunges_before = before;
	return expunges;
}

unsigned int mail_modifylog_get_expunge_count(MailModifyLog *log)
{
	ModifyLogRecord *rec, *end_rec;
	unsigned int expunges;

	i_assert(log->index->lock_type != MAIL_LOCK_UNLOCK);

	if (!mmap_update(log, FALSE))
		return 0;

	/* find the first expunged message that affects our range */
	rec = (ModifyLogRecord *) ((char *) log->mmap_base +
				   log->synced_position);
	end_rec = (ModifyLogRecord *) ((char *) log->mmap_base +
				       log->mmap_used_length);

	expunges = 0;
	while (rec < end_rec) {
		if (rec->type == RECORD_TYPE_EXPUNGE)
			expunges += rec->seq2 -rec->seq1 + 1;
		rec++;
	}

	return expunges;
}
