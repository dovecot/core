/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "mmap-util.h"
#include "mail-index.h"
#include "mail-index-util.h"
#include "mail-modifylog.h"

#include <stdlib.h>
#include <fcntl.h>

/* Maximum size for modify log (isn't exact) */
#define MAX_MODIFYLOG_SIZE 10240

#define MODIFYLOG_FILE_POSITION(log, ptr) \
	((int) ((char *) (ptr) - (char *) (log)->mmap_base))

struct _MailModifyLog {
	MailIndex *index;

	int fd;
	char *filepath;

	void *mmap_base;
	size_t mmap_length;

	ModifyLogHeader *header;
	size_t synced_position;
	unsigned int synced_id, mmaped_id;

	unsigned int modified:1;
	unsigned int dirty_mmap:1;
	unsigned int second_log:1;
};

static int file_lock(int fd, int wait_lock, int lock_type)
{
	struct flock fl;

	fl.l_type = lock_type;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;

	if (fcntl(fd, wait_lock ? F_SETLKW : F_SETLK, &fl) == -1) {
		if (errno == EACCES)
			return 0;
		return -1;
	}

	return 1;
}

/* Returns 1 = ok, 0 = failed to get the lock, -1 = error */
static int mail_modifylog_try_lock(MailModifyLog *log, int lock_type)
{
	int ret;

	ret = file_lock(log->fd, FALSE, lock_type);
	if (ret == -1) {
		index_set_error(log->index, "fcntl() failed with file %s: %m",
				log->filepath);
	}

	return ret;
}

static int mail_modifylog_wait_lock(MailModifyLog *log)
{
	if (file_lock(log->fd, TRUE, F_RDLCK) < 1) {
		index_set_error(log->index, "fcntl() failed with file %s: %m",
				log->filepath);
		return FALSE;
	}

	return TRUE;
}

/* returns 1 = yes, 0 = no, -1 = error */
static int mail_modifylog_have_other_users(MailModifyLog *log)
{
	int ret;

	/* try grabbing exclusive lock */
	ret = mail_modifylog_try_lock(log, F_WRLCK);
	if (ret == -1)
		return -1;

	/* revert back to shared lock */
	switch (mail_modifylog_try_lock(log, F_WRLCK)) {
	case 0:
		/* shouldn't happen */
		index_set_error(log->index, "fcntl(F_WRLCK -> F_RDLCK) "
				"failed with file %s", log->filepath);
		/* fall through */
	case -1:
		return -1;
	}

	return ret == 0 ? 1 : 0;
}

static int mmap_update(MailModifyLog *log)
{
	unsigned int extra;

	if (!log->dirty_mmap && log->mmaped_id == log->header->sync_id)
		return TRUE;

	if (log->mmap_base != NULL)
		(void)munmap(log->mmap_base, log->mmap_length);

	log->mmap_base = mmap_rw_file(log->fd, &log->mmap_length);
	if (log->mmap_base == MAP_FAILED) {
		log->mmap_base = NULL;
		log->header = NULL;
		index_set_error(log->index,
				"modify log: mmap() failed with file %s: %m",
				log->filepath);
		return FALSE;
	}

	if (log->mmap_length < sizeof(ModifyLogHeader)) {
		/* FIXME: we could do better.. */
		(void)unlink(log->filepath);
		i_assert(0);
	}

	extra = (log->mmap_length - sizeof(ModifyLogHeader)) %
		sizeof(ModifyLogRecord);

	if (extra != 0) {
		/* partial write or corrupted -
		   truncate the file to valid length */
		log->mmap_length -= extra;
		(void)ftruncate(log->fd, (off_t) log->mmap_length);
	}

	log->dirty_mmap = FALSE;
	log->header = log->mmap_base;
	log->mmaped_id = log->header->sync_id;
	return TRUE;
}

static MailModifyLog *mail_modifylog_new(MailIndex *index)
{
	MailModifyLog *log;

	log = i_new(MailModifyLog, 1);
	log->fd = -1;
	log->index = index;
	log->dirty_mmap = TRUE;

	index->modifylog = log;
	return log;
}

static void mail_modifylog_close(MailModifyLog *log)
{
	log->dirty_mmap = TRUE;

	if (log->mmap_base != NULL) {
		munmap(log->mmap_base, log->mmap_length);
		log->mmap_base = NULL;
	}

	if (log->fd != -1) {
		(void)close(log->fd);
		log->fd = -1;
	}

	i_free(log->filepath);
}

static int mail_modifylog_init_fd(MailModifyLog *log, int fd,
				  const char *path)
{
        ModifyLogHeader hdr;

	/* write header */
	memset(&hdr, 0, sizeof(hdr));
	hdr.indexid = log->index->indexid;

	if (write(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
		index_set_error(log->index, "write() failed for modify "
				"log %s: %m", path);
		return FALSE;
	}

	if (ftruncate(fd, sizeof(hdr)) == -1) {
		index_set_error(log->index, "ftruncate() failed for modify "
				"log %s: %m", path);
		return FALSE;
	}

	return TRUE;
}

static int mail_modifylog_open_and_init_file(MailModifyLog *log,
					     const char *path)
{
	int fd, ret;

	fd = open(path, O_RDWR | O_CREAT, 0660);
	if (fd == -1) {
		index_set_error(log->index, "Error opening modify log "
				"file %s: %m", path);
		return FALSE;
	}

	ret = file_lock(fd, FALSE, F_WRLCK);
	if (ret == -1) {
		index_set_error(log->index, "Error locking modify log "
				"file %s: %m", path);
	}

	if (ret == 1 && mail_modifylog_init_fd(log, fd, path)) {
		mail_modifylog_close(log);

		log->fd = fd;
		log->filepath = i_strdup(path);
		return TRUE;
	}

	(void)close(fd);
	return FALSE;
}

int mail_modifylog_create(MailIndex *index)
{
	MailModifyLog *log;
	const char *path;

	i_assert(index->lock_type == MAIL_LOCK_EXCLUSIVE);

	log = mail_modifylog_new(index);

	path = t_strconcat(log->index->filepath, ".log", NULL);
	if (!mail_modifylog_open_and_init_file(log, path) ||
	    !mail_modifylog_wait_lock(log) ||
	    !mmap_update(log)) {
		/* fatal failure */
		mail_modifylog_free(log);
		return FALSE;
	}

	log->synced_id = log->header->sync_id;
	log->synced_position = log->mmap_length;
	return TRUE;
}

/* Returns 1 = ok, 0 = full, -1 = error */
static int mail_modifylog_open_and_verify(MailModifyLog *log, const char *path)
{
	ModifyLogHeader hdr;
	int fd, ret;

	fd = open(path, O_RDWR);
	if (fd == -1) {
		if (errno != ENOENT) {
			index_set_error(log->index, "Can't open modify log "
					"file %s: %m", path);
		}
		return -1;
	}

	ret = 1;
	if (read(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
		index_set_error(log->index, "read() failed when for modify "
				"log file %s: %m", path);
		ret = -1;
	}

	if (ret != -1 && hdr.indexid != log->index->indexid) {
		index_set_error(log->index, "IndexID mismatch for modify log "
				"file %s", path);
		ret = -1;
	}

	if (ret != -1 && hdr.sync_id == SYNC_ID_FULL) {
		/* full */
		ret = 0;
	}

	if (ret == 1) {
		log->fd = fd;
		log->filepath = i_strdup(path);
	} else {
		(void)close(fd);
	}

	return ret;
}

static int mail_modifylog_find_or_create(MailModifyLog *log)
{
	const char *path1, *path2;
	int i;

	for (i = 0; i < 2; i++) {
		/* first try <index>.log */
		path1 = t_strconcat(log->index->filepath, ".log", NULL);
		if (mail_modifylog_open_and_verify(log, path1) == 1)
			return TRUE;

		/* then <index>.log.2 */
		path2 = t_strconcat(log->index->filepath, ".log.2", NULL);
		if (mail_modifylog_open_and_verify(log, path2) == 1)
			return TRUE;

		/* try creating/reusing them */
		if (mail_modifylog_open_and_init_file(log, path1))
			return TRUE;

		if (mail_modifylog_open_and_init_file(log, path2))
			return TRUE;

		/* maybe the file was just switched, check the logs again */
	}

	index_set_error(log->index, "We could neither use nor create "
			"the modify log for index %s", log->index->filepath);
	return FALSE;
}

int mail_modifylog_open_or_create(MailIndex *index)
{
	MailModifyLog *log;

	log = mail_modifylog_new(index);

	if (!mail_modifylog_find_or_create(log) ||
	    !mail_modifylog_wait_lock(log) ||
	    !mmap_update(log)) {
		/* fatal failure */
		mail_modifylog_free(log);
		return FALSE;
	}

	log->synced_id = log->header->sync_id;
	log->synced_position = log->mmap_length;
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
	if (!log->modified)
		return TRUE;

	if (log->mmap_base != NULL) {
		if (msync(log->mmap_base, log->mmap_length, MS_SYNC) == -1) {
			index_set_error(log->index, "msync() failed for %s: %m",
					log->filepath);
			return FALSE;
		}
	}

	if (fsync(log->fd) == -1) {
		index_set_error(log->index, "fsync() failed for %s: %m",
				log->filepath);
		return FALSE;
	}

	log->modified = FALSE;
	return TRUE;
}

static int mail_modifylog_append(MailModifyLog *log, ModifyLogRecord *rec,
				 int external_change)
{
	i_assert(log->index->lock_type == MAIL_LOCK_EXCLUSIVE);
	i_assert(rec->seq != 0);
	i_assert(rec->uid != 0);

	if (!external_change) {
		switch (mail_modifylog_have_other_users(log)) {
		case 0:
			/* we're the only one having this log open,
			   no need for modify log. */
			return TRUE;
		case -1:
			return FALSE;
		}
	}

	if (lseek(log->fd, 0, SEEK_END) == -1) {
		index_set_error(log->index, "lseek() failed with file %s: %m",
				log->filepath);
		return FALSE;
	}

	if (write(log->fd, rec, sizeof(ModifyLogRecord)) !=
	    sizeof(ModifyLogRecord)) {
		index_set_error(log->index, "Error appending to file %s: %m",
				log->filepath);
		return FALSE;
	}

	log->header->sync_id++;
	log->modified = TRUE;
	log->dirty_mmap = TRUE;

	if (!external_change) {
		log->synced_id = log->header->sync_id;
		log->synced_position += sizeof(ModifyLogRecord);
	}
	return TRUE;
}

int mail_modifylog_add_expunge(MailModifyLog *log, unsigned int seq,
			       unsigned int uid, int external_change)
{
	ModifyLogRecord rec;

	/* expunges must not be added when log isn't synced */
	i_assert(external_change || log->synced_id == log->header->sync_id);

	rec.type = RECORD_TYPE_EXPUNGE;
	rec.seq = seq;
	rec.uid = uid;
	return mail_modifylog_append(log, &rec, external_change);
}

int mail_modifylog_add_flags(MailModifyLog *log, unsigned int seq,
			     unsigned int uid, int external_change)
{
	ModifyLogRecord rec;

	rec.type = RECORD_TYPE_FLAGS_CHANGED;
	rec.seq = seq;
	rec.uid = uid;
	return mail_modifylog_append(log, &rec, external_change);
}

ModifyLogRecord *mail_modifylog_get_nonsynced(MailModifyLog *log,
					      unsigned int *count)
{
	ModifyLogRecord *rec, *end_rec;

	i_assert(log->index->lock_type != MAIL_LOCK_UNLOCK);

	*count = 0;
	if (!mmap_update(log))
		return NULL;

	i_assert(log->synced_position <= log->mmap_length);
	i_assert(log->synced_position >= sizeof(ModifyLogHeader));

	rec = (ModifyLogRecord *) ((char *) log->mmap_base +
				   log->synced_position);
	end_rec = (ModifyLogRecord *) ((char *) log->mmap_base +
				       log->mmap_length);
	*count = (unsigned int) (end_rec - rec);
	return rec;
}

static int mail_modifylog_switch_file(MailModifyLog *log)
{
	MailIndex *index = log->index;

	mail_modifylog_free(log);
	return mail_modifylog_open_or_create(index);
}

static void mail_modifylog_try_switch_file(MailModifyLog *log)
{
	const char *path;

	path = t_strconcat(log->index->filepath,
			   log->second_log ? ".log" : ".log.2", NULL);

	if (mail_modifylog_open_and_init_file(log, path))
		log->header->sync_id = SYNC_ID_FULL;
}

int mail_modifylog_mark_synced(MailModifyLog *log)
{
	i_assert(log->index->lock_type != MAIL_LOCK_UNLOCK);

	if (log->header->sync_id == SYNC_ID_FULL) {
		/* log file is full, switch to next one */
		return mail_modifylog_switch_file(log);
	}

	if (log->synced_id == log->header->sync_id) {
		/* we are already synced */
		return TRUE;
	}

	log->synced_id = log->header->sync_id;
	log->synced_position = log->mmap_length;

	log->modified = TRUE;

	if (log->mmap_length > MAX_MODIFYLOG_SIZE) {
		/* if the other file isn't locked, switch to it */
		mail_modifylog_try_switch_file(log);
		return TRUE;
	}

	return TRUE;
}

static int compare_uint(const void *p1, const void *p2)
{
	const unsigned int *u1 = p1;
	const unsigned int *u2 = p2;

	return *u1 < *u2 ? -1 : *u1 > *u2 ? 1 : 0;
}

const unsigned int *
mail_modifylog_seq_get_expunges(MailModifyLog *log,
				unsigned int first_seq,
				unsigned int last_seq,
				unsigned int *expunges_before)
{
	ModifyLogRecord *rec, *end_rec;
	unsigned int last_pos_seq, before, max_records, *arr, *expunges;

	i_assert(log->index->lock_type != MAIL_LOCK_UNLOCK);

	*expunges_before = 0;

	if (!mmap_update(log))
		return NULL;

	/* find the first expunged message that affects our range */
	rec = (ModifyLogRecord *) ((char *) log->mmap_base +
				   log->synced_position);
	end_rec = (ModifyLogRecord *) ((char *) log->mmap_base +
				       log->mmap_length);

	while (rec < end_rec) {
		if (rec->type == RECORD_TYPE_EXPUNGE && rec->seq <= last_seq)
			break;
		rec++;
	}

	if (rec >= end_rec) {
		/* none found */
		expunges = t_malloc(sizeof(unsigned int));
		*expunges = 0;
		return expunges;
	}

	/* allocate memory for the returned array. the file size - synced
	   position should be quite near the amount of memory we need, unless
	   there's lots of FLAGS_CHANGED records which is why there's the
	   second check to make sure it's not unneededly large. */
	max_records = (log->mmap_length - MODIFYLOG_FILE_POSITION(log, rec)) /
		sizeof(ModifyLogRecord);
	if (max_records > last_seq - first_seq + 1)
		max_records = last_seq - first_seq + 1;

	expunges = arr = t_malloc((max_records+1) * sizeof(unsigned int));

	/* last_pos_seq is updated all the time to contain the last_seq
	   comparable to current record's seq. number */
	last_pos_seq = last_seq;

	before = 0;
	for (; rec < end_rec; rec++) {
		if (rec->type != RECORD_TYPE_EXPUNGE)
			continue;

		if (rec->seq + before < first_seq) {
			/* before our range */
			before++;
			last_pos_seq--;
		} else if (rec->seq <= last_pos_seq) {
			/* within our range */
			last_pos_seq--;

			if (max_records-- == 0) {
				/* log contains more data than it should
				   have - must be corrupted. */
				index_set_error(log->index,
						"Modify log %s is corrupted",
						log->filepath);
				return NULL;
			}

			*arr++ = rec->uid;
		}
	}
	*arr = 0;

	/* sort the UID array, not including the terminating 0 */
	qsort(expunges, (unsigned int) (arr - expunges), sizeof(unsigned int),
	      compare_uint);

	*expunges_before = before;
	return expunges;
}

const unsigned int *
mail_modifylog_uid_get_expunges(MailModifyLog *log,
				unsigned int first_uid,
				unsigned int last_uid)
{
	/* pretty much copy&pasted from sequence code above ..
	   kind of annoying */
	ModifyLogRecord *rec, *end_rec;
	unsigned int before, max_records, *arr, *expunges;

	i_assert(log->index->lock_type != MAIL_LOCK_UNLOCK);

	if (!mmap_update(log))
		return NULL;

	/* find the first expunged message that affects our range */
	rec = (ModifyLogRecord *) ((char *) log->mmap_base +
				   log->synced_position);
	end_rec = (ModifyLogRecord *) ((char *) log->mmap_base +
				       log->mmap_length);

	while (rec < end_rec) {
		if (rec->type == RECORD_TYPE_EXPUNGE && rec->uid <= last_uid)
			break;
		rec++;
	}

	if (rec >= end_rec) {
		/* none found */
		expunges = t_malloc(sizeof(unsigned int));
		*expunges = 0;
		return expunges;
	}

	/* allocate memory for the returned array. the file size - synced
	   position should be quite near the amount of memory we need, unless
	   there's lots of FLAGS_CHANGED records which is why there's the
	   second check to make sure it's not unneededly large. */
	max_records = (log->mmap_length - MODIFYLOG_FILE_POSITION(log, rec)) /
		sizeof(ModifyLogRecord);
	if (max_records > last_uid - first_uid + 1)
		max_records = last_uid - first_uid + 1;

	expunges = arr = t_malloc((max_records+1) * sizeof(unsigned int));

	before = 0;
	while (rec < end_rec) {
		if (rec->type == RECORD_TYPE_EXPUNGE &&
		    rec->uid >= first_uid && rec->uid <= last_uid) {
			/* within our range */
			if (max_records-- == 0) {
				/* log contains more data than it should
				   have - must be corrupted. */
				index_set_error(log->index,
						"Modify log %s is corrupted",
						log->filepath);
				return NULL;
			}
			*arr++ = rec->uid;
		}
		rec++;
	}
	*arr = 0;

	/* sort the UID array, not including the terminating 0 */
	qsort(expunges, (unsigned int) (arr - expunges), sizeof(unsigned int),
	      compare_uint);

	return expunges;
}
