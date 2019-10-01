/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "eacces-error.h"
#include "mailbox-log.h"

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

/* How often to reopen the log file to make sure that the changes are written
   to the latest file. The main problem here is if the value is too high the
   changes could be written to a file that was already rotated and deleted.
   That wouldn't happen in any real world situations though, since the file
   rotation time is probably measured in months or years. Still, each session
   rarely writes anything here, so the value can just as well be a pretty small
   one without any performance problems. */
#define MAILBOX_LOG_REOPEN_SECS (60)
#define MAILBOX_LOG_ROTATE_SIZE (1024*4)

struct mailbox_log {
	char *filepath, *filepath2;
	int fd;
	struct event *event;
	time_t open_timestamp;

	mode_t mode;
	gid_t gid;
	char *gid_origin;
};

struct mailbox_log_iter {
	struct mailbox_log *log;

	int fd;
	const char *filepath;

	struct mailbox_log_record buf[128];
	unsigned int idx, count;
	uoff_t offset;
	bool failed;
};

static void mailbox_log_close(struct mailbox_log *log);

struct mailbox_log *
mailbox_log_alloc(struct event *parent_event, const char *path)
{
	struct mailbox_log *log;

	log = i_new(struct mailbox_log, 1);
	log->event = event_create(parent_event);
	log->filepath = i_strdup(path);
	log->filepath2 = i_strconcat(path, ".2", NULL);
	log->mode = 0644;
	log->gid = (gid_t)-1;
	log->fd = -1;
	return log;
}

void mailbox_log_free(struct mailbox_log **_log)
{
	struct mailbox_log *log = *_log;

	*_log = NULL;

	mailbox_log_close(log);
	event_unref(&log->event);
	i_free(log->gid_origin);
	i_free(log->filepath);
	i_free(log->filepath2);
	i_free(log);
}

static void mailbox_log_close(struct mailbox_log *log)
{
	i_close_fd_path(&log->fd, log->filepath);
}

void mailbox_log_set_permissions(struct mailbox_log *log, mode_t mode,
				 gid_t gid, const char *gid_origin)
{
	log->mode = mode;
	log->gid = gid;
	i_free(log->gid_origin);
	log->gid_origin = i_strdup(gid_origin);
}

static int mailbox_log_open(struct mailbox_log *log)
{
	mode_t old_mode;

	i_assert(log->fd == -1);

	log->open_timestamp = ioloop_time;
	log->fd = open(log->filepath, O_RDWR | O_APPEND);
	if (log->fd != -1)
		return 0;

	/* try to create it */
	old_mode = umask(0666 ^ log->mode);
	log->fd = open(log->filepath, O_RDWR | O_APPEND | O_CREAT, 0666);
	umask(old_mode);

	if (log->fd == -1) {
		if (errno != EACCES)
			e_error(log->event, "creat(%s) failed: %m",
				log->filepath);
		else
			e_error(log->event, "%s",
				eacces_error_get("creat", log->filepath));
		return -1;
	}
	if (fchown(log->fd, (uid_t)-1, log->gid) < 0) {
		if (errno != EPERM)
			e_error(log->event, "fchown(%s) failed: %m",
				log->filepath);
		else {
			e_error(log->event, "%s",
				eperm_error_get_chgrp("fchown",
						      log->filepath, log->gid,
						      log->gid_origin));
		}
	}
	return 0;
}

static int mailbox_log_rotate_if_needed(struct mailbox_log *log)
{
	struct stat st;

	if (fstat(log->fd, &st) < 0) {
		e_error(log->event, "fstat(%s) failed: %m", log->filepath);
		return -1;
	}

	if (st.st_size < MAILBOX_LOG_ROTATE_SIZE)
		return 0;

	if (rename(log->filepath, log->filepath2) < 0 && errno != ENOENT) {
		e_error(log->event, "rename(%s, %s) failed: %m",
			log->filepath, log->filepath2);
		return -1;
	}
	return 0;
}

void mailbox_log_record_set_timestamp(struct mailbox_log_record *rec,
				      time_t stamp)
{
	cpu32_to_be_unaligned(stamp, rec->timestamp);
}

time_t mailbox_log_record_get_timestamp(const struct mailbox_log_record *rec)
{
	return (time_t) be32_to_cpu_unaligned(rec->timestamp);
}

int mailbox_log_append(struct mailbox_log *log,
		       const struct mailbox_log_record *rec)
{
	struct stat st;
	ssize_t ret;

	/* we don't have to be too strict about appending to the latest log
	   file. the records' ordering doesn't matter and iteration goes
	   through both logs anyway. still, if there's a long running session
	   it shouldn't keep writing to a rotated log forever. */
	if (log->open_timestamp/MAILBOX_LOG_REOPEN_SECS !=
	    ioloop_time/MAILBOX_LOG_REOPEN_SECS)
		mailbox_log_close(log);
	if (log->fd == -1) {
		if (mailbox_log_open(log) < 0)
			return -1;
		i_assert(log->fd != -1);
	}

	/* We don't bother with locking, atomic appends will protect us.
	   If they don't (NFS), the worst that can happen is that a few
	   records get overwritten (because they're all the same size).
	   This whole log isn't supposed to be super-reliable anyway. */
	ret = write(log->fd, rec, sizeof(*rec));
	if (ret < 0) {
		e_error(log->event, "write(%s) failed: %m", log->filepath);
		return -1;
	} else if (ret != sizeof(*rec)) {
		e_error(log->event, "write(%s) wrote %d/%u bytes", log->filepath,
			(int)ret, (unsigned int)sizeof(*rec));
		if (fstat(log->fd, &st) == 0) {
			if (ftruncate(log->fd, st.st_size - ret) < 0) {
				e_error(log->event, "ftruncate(%s) failed: %m",
					log->filepath);
			}
		}
		return -1;
	}

	(void)mailbox_log_rotate_if_needed(log);
	return 0;
}

static bool mailbox_log_iter_open_next(struct mailbox_log_iter *iter)
{
	i_close_fd_path(&iter->fd, iter->filepath);
	if (iter->filepath == NULL)
		iter->filepath = iter->log->filepath2;
	else if (iter->filepath == iter->log->filepath2)
		iter->filepath = iter->log->filepath;
	else
		return FALSE;

	iter->fd = open(iter->filepath, O_RDONLY | O_APPEND);
	if (iter->fd != -1)
		return TRUE;
	else if (errno == ENOENT) {
		if (iter->filepath == iter->log->filepath2)
			return mailbox_log_iter_open_next(iter);
	} else {
		e_error(iter->log->event, "open(%s) failed: %m", iter->filepath);
		iter->failed = TRUE;
	}
	return FALSE;
}

struct mailbox_log_iter *mailbox_log_iter_init(struct mailbox_log *log)
{
	struct mailbox_log_iter *iter;

	iter = i_new(struct mailbox_log_iter, 1);
	iter->log = log;
	iter->fd = -1;
	(void)mailbox_log_iter_open_next(iter);
	return iter;
}

const struct mailbox_log_record *
mailbox_log_iter_next(struct mailbox_log_iter *iter)
{
	const struct mailbox_log_record *rec;
	uoff_t offset;
	ssize_t ret;

	if (iter->idx == iter->count) {
		if (iter->fd == -1)
			return NULL;

		ret = pread(iter->fd, iter->buf, sizeof(iter->buf),
			    iter->offset);
		if (ret < 0) {
			e_error(iter->log->event, "pread(%s) failed: %m",
				iter->filepath);
			iter->failed = TRUE;
			return NULL;
		}
		if (ret == 0) {
			if (!mailbox_log_iter_open_next(iter))
				return NULL;
			iter->idx = iter->count = 0;
			iter->offset = 0;
			return mailbox_log_iter_next(iter);
		}
		iter->idx = 0;
		iter->count = ret / sizeof(iter->buf[0]);
		iter->offset += iter->count * sizeof(iter->buf[0]);
	}
	rec = &iter->buf[iter->idx++];
	if (rec->type < MAILBOX_LOG_RECORD_DELETE_MAILBOX ||
	    rec->type > MAILBOX_LOG_RECORD_UNSUBSCRIBE) {
		offset = iter->offset -
			(iter->count - iter->idx) * sizeof(iter->buf[0]);
		e_error(iter->log->event,
			"Corrupted mailbox log %s at offset %"PRIuUOFF_T": "
			"type=%d", iter->filepath, offset, rec->type);
		i_unlink(iter->filepath);
		return NULL;
	}
	return rec;
}

int mailbox_log_iter_deinit(struct mailbox_log_iter **_iter)
{
	struct mailbox_log_iter *iter = *_iter;
	int ret = iter->failed ? -1 : 0;

	*_iter = NULL;

	i_close_fd_path(&iter->fd, iter->filepath);
	i_free(iter);
	return ret;
}
