/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "hostpid.h"
#include "file-lock.h"
#include "message-size.h"
#include "message-part-serialize.h"
#include "mail-index.h"
#include "mail-index-util.h"

#include <unistd.h>
#include <fcntl.h>

int index_set_error(struct mail_index *index, const char *fmt, ...)
{
	va_list va;

	i_free(index->error);

	if (fmt == NULL)
		index->error = NULL;
	else {
		va_start(va, fmt);
		index->error = i_strdup_vprintf(fmt, va);
		va_end(va);

		i_error("%s", index->error);
	}

	return FALSE;
}

int index_set_corrupted(struct mail_index *index, const char *fmt, ...)
{
	va_list va;

	INDEX_MARK_CORRUPTED(index);
	index->inconsistent = TRUE;

	va_start(va, fmt);
	t_push();
	index_set_error(index, "Corrupted index file %s: %s",
			index->filepath, t_strdup_vprintf(fmt, va));
	t_pop();
	va_end(va);

	return FALSE;
}

int index_set_syscall_error(struct mail_index *index, const char *function)
{
	i_assert(function != NULL);

	if (ENOSPACE(errno)) {
		index->nodiskspace = TRUE;
		return FALSE;
	}

	index_set_error(index, "%s failed with index file %s: %m",
			function, index->filepath);
	return FALSE;
}

int index_file_set_syscall_error(struct mail_index *index, const char *filepath,
				 const char *function)
{
	i_assert(filepath != NULL);
	i_assert(function != NULL);

	if (ENOSPACE(errno)) {
		index->nodiskspace = TRUE;
		return FALSE;
	}

	index_set_error(index, "%s failed with file %s: %m",
			function, filepath);

	return FALSE;
}

void index_reset_error(struct mail_index *index)
{
	if (index->error != NULL) {
		i_free(index->error);
		index->error = NULL;
	}

	index->nodiskspace = FALSE;
}

int mail_index_create_temp_file(struct mail_index *index, const char **path)
{
	int fd;

	/* use ".temp.host.pid" as temporary file name. unlink() it first,
	   just to be sure it's not symlinked somewhere for some reason..
	   FIXME: this function should rather be removed entirely. With
	   in-memory indexes index->dir is NULL, so we fallback to /tmp
           so that mbox rewriting doesn't crash. */
	*path = t_strconcat(index->dir != NULL ? index->dir : "/tmp",
			    "/.temp.", my_hostname, ".", my_pid, NULL);
	(void)unlink(*path);

	/* usage of O_EXCL isn't exactly needed since the path should be
	   trusted, but it shouldn't hurt either - if creating file fails
	   because of it, it's because something must be wrong (race
	   condition). also, might not won't work through NFS but that
	   can't be helped. */
	fd = open(*path, O_RDWR | O_CREAT | O_EXCL, 0660);
	if (fd == -1) {
		if (ENOSPACE(errno))
			index->nodiskspace = TRUE;
		else {
			index_set_error(index, "Can't create temp index %s: %m",
					*path);
		}
	}

	return fd;
}

static void mail_index_lock_notify(unsigned int secs_left, void *context)
{
	struct mail_index *index = context;

	if (index->lock_notify_cb == NULL)
		return;

	index->lock_notify_cb(MAIL_LOCK_NOTIFY_INDEX_ABORT, secs_left,
			      index->lock_notify_context);
}

int mail_index_wait_lock(struct mail_index *index, int lock_type)
{
	int ret;

	ret = file_wait_lock_full(index->fd, lock_type, DEFAULT_LOCK_TIMEOUT,
				  mail_index_lock_notify, index);
	if (ret < 0)
		return index_set_syscall_error(index, "file_wait_lock()");

	if (ret == 0) {
		index_set_error(index, "Timeout while waiting for release of "
				"fcntl() lock for index file %s",
				index->filepath);
		index->index_lock_timeout = TRUE;
		return FALSE;
	}

	return TRUE;

}
