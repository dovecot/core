/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "index-storage.h"

#include <stdlib.h>
#include <sys/stat.h>

static void check_timeout(void *context)
{
	struct index_mailbox *ibox = context;
	struct index_autosync_file *file;
	struct stat st;
	int sync;

	/* check changes only when we can also notify of new mail */
	if ((unsigned int) (ioloop_time - ibox->sync_last_check) <
	    ibox->min_newmail_notify_interval)
		return;

	ibox->sync_last_check = ioloop_time;

	sync = ibox->autosync_pending;
	for (file = ibox->autosync_files; file != NULL; file = file->next) {
		if (stat(file->path, &st) == 0 &&
		    file->last_stamp != st.st_mtime)
			file->last_stamp = st.st_mtime;
	}

	if (sync) {
		ibox->box.sync(&ibox->box, ibox->autosync_flags);
                ibox->autosync_pending = FALSE;
	}
}

static void notify_callback(void *context)
{
	struct index_mailbox *ibox = context;

	if ((unsigned int) (ioloop_time - ibox->sync_last_check) >=
	    ibox->min_newmail_notify_interval) {
		ibox->sync_last_check = ioloop_time;
		ibox->box.sync(&ibox->box, ibox->autosync_flags);
                ibox->autosync_pending = FALSE;
	} else {
		ibox->autosync_pending = TRUE;
	}
}

void index_mailbox_check_add(struct index_mailbox *ibox,
			     const char *path, int dir)
{
	struct index_autosync_file *file;
	struct stat st;
	struct io *io;
	struct index_autosync_io *aio;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd >= 0) {
		io = io_add(fd, dir ? IO_DIR_NOTIFY : IO_FILE_NOTIFY,
			    notify_callback, ibox);
		if (io != NULL) {
			aio = i_new(struct index_autosync_io, 1);
			aio->io = io;
			aio->fd = fd;
			aio->next = ibox->autosync_ios;
			ibox->autosync_ios = aio;
		}
	}

	file = i_new(struct index_autosync_file, 1);
	file->path = i_strdup(path);
	if (fd < 0)
		file->last_stamp = stat(path, &st) < 0 ? 0 : st.st_mtime;
	else
		file->last_stamp = fstat(fd, &st) < 0 ? 0 : st.st_mtime;

	file->next = ibox->autosync_files;
        ibox->autosync_files = file;

	if (ibox->autosync_to == NULL)
		ibox->autosync_to = timeout_add(1000, check_timeout, ibox);
}

void index_mailbox_check_remove_all(struct index_mailbox *ibox)
{
	struct index_autosync_file *file;
	struct index_autosync_io *aio;

	while (ibox->autosync_files != NULL) {
		file = ibox->autosync_files;
		ibox->autosync_files = file->next;

                i_free(file->path);
		i_free(file);
	}

	while (ibox->autosync_ios != NULL) {
		aio = ibox->autosync_ios;
		ibox->autosync_ios = aio->next;

		io_remove(aio->io);
		if (close(aio->fd) < 0)
			i_error("close(autosync_io) failed: %m");
		i_free(aio);
	}

	if (ibox->autosync_to != NULL) {
		timeout_remove(ibox->autosync_to);
		ibox->autosync_to = NULL;
	}
}
