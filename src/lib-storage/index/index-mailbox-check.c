/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "index-storage.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

struct index_notify_file {
	struct index_notify_file *next;

	char *path;
	time_t last_stamp;
};

struct index_notify_io {
	struct index_notify_io *next;
	struct io *io;
	int fd;
};

static void check_timeout(void *context)
{
	struct index_mailbox *ibox = context;
	struct index_notify_file *file;
	struct stat st;
	time_t last_check;
	int notify;

	/* check changes only when we can also notify of new mail */
	last_check = I_MAX(ibox->sync_last_check, ibox->notify_last_check);
	if ((unsigned int)(ioloop_time - last_check) <
	    ibox->min_notify_interval)
		return;

	ibox->notify_last_check = ioloop_time;

	notify = ibox->notify_pending;
	for (file = ibox->notify_files; file != NULL; file = file->next) {
		if (stat(file->path, &st) == 0 &&
		    file->last_stamp != st.st_mtime)
			file->last_stamp = st.st_mtime;
	}

	if (notify) {
		ibox->notify_last_sent = ioloop_time;
		ibox->notify_pending = FALSE;
		ibox->notify_callback(&ibox->box, ibox->notify_context);
	}
}

static void notify_callback(void *context)
{
	struct index_mailbox *ibox = context;

	ibox->notify_last_check = ioloop_time;
	if ((unsigned int)(ioloop_time - ibox->notify_last_sent) >=
	    ibox->min_notify_interval) {
		ibox->notify_last_sent = ioloop_time;
                ibox->notify_pending = FALSE;
		ibox->notify_callback(&ibox->box, ibox->notify_context);
	} else {
		ibox->notify_pending = TRUE;
	}
}

void index_mailbox_check_add(struct index_mailbox *ibox,
			     const char *path, int dir)
{
	struct index_notify_file *file;
	struct stat st;
	struct io *io;
	struct index_notify_io *aio;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd >= 0) {
		io = io_add(fd, dir ? IO_DIR_NOTIFY : IO_FILE_NOTIFY,
			    notify_callback, ibox);
		if (io != NULL) {
			aio = i_new(struct index_notify_io, 1);
			aio->io = io;
			aio->fd = fd;
			aio->next = ibox->notify_ios;
			ibox->notify_ios = aio;
		}
	}

	file = i_new(struct index_notify_file, 1);
	file->path = i_strdup(path);
	if (fd < 0)
		file->last_stamp = stat(path, &st) < 0 ? 0 : st.st_mtime;
	else
		file->last_stamp = fstat(fd, &st) < 0 ? 0 : st.st_mtime;

	file->next = ibox->notify_files;
        ibox->notify_files = file;

	if (ibox->notify_to == NULL)
		ibox->notify_to = timeout_add(1000, check_timeout, ibox);
}

void index_mailbox_check_remove_all(struct index_mailbox *ibox)
{
	struct index_notify_file *file;
	struct index_notify_io *aio;

	/* reset notify stamp */
	ibox->notify_last_sent = 0;

	while (ibox->notify_files != NULL) {
		file = ibox->notify_files;
		ibox->notify_files = file->next;

                i_free(file->path);
		i_free(file);
	}

	while (ibox->notify_ios != NULL) {
		aio = ibox->notify_ios;
		ibox->notify_ios = aio->next;

		io_remove(aio->io);
		if (close(aio->fd) < 0)
			i_error("close(notify_io) failed: %m");
		i_free(aio);
	}

	if (ibox->notify_to != NULL) {
		timeout_remove(ibox->notify_to);
		ibox->notify_to = NULL;
	}
}
