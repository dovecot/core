/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

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
};

static void check_timeout(struct index_mailbox *ibox)
{
	struct index_notify_file *file;
	struct stat st;
	bool notify;

	notify = ibox->notify_pending;
	for (file = ibox->notify_files; file != NULL; file = file->next) {
		if (stat(file->path, &st) == 0 &&
		    file->last_stamp != st.st_mtime) {
			file->last_stamp = st.st_mtime;
			notify = TRUE;
		}
	}

	if (notify) {
		ibox->notify_last_sent = ioloop_time;
		ibox->notify_pending = FALSE;
		ibox->box.notify_callback(&ibox->box, ibox->box.notify_context);
	}
}

static void notify_callback(struct index_mailbox *ibox)
{
	timeout_reset(ibox->notify_to);

	/* don't notify more often than once a second */
	if (ioloop_time > ibox->notify_last_sent) {
		ibox->notify_last_sent = ioloop_time;
                ibox->notify_pending = FALSE;
		ibox->box.notify_callback(&ibox->box, ibox->box.notify_context);
	} else {
		ibox->notify_pending = TRUE;
	}
}

void index_mailbox_check_add(struct index_mailbox *ibox,
			     const char *path)
{
	struct index_notify_file *file;
	struct stat st;
	struct io *io = NULL;
	struct index_notify_io *aio;

	(void)io_add_notify(path, notify_callback, ibox, &io);
	if (io != NULL) {
		aio = i_new(struct index_notify_io, 1);
		aio->io = io;
		aio->next = ibox->notify_ios;
		ibox->notify_ios = aio;
	}

	file = i_new(struct index_notify_file, 1);
	file->path = i_strdup(path);
	file->last_stamp = stat(path, &st) < 0 ? 0 : st.st_mtime;

	file->next = ibox->notify_files;
	ibox->notify_files = file;

	/* we still add a timeout if we don't have one already,
	 * because we don't know what happens with [di]notify
	 * when the filesystem is remote (NFS, ...) */
	if (ibox->notify_to == NULL) {
		ibox->notify_to =
			timeout_add(ibox->box.notify_min_interval * 1000,
				    check_timeout, ibox);
	}
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

		io_remove(&aio->io);
		i_free(aio);
	}

	if (ibox->notify_to != NULL)
		timeout_remove(&ibox->notify_to);
}
