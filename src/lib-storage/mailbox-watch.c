/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "mail-storage-private.h"
#include "mailbox-watch.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#define NOTIFY_DELAY_MSECS 500

struct mailbox_notify_file {
	struct mailbox_notify_file *next;

	char *path;
	struct stat last_st;
	struct io *io_notify;
};

static void notify_delay_callback(struct mailbox *box)
{
	timeout_remove(&box->to_notify_delay);
	box->notify_callback(box, box->notify_context);
}

static void notify_timeout(struct mailbox *box)
{
	struct mailbox_notify_file *file;
	struct stat st;
	bool notify = FALSE;

	for (file = box->notify_files; file != NULL; file = file->next) {
		if (stat(file->path, &st) == 0 &&
		    ST_CHANGED(file->last_st, st)) {
			file->last_st = st;
			notify = TRUE;
		}
	}

	if (notify)
		notify_delay_callback(box);
}

static void notify_callback(struct mailbox *box)
{
	timeout_reset(box->to_notify);

	if (box->to_notify_delay == NULL) {
		box->to_notify_delay =
			timeout_add_short(NOTIFY_DELAY_MSECS,
					  notify_delay_callback, box);
	}
}

void mailbox_watch_add(struct mailbox *box, const char *path)
{
	const struct mail_storage_settings *set = box->storage->set;
	struct mailbox_notify_file *file;
	struct stat st;
	struct io *io = NULL;

	i_assert(set->mailbox_idle_check_interval > 0);

	(void)io_add_notify(path, notify_callback, box, &io);

	file = i_new(struct mailbox_notify_file, 1);
	file->path = i_strdup(path);
	if (stat(path, &st) == 0)
		file->last_st = st;
	file->io_notify = io;

	file->next = box->notify_files;
	box->notify_files = file;

	/* we still add a timeout if we don't have one already,
	 * because we don't know what happens with [di]notify
	 * when the filesystem is remote (NFS, ...) */
	if (box->to_notify == NULL) {
		box->to_notify =
			timeout_add(set->mailbox_idle_check_interval * 1000,
				    notify_timeout, box);
	}
}

void mailbox_watch_remove_all(struct mailbox *box)
{
	struct mailbox_notify_file *file;

	while (box->notify_files != NULL) {
		file = box->notify_files;
		box->notify_files = file->next;

		io_remove(&file->io_notify);
                i_free(file->path);
		i_free(file);
	}

	timeout_remove(&box->to_notify_delay);
	timeout_remove(&box->to_notify);
}

static void notify_extract_callback(struct mailbox *box ATTR_UNUSED)
{
	i_unreached();
}

int mailbox_watch_extract_notify_fd(struct mailbox *box, const char **reason_r)
{
	struct ioloop *ioloop;
	struct mailbox_notify_file *file;
	struct io *io, *const *iop;
	ARRAY(struct io *) temp_ios;
	int ret;
	bool failed = FALSE;

	/* add all the notify IOs to a new ioloop. */
	ioloop = io_loop_create();

	t_array_init(&temp_ios, 8);
	for (file = box->notify_files; file != NULL && !failed; file = file->next) {
		switch (io_add_notify(file->path, notify_extract_callback, box, &io)) {
		case IO_NOTIFY_ADDED:
			array_push_back(&temp_ios, &io);
			break;
		case IO_NOTIFY_NOTFOUND:
			*reason_r = t_strdup_printf(
				"%s not found - can't watch it", file->path);
			failed = TRUE;
			break;
		case IO_NOTIFY_NOSUPPORT:
			*reason_r = "Filesystem notifications not supported";
			failed = TRUE;
			break;
		}
	}
	if (failed)
		ret = -1;
	else if (array_count(&temp_ios) == 0) {
		*reason_r = "Mailbox has no IO notifications";
		ret = -1;
	} else {
		ret = io_loop_extract_notify_fd(ioloop);
		if (ret == -1)
			*reason_r = "Couldn't extra notify fd";
	}
	array_foreach(&temp_ios, iop) {
		struct io *io = *iop;
		io_remove(&io);
	}
	io_loop_destroy(&ioloop);
	return ret;
}
