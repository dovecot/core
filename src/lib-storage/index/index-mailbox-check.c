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
	int synced, sync_expunges;

	/* check changes only when we can also notify of new mail */
	if ((unsigned int) (ioloop_time - ibox->sync_last_check) <
	    ibox->min_newmail_notify_interval)
		return;

	ibox->sync_last_check = ioloop_time;

	synced = FALSE;
	sync_expunges = ibox->autosync_type != MAILBOX_SYNC_NO_EXPUNGES;

	for (file = ibox->autosync_files; file != NULL; file = file->next) {
		if (stat(file->path, &st) == 0 &&
		    file->last_stamp != st.st_mtime) {
			file->last_stamp = st.st_mtime;
			if (!synced) {
				ibox->box.sync(&ibox->box, sync_expunges);
				synced = TRUE;
			}
		}
	}
}

void index_mailbox_check_add(struct index_mailbox *ibox, const char *path)
{
	struct index_autosync_file *file;
	struct stat st;

	file = i_new(struct index_autosync_file, 1);
	file->path = i_strdup(path);
	file->last_stamp = stat(path, &st) < 0 ? 0 : st.st_mtime;

	file->next = ibox->autosync_files;
        ibox->autosync_files = file;

	if (ibox->autosync_to == NULL)
		ibox->autosync_to = timeout_add(1000, check_timeout, ibox);
}

void index_mailbox_check_remove_all(struct index_mailbox *ibox)
{
	struct index_autosync_file *file;

	while (ibox->autosync_files != NULL) {
		file = ibox->autosync_files;
		ibox->autosync_files = file->next;

                i_free(file->path);
		i_free(file);
	}

	if (ibox->autosync_to != NULL) {
		timeout_remove(ibox->autosync_to);
		ibox->autosync_to = NULL;
	}
}
