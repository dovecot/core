/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "maildir-index.h"
#include "mail-index-util.h"

#include <unistd.h>

static int do_expunge(struct mail_index *index, const char *path, void *context)
{
	int *found = context;

	if (unlink(path) < 0) {
		if (errno == ENOENT)
			return 0;
		if (errno == EACCES) {
			index->mailbox_readonly = TRUE;
			return 1;
		}

		index_set_error(index, "unlink(%s) failed: %m", path);
		return -1;
	}

	*found = TRUE;
	return 1;
}

int maildir_expunge_mail(struct mail_index *index,
			 struct mail_index_record *rec)
{
	int found = FALSE;

	if (!maildir_file_do(index, rec, do_expunge, &found))
		return FALSE;

	if (found) {
		/* if we're in out-of-space condition, reset it since we'll
		   probably have enough space now. */
		index->maildir_keep_new = FALSE;
		if (index->next_dirty_flags_flush != 0)
			index->next_dirty_flags_flush = ioloop_time;

		/* cur/ was updated, set it dirty-synced */
		index->sync_dirty_stamp = ioloop_time;
		index->sync_stamp = ioloop_time;
	}
	return TRUE;
}
