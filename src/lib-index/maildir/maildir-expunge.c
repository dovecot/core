/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "maildir-index.h"
#include "mail-index-util.h"

#include <unistd.h>

static int maildir_expunge_mail_file(struct mail_index *index,
				     struct mail_index_record *rec,
				     const char **fname)
{
	const char *path;
	int new_dir;

	*fname = maildir_get_location(index, rec, &new_dir);
	if (*fname == NULL)
		return -1;

	/* if we're in out-of-space condition, reset it since we'll probably
	   have enough space now. */
	index->maildir_keep_new = FALSE;
	if (index->next_dirty_flush != 0)
		index->next_dirty_flush = ioloop_time;

	if (new_dir) {
		/* probably in new/ dir */
		path = t_strconcat(index->mailbox_path, "/new/", *fname, NULL);
		if (unlink(path) == 0)
			return 1;

		if (errno == EACCES)
			return -1;
		if (errno != ENOENT) {
			index_set_error(index, "unlink(%s) failed: %m", path);
			return -1;
		}
	}

	path = t_strconcat(index->mailbox_path, "/cur/", *fname, NULL);
	if (unlink(path) == 0)
		return 1;

	if (errno == EACCES)
		return -1;

	if (errno != ENOENT) {
		index_set_error(index, "unlink(%s) failed: %m", path);
		return -1;
	}

	return 0;
}

int maildir_expunge_mail(struct mail_index *index,
			 struct mail_index_record *rec)
{
	const char *fname;
	int i, ret, found;

	for (i = 0;; i++) {
		ret = maildir_expunge_mail_file(index, rec, &fname);
		if (ret > 0)
			break;
		if (ret < 0)
			return FALSE;

		if (i == 10) {
			index_set_error(index, "Filename keeps changing, "
					"expunge failed: %s", fname);
			return FALSE;
		}

		if (!maildir_index_sync_readonly(index, fname, &found))
			return FALSE;

		if (!found) {
			/* syncing didn't find it, it's already deleted */
			return TRUE;
		}
	}

	/* cur/ was updated, set it dirty-synced */
	index->maildir_cur_dirty = ioloop_time;
	index->file_sync_stamp = ioloop_time;
	return TRUE;
}
