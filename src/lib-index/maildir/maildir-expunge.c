/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "maildir-index.h"
#include "mail-index-util.h"

#include <unistd.h>

static int maildir_expunge_mail_file(struct mail_index *index,
				     struct mail_index_record *rec,
				     const char **fname)
{
	const char *path;

	*fname = maildir_get_location(index, rec);
	if (*fname == NULL)
		return -1;

	if ((rec->index_flags & INDEX_MAIL_FLAG_MAILDIR_NEW) != 0) {
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
			return TRUE;
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
}
