/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "maildir-index.h"
#include "mail-index-util.h"

#include <stdio.h>

static int handle_error(struct mail_index *index,
			const char *path, const char *new_path)
{
	if (errno == ENOENT)
		return 0;

	if (ENOSPACE(errno)) {
		index->nodiskspace = TRUE;
		return -2;
	}

	if (errno == EACCES)
		index->mailbox_readonly = TRUE;
	else {
		index_set_error(index, "rename(%s, %s) failed: %m",
				path, new_path);
	}

	return -1;
}

static int maildir_rename_mail_file(struct mail_index *index,
				    struct mail_index_record *rec,
				    const char *old_fname, const char *new_path)
{
	const char *path;

	if ((rec->index_flags & INDEX_MAIL_FLAG_MAILDIR_NEW) != 0) {
		/* probably in new/ dir */
		path = t_strconcat(index->mailbox_path, "/new/",
				   old_fname, NULL);
		if (rename(path, new_path) == 0)
			return 1;

		if (errno != ENOENT)
			return handle_error(index, path, new_path);
	}

	path = t_strconcat(index->mailbox_path, "/cur/", old_fname, NULL);
	if (rename(path, new_path) == 0)
		return 1;

	return handle_error(index, path, new_path);
}

static int maildir_rename_mail(struct mail_index *index,
			       struct mail_index_record *rec,
			       enum mail_flags flags, const char **new_fname_r)
{
	const char *old_fname, *new_fname, *new_path;
	int i, ret, found;

	new_fname = new_path = NULL;

	i = 0;
	do {
		/* we need to update the flags in the file name */
		old_fname = maildir_get_location(index, rec);
		if (old_fname == NULL)
			return FALSE;

		if (new_path == NULL) {
			new_fname = maildir_filename_set_flags(old_fname,
							       flags);
                        *new_fname_r = new_fname;
			new_path = t_strconcat(index->mailbox_path,
					       "/cur/", new_fname, NULL);
		}

		if (strcmp(old_fname, new_fname) == 0)
			ret = 1;
		else {
			ret = maildir_rename_mail_file(index, rec, old_fname,
						       new_path);
			if (ret == -1)
				return FALSE;

			if (ret == 1) {
				if (index->maildir_keep_new &&
				    (rec->index_flags &
				     INDEX_MAIL_FLAG_MAILDIR_NEW) != 0) {
					/* looks like we have some more space
					   again, see if we could move mails
					   from new/ to cur/ again */
					index->maildir_keep_new = FALSE;
					rec->index_flags &=
						~INDEX_MAIL_FLAG_MAILDIR_NEW;
				}

				/* cur/ was updated, set it dirty-synced */
                                index->file_sync_stamp = ioloop_time;
				index->maildir_cur_dirty = ioloop_time;
			}

		}
		if (ret == 0) {
			if (!maildir_index_sync_readonly(index, old_fname,
							 &found))
				return FALSE;
			if (!found)
				break;
		}

		i++;
	} while (i < 10 && ret == 0);

	if (ret != 1) {
		/* we couldn't actually rename() the file now.
		   leave it's flags dirty so they get changed later. */
		rec->index_flags |= INDEX_MAIL_FLAG_DIRTY;
	}
	return TRUE;
}

int maildir_index_update_flags(struct mail_index *index,
			       struct mail_index_record *rec, unsigned int seq,
			       enum mail_flags flags, int external_change)
{
	struct mail_index_update *update;
	const char *new_fname;
	int ret;

	t_push();
	if (!maildir_rename_mail(index, rec, flags, &new_fname)) {
		t_pop();
		return FALSE;
	}

	/* update the filename in index */
	update = index->update_begin(index, rec);
	index->update_field(update, DATA_FIELD_LOCATION, new_fname, 0);

	if (!index->update_end(update))
		ret = FALSE;
	else if (!mail_index_update_flags(index, rec, seq, flags,
					  external_change))
		ret = FALSE;
	else
		ret = TRUE;
	t_pop();

	return ret;
}
