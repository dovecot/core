/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "hash.h"
#include "ioloop.h"
#include "maildir-index.h"
#include "mail-index-util.h"
#include "mail-cache.h"

#include <stdio.h>

static int update_filename(struct mail_index *index,
			   struct mail_index_record *rec)
{
	const char *old_fname, *old_path, *new_fname, *new_path;
	enum mail_index_record_flag flags;

	old_fname = maildir_get_location(index, rec, NULL);
	if (old_fname == NULL)
		return -1;

	flags = mail_cache_get_index_flags(index->cache, rec);

	old_path = t_strconcat(index->mailbox_path,
			       (flags & MAIL_INDEX_FLAG_MAILDIR_NEW) != 0 ?
			       "/new/" : "/cur/", old_fname, NULL);

	new_fname = maildir_filename_set_flags(old_fname, rec->msg_flags);
	new_path = t_strconcat(index->mailbox_path, "/cur/", new_fname, NULL);

	if (strcmp(old_path, new_path) == 0 ||
	    rename(old_path, new_path) == 0) {
		flags &= ~(MAIL_INDEX_FLAG_DIRTY | MAIL_INDEX_FLAG_MAILDIR_NEW);
		if (!mail_cache_update_index_flags(index->cache, rec, flags))
			return -1;
		return 1;
	} else {
		if (errno != ENOENT && errno != EACCES &&
		    !ENOSPACE(errno)) {
			index_set_error(index,
					"rename(%s, %s) failed: %m",
					old_path, new_path);
			return -1;
		}
		return 0;
	}
}

int maildir_try_flush_dirty_flags(struct mail_index *index, int force)
{
	struct mail_index_record *rec;
	int ret, dirty = FALSE;

	if (index->next_dirty_flush == 0 ||
	    (ioloop_time < index->next_dirty_flush && !force))
		return TRUE;

	if (!index->set_lock(index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	ret = mail_cache_lock(index->cache, !force);
	if (ret <= 0)
		return ret == 0;
        mail_cache_unlock_later(index->cache);

	rec = index->lookup(index, 1);
	while (rec != NULL) {
		if ((mail_cache_get_index_flags(index->cache, rec) &
		     MAIL_INDEX_FLAG_DIRTY) != 0) {
			ret = update_filename(index, rec);
			if (ret < 0)
				break;
			if (ret == 0)
				dirty = TRUE;
		}

		rec = index->next(index, rec);
	}

	if (ret < 0)
		return FALSE;

	if (!dirty) {
		index->header->flags &= ~MAIL_INDEX_HDR_FLAG_DIRTY_MESSAGES;
		index->next_dirty_flush = 0;
	} else {
		index->next_dirty_flush =
			ioloop_time + MAILDIR_DIRTY_FLUSH_TIMEOUT;
	}

	return TRUE;
}

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

static int maildir_rename_mail_file(struct mail_index *index, int new_dir,
				    const char *old_fname, const char *new_path)
{
	const char *path;

	if (new_dir) {
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
        enum mail_index_record_flag index_flags;
	int i, ret, found, new_dir;

	new_fname = new_path = NULL;

	i = 0;
	do {
		/* we need to update the flags in the file name */
		old_fname = maildir_get_location(index, rec, &new_dir);
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
			ret = maildir_rename_mail_file(index, new_dir,
						       old_fname, new_path);
			if (ret == -1)
				return FALSE;

			if (ret == 1) {
				if (index->maildir_keep_new && new_dir) {
					/* looks like we have some more space
					   again, see if we could move mails
					   from new/ to cur/ again */
					index->maildir_keep_new = FALSE;
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

	if (ret == 1)
		return TRUE;

	/* we couldn't actually rename() the file now.
	   leave it's flags dirty so they get changed later. */
	index_flags = mail_cache_get_index_flags(index->cache, rec);
	if ((index_flags & MAIL_INDEX_FLAG_DIRTY) == 0) {
		if (mail_cache_lock(index->cache, FALSE) <= 0)
			return FALSE;
		mail_cache_unlock_later(index->cache);

		index_flags |= MAIL_INDEX_FLAG_DIRTY;
		mail_cache_update_index_flags(index->cache, rec, index_flags);

		index->header->flags |= MAIL_INDEX_HDR_FLAG_DIRTY_MESSAGES;
	}

	index->next_dirty_flush =
		ioloop_time + MAILDIR_DIRTY_FLUSH_TIMEOUT;
	*new_fname_r = NULL;
	return TRUE;
}

int maildir_index_update_flags(struct mail_index *index,
			       struct mail_index_record *rec, unsigned int seq,
			       enum mail_flags flags, int external_change)
{
	const char *new_fname;
	int failed = FALSE;

	t_push();
	if (!maildir_rename_mail(index, rec, flags, &new_fname)) {
		t_pop();
		return FALSE;
	}

	if (new_fname != NULL) {
		maildir_index_update_filename(index, rec->uid,
					      new_fname, FALSE);
	}

	if (!failed && !mail_index_update_flags(index, rec, seq, flags,
						external_change))
		failed = TRUE;
	t_pop();

	return !failed;
}
