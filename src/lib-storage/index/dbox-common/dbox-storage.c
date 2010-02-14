/* Copyright (c) 2007-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "mkdir-parents.h"
#include "unlink-old-files.h"
#include "mailbox-uidvalidity.h"
#include "mailbox-list-private.h"
#include "index-storage.h"
#include "dbox-storage.h"

#include <stdio.h>

void dbox_storage_get_list_settings(const struct mail_namespace *ns ATTR_UNUSED,
				    struct mailbox_list_settings *set)
{
	if (set->layout == NULL)
		set->layout = MAILBOX_LIST_NAME_FS;
	if (set->subscription_fname == NULL)
		set->subscription_fname = DBOX_SUBSCRIPTION_FILE_NAME;
	if (set->maildir_name == NULL)
		set->maildir_name = DBOX_MAILDIR_NAME;
	if (set->mailbox_dir_name == NULL)
		set->mailbox_dir_name = DBOX_MAILBOX_DIR_NAME;
}

uint32_t dbox_get_uidvalidity_next(struct mailbox_list *list)
{
	const char *path;

	path = mailbox_list_get_path(list, NULL,
				     MAILBOX_LIST_PATH_TYPE_CONTROL);
	path = t_strconcat(path, "/"DBOX_UIDVALIDITY_FILE_NAME, NULL);
	return mailbox_uidvalidity_next(list, path);
}

void dbox_notify_changes(struct mailbox *box)
{
	const char *dir, *path;

	if (box->notify_callback == NULL)
		index_mailbox_check_remove_all(box);
	else {
		dir = mailbox_list_get_path(box->list, box->name,
					    MAILBOX_LIST_PATH_TYPE_INDEX);
		path = t_strdup_printf("%s/"DBOX_INDEX_PREFIX".log", dir);
		index_mailbox_check_add(box, path);
	}
}

static bool
dbox_cleanup_if_exists(struct mailbox_list *list, const char *path)
{
	struct stat st;

	if (stat(path, &st) < 0)
		return FALSE;

	/* check once in a while if there are temp files to clean up */
	if (st.st_atime > st.st_ctime + DBOX_TMP_DELETE_SECS) {
		/* there haven't been any changes to this directory since we
		   last checked it. */
	} else if (st.st_atime < ioloop_time - DBOX_TMP_SCAN_SECS) {
		/* time to scan */
		const char *prefix =
			mailbox_list_get_global_temp_prefix(list);

		(void)unlink_old_files(path, prefix,
				       ioloop_time - DBOX_TMP_DELETE_SECS);
	}
	return TRUE;
}

static int dbox_mailbox_create_indexes(struct mailbox *box,
				       const struct mailbox_update *update)
{
	struct dbox_storage *storage = (struct dbox_storage *)box->storage;
	const char *origin;
	mode_t mode;
	gid_t gid;

	mailbox_list_get_dir_permissions(box->list, NULL, &mode, &gid, &origin);
	if (mkdir_parents_chgrp(box->path, mode, gid, origin) == 0) {
		/* create indexes immediately with the dbox header */
		if (index_storage_mailbox_open(box, FALSE) < 0)
			return -1;
		if (storage->v.mailbox_create_indexes(box, update) < 0)
			return -1;
	} else if (errno != EEXIST) {
		if (!mail_storage_set_error_from_errno(box->storage)) {
			mail_storage_set_critical(box->storage,
				"mkdir(%s) failed: %m", box->path);
		}
		return -1;
	}
	return 0;
}

int dbox_mailbox_open(struct mailbox *box)
{
	if (dbox_cleanup_if_exists(box->list, box->path)) {
		return index_storage_mailbox_open(box, FALSE);
	} else if (errno == ENOENT) {
		if (strcmp(box->name, "INBOX") == 0 &&
		    (box->list->ns->flags & NAMESPACE_FLAG_INBOX) != 0) {
			/* INBOX always exists, create it */
			if (dbox_mailbox_create_indexes(box, NULL) < 0)
				return -1;
			return box->opened ? 0 :
				index_storage_mailbox_open(box, FALSE);
		}

		mail_storage_set_error(box->storage, MAIL_ERROR_NOTFOUND,
			T_MAIL_ERR_MAILBOX_NOT_FOUND(box->name));
		return -1;
	} else if (errno == EACCES) {
		mail_storage_set_critical(box->storage, "%s",
			mail_error_eacces_msg("stat", box->path));
		return -1;
	} else {
		mail_storage_set_critical(box->storage,
					  "stat(%s) failed: %m", box->path);
		return -1;
	}
}

int dbox_mailbox_create(struct mailbox *box,
			const struct mailbox_update *update, bool directory)
{
	struct dbox_storage *storage = (struct dbox_storage *)box->storage;

	if (directory &&
	    (box->list->props & MAILBOX_LIST_PROP_NO_NOSELECT) == 0)
		return 0;

	if (index_storage_mailbox_open(box, FALSE) < 0)
		return -1;
	if (storage->v.mailbox_create_indexes(box, update) < 0)
		return -1;
	return 0;
}

int dbox_list_iter_is_mailbox(struct mailbox_list_iterate_context *ctx ATTR_UNUSED,
			      const char *dir, const char *fname,
			      const char *mailbox_name ATTR_UNUSED,
			      enum mailbox_list_file_type type,
			      enum mailbox_info_flags *flags)
{
	const char *path, *maildir_path;
	struct stat st, st2;
	int ret = 1;

	/* try to avoid stat() with these checks */
	if (type != MAILBOX_LIST_FILE_TYPE_DIR &&
	    type != MAILBOX_LIST_FILE_TYPE_SYMLINK &&
	    type != MAILBOX_LIST_FILE_TYPE_UNKNOWN) {
		/* it's a file */
		*flags |= MAILBOX_NOSELECT | MAILBOX_NOINFERIORS;
		return 0;
	}

	/* need to stat() then */
	path = t_strconcat(dir, "/", fname, NULL);
	if (stat(path, &st) == 0) {
		if (!S_ISDIR(st.st_mode)) {
			/* non-directory */
			*flags |= MAILBOX_NOSELECT | MAILBOX_NOINFERIORS;
			ret = 0;
		} else if (st.st_nlink == 2) {
			/* no subdirectories */
			*flags |= MAILBOX_NOCHILDREN;
		} else if (*ctx->list->set.maildir_name != '\0') {
			/* default configuration: we have one directory
			   containing the mailboxes. if there are 3 links,
			   either this is a selectable mailbox without children
			   or non-selectable mailbox with children */
			if (st.st_nlink > 3)
				*flags |= MAILBOX_CHILDREN;
		} else {
			/* non-default configuration: all subdirectories are
			   child mailboxes. */
			if (st.st_nlink > 2)
				*flags |= MAILBOX_CHILDREN;
		}
	} else if (errno == ENOENT) {
		/* doesn't exist - probably a non-existing subscribed mailbox */
		*flags |= MAILBOX_NONEXISTENT;
	} else {
		/* non-selectable. probably either access denied, or symlink
		   destination not found. don't bother logging errors. */
		*flags |= MAILBOX_NOSELECT;
	}
	if ((*flags & (MAILBOX_NOSELECT | MAILBOX_NONEXISTENT)) == 0) {
		/* make sure it's a selectable mailbox */
		maildir_path = t_strconcat(path, "/",
					   ctx->list->set.maildir_name, NULL);
		if (stat(maildir_path, &st2) < 0 || !S_ISDIR(st2.st_mode))
			*flags |= MAILBOX_NOSELECT;
		if (st.st_nlink == 3 && *ctx->list->set.maildir_name != '\0') {
			/* now we know what link count 3 means. */
			if ((*flags & MAILBOX_NOSELECT) != 0)
				*flags |= MAILBOX_CHILDREN;
			else
				*flags |= MAILBOX_NOCHILDREN;
		}
	}
	return ret;
}
