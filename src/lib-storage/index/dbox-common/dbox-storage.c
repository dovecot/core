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
