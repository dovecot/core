/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "fs-api.h"
#include "mkdir-parents.h"
#include "unlink-old-files.h"
#include "mailbox-uidvalidity.h"
#include "mailbox-list-private.h"
#include "index-storage.h"
#include "dbox-storage.h"

#include <stdio.h>
#include <dirent.h>
#include <unistd.h>

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

int dbox_storage_create(struct mail_storage *_storage,
			struct mail_namespace *ns,
			const char **error_r ATTR_UNUSED)
{
	struct dbox_storage *storage = (struct dbox_storage *)_storage;
	const struct mail_storage_settings *set = _storage->set;
	struct fs_settings fs_set;

	memset(&fs_set, 0, sizeof(fs_set));
	fs_set.temp_file_prefix = mailbox_list_get_global_temp_prefix(ns->list);

	if (*set->mail_attachment_fs != '\0') T_BEGIN {
		const char *name, *args, *dir;

		args = strchr(set->mail_attachment_fs, ' ');
		if (args == NULL) {
			name = set->mail_attachment_fs;
			args = "";
		} else {
			name = t_strdup_until(set->mail_attachment_fs, args++);
		}
		dir = mail_user_home_expand(_storage->user,
					    set->mail_attachment_dir);
		storage->attachment_dir = p_strdup(_storage->pool, dir);
		storage->attachment_fs = fs_init(name, args, &fs_set);
	} T_END;
	return 0;
}

void dbox_storage_destroy(struct mail_storage *_storage)
{
	struct dbox_storage *storage = (struct dbox_storage *)_storage;

	if (storage->attachment_fs != NULL)
		fs_deinit(&storage->attachment_fs);
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

int dbox_mailbox_open(struct mailbox *box)
{
	if (dbox_cleanup_if_exists(box->list, box->path)) {
		return index_storage_mailbox_open(box, FALSE);
	} else if (errno == ENOENT) {
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

static int dir_is_empty(struct mail_storage *storage, const char *path)
{
	DIR *dir;
	struct dirent *d;
	int ret = 1;

	dir = opendir(path);
	if (dir == NULL) {
		if (errno == ENOENT) {
			/* race condition with DELETE/RENAME? */
			return 1;
		}
		mail_storage_set_critical(storage, "opendir(%s) failed: %m",
					  path);
		return -1;
	}
	while ((d = readdir(dir)) != NULL) {
		if (*d->d_name == '.')
			continue;

		ret = 0;
		break;
	}
	if (closedir(dir) < 0) {
		mail_storage_set_critical(storage, "closedir(%s) failed: %m",
					  path);
		ret = -1;
	}
	return ret;
}

int dbox_mailbox_create(struct mailbox *box,
			const struct mailbox_update *update, bool directory)
{
	struct dbox_storage *storage = (struct dbox_storage *)box->storage;
	struct mail_index_sync_ctx *sync_ctx;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	const char *alt_path;
	struct stat st;
	int ret;

	if (directory &&
	    (box->list->props & MAILBOX_LIST_PROP_NO_NOSELECT) == 0)
		return 0;

	if (mailbox_open(box) < 0)
		return -1;

	/* if alt path already exists and contains files, rebuild storage so
	   that we don't start overwriting files. */
	alt_path = mailbox_list_get_path(box->list, box->name,
					 MAILBOX_LIST_PATH_TYPE_ALT_MAILBOX);
	if (alt_path != NULL && stat(alt_path, &st) == 0) {
		ret = dir_is_empty(box->storage, alt_path);
		if (ret < 0)
			return -1;
		if (ret == 0) {
			mail_storage_set_critical(&storage->storage,
				"Mailbox %s has existing files in alt path, "
				"rebuilding storage to avoid losing messages",
				box->vname);
			storage->v.set_mailbox_corrupted(box);
			return -1;
		}
		/* dir is empty, ignore it */
	}

	/* use syncing as a lock */
	ret = mail_index_sync_begin(box->index, &sync_ctx, &view, &trans, 0);
	if (ret <= 0) {
		i_assert(ret != 0);
		mail_storage_set_index_error(box);
		return -1;
	}

	if (mail_index_get_header(view)->uid_validity == 0) {
		if (storage->v.mailbox_create_indexes(box, update, trans) < 0) {
			mail_index_sync_rollback(&sync_ctx);
			return -1;
		}
	}

	return mail_index_sync_commit(&sync_ctx);
}
