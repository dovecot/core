/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "home-expand.h"
#include "mkdir-parents.h"
#include "unlink-directory.h"
#include "subscription-file/subscription-file.h"
#include "maildir-index.h"
#include "maildir-storage.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#define CREATE_MODE 0770 /* umask() should limit it more */

struct rename_context {
	int found;
	size_t oldnamelen;
	const char *newname;
};

extern struct mail_storage maildir_storage;
extern struct mailbox maildir_mailbox;

static const char *maildirs[] = { "cur", "new", "tmp", NULL  };

static struct mail_storage *maildir_create(const char *data, const char *user)
{
	struct mail_storage *storage;
	const char *root_dir, *inbox_dir, *index_dir, *control_dir;
	const char *home, *path, *p;

	inbox_dir = root_dir = index_dir = control_dir = NULL;

	if (data == NULL || *data == '\0') {
		/* we'll need to figure out the maildir location ourself.
		   it's either root dir if we've already chroot()ed, or
		   $HOME/Maildir otherwise */
		if (access("/cur", R_OK|W_OK|X_OK) == 0)
			root_dir = "/";
		else {
			home = getenv("HOME");
			if (home != NULL) {
				path = t_strconcat(home, "/Maildir", NULL);
				if (access(path, R_OK|W_OK|X_OK) == 0)
					root_dir = path;
			}
		}
	} else {
		/* <Maildir> [:INBOX=<dir>] [:INDEX=<dir>] [:CONTROL=<dir>] */
		p = strchr(data, ':');
		if (p == NULL)
			root_dir = data;
		else {
			root_dir = t_strdup_until(data, p);

			do {
				p++;
				if (strncmp(p, "INBOX=", 6) == 0)
					inbox_dir = t_strcut(p+6, ':');
				else if (strncmp(p, "INDEX=", 6) == 0)
					index_dir = t_strcut(p+6, ':');
				else if (strncmp(p, "CONTROL=", 8) == 0)
					control_dir = t_strcut(p+8, ':');
				p = strchr(p, ':');
			} while (p != NULL);
		}
	}

	if (root_dir == NULL)
		return NULL;

	if (index_dir == NULL)
		index_dir = root_dir;
	else if (strcmp(index_dir, "MEMORY") == 0)
		index_dir = NULL;

	storage = i_new(struct mail_storage, 1);
	memcpy(storage, &maildir_storage, sizeof(struct mail_storage));

	storage->dir = i_strdup(home_expand(root_dir));
	storage->inbox_file = i_strdup(home_expand(inbox_dir));
	storage->index_dir = i_strdup(home_expand(index_dir));
	storage->control_dir = i_strdup(home_expand(control_dir));
	storage->user = i_strdup(user);
	storage->callbacks = i_new(struct mail_storage_callbacks, 1);
	index_storage_init(storage);
	return storage;
}

static void maildir_free(struct mail_storage *storage)
{
	index_storage_deinit(storage);

	i_free(storage->dir);
	i_free(storage->inbox_file);
	i_free(storage->index_dir);
	i_free(storage->control_dir);
	i_free(storage->user);
	i_free(storage->error);
	i_free(storage->callbacks);
	i_free(storage);
}

static int maildir_autodetect(const char *data)
{
	struct stat st;

	data = t_strcut(data, ':');

	return stat(t_strconcat(data, "/cur", NULL), &st) == 0 &&
		S_ISDIR(st.st_mode);
}

static int maildir_is_valid_create_name(struct mail_storage *storage,
					const char *name)
{
	if (name[0] == '\0' || name[strlen(name)-1] == storage->hierarchy_sep ||
	    strchr(name, '*') != NULL || strchr(name, '%') != NULL)
		return FALSE;

	if (full_filesystem_access)
		return TRUE;

	return *name != '~' &&
		strchr(name, '/') == NULL && strchr(name, '\\') == NULL;
}

static int maildir_is_valid_existing_name(const char *name)
{
	if (name[0] == '\0' || name[0] == '.')
		return FALSE;

	if (full_filesystem_access)
		return TRUE;

	return *name != '~' &&
		strchr(name, '/') == NULL && strchr(name, '\\') == NULL;
}

static const char *maildir_get_absolute_path(const char *name, int unlink)
{
	const char *p;

	name = home_expand(name);

	p = strrchr(name, '/');
	if (p == NULL)
		return name;
	return t_strconcat(t_strdup_until(name, p+1),
			   unlink ? ".." : ".", p+1, NULL);
}

const char *maildir_get_path(struct mail_storage *storage, const char *name)
{
	if (full_filesystem_access && (*name == '/' || *name == '~'))
		return maildir_get_absolute_path(name, FALSE);

	if (strcasecmp(name, "INBOX") == 0) {
		return storage->inbox_file != NULL ?
			storage->inbox_file : storage->dir;
	}

	return t_strconcat(storage->dir, "/.", name, NULL);
}

static const char *
maildir_get_unlink_path(struct mail_storage *storage, const char *name)
{
	if (full_filesystem_access && (*name == '/' || *name == '~'))
		return maildir_get_absolute_path(name, TRUE);

	return maildir_get_path(storage, t_strconcat(".", name, NULL));
}

static const char *maildir_get_index_path(struct mail_storage *storage,
					  const char *name)
{
	if (storage->index_dir == NULL)
		return NULL;

	if (strcasecmp(name, "INBOX") == 0 && storage->inbox_file != NULL)
		return storage->inbox_file;

	if (full_filesystem_access && (*name == '/' || *name == '~'))
		return maildir_get_absolute_path(name, FALSE);

	return t_strconcat(storage->index_dir, "/.", name, NULL);
}

static const char *maildir_get_control_path(struct mail_storage *storage,
					    const char *name)
{
	if (storage->control_dir == NULL)
		return maildir_get_path(storage, name);

	if (full_filesystem_access && (*name == '/' || *name == '~'))
		return maildir_get_absolute_path(name, FALSE);

	return t_strconcat(storage->control_dir, "/.", name, NULL);
}

static int mkdir_verify(struct mail_storage *storage,
			const char *dir, int verify)
{
	struct stat st;

	if (verify) {
		if (lstat(dir, &st) == 0)
			return TRUE;

		if (errno != ENOENT) {
			mail_storage_set_critical(storage,
						  "lstat(%s) failed: %m", dir);
			return FALSE;
		}
	}

	if (mkdir(dir, CREATE_MODE) < 0 && (errno != EEXIST || !verify)) {
		if (errno != EEXIST && (!verify || errno != ENOENT)) {
			mail_storage_set_critical(storage,
						  "mkdir(%s) failed: %m", dir);
		}
		return FALSE;
	}

	return TRUE;
}

/* create or fix maildir, ignore if it already exists */
static int create_maildir(struct mail_storage *storage,
			  const char *dir, int verify)
{
	const char **tmp, *path;

	if (!verify && !mkdir_verify(storage, dir, verify))
		return FALSE;

	for (tmp = maildirs; *tmp != NULL; tmp++) {
		path = t_strconcat(dir, "/", *tmp, NULL);

		if (!mkdir_verify(storage, path, verify)) {
			if (!verify || errno != ENOENT)
				return FALSE;

			/* small optimization. if we're verifying, we don't
			   check that the root dir actually exists unless we
			   fail here. */
			if (!mkdir_verify(storage, dir, verify))
				return FALSE;
			if (!mkdir_verify(storage, path, verify))
				return FALSE;
		}
	}

	return TRUE;
}

static int create_index_dir(struct mail_storage *storage, const char *name)
{
	const char *dir;

	if (storage->index_dir == NULL)
		return TRUE;

	if (strcmp(storage->index_dir, storage->dir) == 0 ||
	    (strcmp(name, "INBOX") == 0 &&
	     strcmp(storage->index_dir, storage->inbox_file) == 0))
		return TRUE;

	dir = t_strconcat(storage->index_dir, "/.", name, NULL);
	if (mkdir_parents(dir, CREATE_MODE) == -1 && errno != EEXIST) {
		mail_storage_set_critical(storage, "mkdir(%s) failed: %m", dir);
		return FALSE;
	}

	return TRUE;
}

static int create_control_dir(struct mail_storage *storage, const char *name)
{
	const char *dir;

	if (storage->control_dir == NULL)
		return TRUE;

	dir = t_strconcat(storage->control_dir, "/.", name, NULL);
	if (mkdir_parents(dir, CREATE_MODE) < 0 && errno != EEXIST) {
		mail_storage_set_critical(storage, "mkdir(%s) failed: %m", dir);
		return FALSE;
	}

	return TRUE;
}

static int verify_inbox(struct mail_storage *storage)
{
	const char *inbox;

	if (storage->inbox_file == NULL) {
		/* first make sure the cur/ new/ and tmp/ dirs exist
		   in root dir */
		if (!create_maildir(storage, storage->dir, TRUE))
			return FALSE;

		/* create the .INBOX directory */
		inbox = t_strconcat(storage->dir, "/.INBOX", NULL);
		if (!mkdir_verify(storage, inbox, TRUE))
			return FALSE;
	} else {
		if (!create_maildir(storage, storage->inbox_file, TRUE))
			return FALSE;
	}

	/* make sure the index directories exist */
	return create_index_dir(storage, "INBOX") &&
		create_control_dir(storage, "INBOX");
}

static struct mailbox *
maildir_open(struct mail_storage *storage, const char *name,
	     int readonly, int fast)
{
	struct index_mailbox *ibox;
	struct mail_index *index;
	const char *path, *index_dir, *control_dir;

	path = maildir_get_path(storage, name);
	index_dir = maildir_get_index_path(storage, name);
	control_dir = maildir_get_control_path(storage, name);

	index = index_storage_lookup_ref(index_dir);
	if (index == NULL) {
		index = maildir_index_alloc(path, index_dir, control_dir);
		index_storage_add(index);
	}

	ibox = index_storage_mailbox_init(storage, &maildir_mailbox,
					  index, name, readonly, fast);
	if (ibox != NULL)
		ibox->expunge_locked = maildir_expunge_locked;
	return (struct mailbox *) ibox;
}

static const char *inbox_fix_case(struct mail_storage *storage,
				  const char *name)
{
        if (strncasecmp(name, "INBOX", 5) == 0 &&
	    (name[5] == '\0' || name[5] == storage->hierarchy_sep)) {
		/* use same case with all INBOX folders or we'll get
		   into trouble */
		name = t_strconcat("INBOX", name+5, NULL);
	}

	return name;
}

static struct mailbox *
maildir_open_mailbox(struct mail_storage *storage,
		     const char *name, int readonly, int fast)
{
	const char *path;
	struct stat st;

	mail_storage_clear_error(storage);

	name = inbox_fix_case(storage, name);
	if (strcmp(name, "INBOX") == 0) {
		if (!verify_inbox(storage))
			return NULL;
		return maildir_open(storage, "INBOX", readonly, fast);
	}

	if (!maildir_is_valid_existing_name(name)) {
		mail_storage_set_error(storage, "Invalid mailbox name");
		return FALSE;
	}

	path = maildir_get_path(storage, name);
	if (stat(path, &st) == 0) {
		/* exists - make sure the required directories are also there */
		if (!create_maildir(storage, path, TRUE) ||
		    !create_index_dir(storage, name) ||
		    !create_control_dir(storage, name))
			return FALSE;

		return maildir_open(storage, name, readonly, fast);
	} else if (errno == ENOENT) {
		mail_storage_set_error(storage, "Mailbox doesn't exist: %s",
				       name);
		return NULL;
	} else {
		mail_storage_set_critical(storage, "stat(%s) failed: %m", path);
		return NULL;
	}
}

static int maildir_create_mailbox(struct mail_storage *storage,
				  const char *name, int only_hierarchy)
{
	const char *path;

	mail_storage_clear_error(storage);

	name = inbox_fix_case(storage, name);
	if (!maildir_is_valid_create_name(storage, name)) {
		mail_storage_set_error(storage, "Invalid mailbox name");
		return FALSE;
	}

	if (only_hierarchy) {
		/* no need to do anything */
		return TRUE;
	}

	path = maildir_get_path(storage, name);
	if (!create_maildir(storage, path, FALSE)) {
		if (errno == EEXIST) {
			mail_storage_set_error(storage,
					       "Mailbox already exists");
		}
		return FALSE;
	}

	return TRUE;
}

static int maildir_delete_mailbox(struct mail_storage *storage,
				  const char *name)
{
	struct stat st;
	const char *src, *dest, *index_dir;
	int count;

	mail_storage_clear_error(storage);

	name = inbox_fix_case(storage, name);
	if (strcasecmp(name, "INBOX") == 0) {
		mail_storage_set_error(storage, "INBOX can't be deleted.");
		return FALSE;
	}

	if (!maildir_is_valid_existing_name(name)) {
		mail_storage_set_error(storage, "Invalid mailbox name");
		return FALSE;
	}

	/* rename the .maildir into ..maildir which marks it as being
	   deleted. delete indexes before the actual maildir. this way we
	   never see partially deleted mailboxes. */
	src = maildir_get_path(storage, name);
	dest = maildir_get_unlink_path(storage, name);
	if (stat(src, &st) != 0 && errno == ENOENT) {
		mail_storage_set_error(storage, "Mailbox doesn't exist: %s",
				       name);
		return FALSE;
	}

	if (storage->index_dir != NULL && *name != '/' && *name != '~' &&
	    strcmp(storage->index_dir, storage->dir) != 0) {
		index_dir = t_strconcat(storage->index_dir, "/.", name, NULL);
		index_storage_destroy_unrefed();

		/* it can fail with some NFS implementations if indexes are
		   opened by another session.. can't really help it. */
		if (unlink_directory(index_dir, TRUE) < 0 &&
		    errno != ENOTEMPTY) {
			mail_storage_set_critical(storage,
				"unlink_directory(%s) failed: %m", index_dir);
			return FALSE;
		}
	}

	count = 0;
	while (rename(src, dest) < 0 && count < 2) {
		if (errno != EEXIST && errno != ENOTEMPTY) {
			mail_storage_set_critical(storage,
				"rename(%s, %s) failed: %m", src, dest);
			return FALSE;
		}

		/* ..dir already existed? delete it and try again */
		if (unlink_directory(dest, TRUE) < 0) {
			mail_storage_set_critical(storage,
				"unlink_directory(%s) failed: %m", dest);
			return FALSE;
		}
		count++;
	}

	if (unlink_directory(dest, TRUE) < 0 && errno != ENOTEMPTY) {
		mail_storage_set_critical(storage,
			"unlink_directory(%s) failed: %m", dest);

		/* it's already renamed to ..dir, which means it's deleted
		   as far as client is concerned. Report success. */
	}

	return TRUE;
}

static int rename_indexes(struct mail_storage *storage,
			  const char *oldname, const char *newname)
{
	const char *oldpath, *newpath;

	if (storage->index_dir == NULL ||
	    strcmp(storage->index_dir, storage->dir) == 0)
		return TRUE;

	/* Rename it's index. */
	oldpath = t_strconcat(storage->index_dir, "/.", oldname, NULL);
	newpath = t_strconcat(storage->index_dir, "/.", newname, NULL);

	if (rename(oldpath, newpath) < 0 && errno != ENOENT) {
		mail_storage_set_critical(storage, "rename(%s, %s) failed: %m",
					  oldpath, newpath);
		return FALSE;
	}

	return TRUE;
}

static int rename_subfolders(struct mail_storage *storage,
			     const char *oldname, const char *newname)
{
	struct mailbox_list_context *ctx;
        struct mailbox_list *list;
	const char *oldpath, *newpath, *new_listname;
	size_t oldnamelen;
	int sorted, ret;

	ret = 0;
	oldnamelen = strlen(oldname);

	ctx = storage->list_mailbox_init(storage,
					 t_strconcat(oldname, ".*", NULL),
					 MAILBOX_LIST_FAST_FLAGS, &sorted);
	while ((list = maildir_list_mailbox_next(ctx)) != NULL) {
		i_assert(oldnamelen <= strlen(list->name));

		t_push();
		new_listname = t_strconcat(newname,
					   list->name + oldnamelen, NULL);
		oldpath = maildir_get_path(storage, list->name);
		newpath = maildir_get_path(storage, new_listname);

		/* FIXME: it's possible to merge two folders if either one of
		   them doesn't have existing root folder. We could check this
		   but I'm not sure if it's worth it. It could be even
		   considered as a feature.

		   Anyway, the bug with merging is that if both folders have
		   identically named subfolder they conflict. Just ignore those
		   and leave them under the old folder. */
		if (rename(oldpath, newpath) == 0 ||
		    errno == EEXIST || errno == ENOTEMPTY)
			ret = 1;
		else {
			mail_storage_set_critical(storage,
						  "rename(%s, %s) failed: %m",
						  oldpath, newpath);
			ret = -1;
			t_pop();
			break;
		}

		(void)rename_indexes(storage, list->name, new_listname);
		t_pop();
	}

	if (!maildir_list_mailbox_deinit(ctx))
		return -1;
	return ret;
}

static int maildir_rename_mailbox(struct mail_storage *storage,
				  const char *oldname, const char *newname)
{
	const char *oldpath, *newpath;
	int ret, found;

	mail_storage_clear_error(storage);

	oldname = inbox_fix_case(storage, oldname);
	if (!maildir_is_valid_existing_name(oldname) ||
	    !maildir_is_valid_create_name(storage, newname)) {
		mail_storage_set_error(storage, "Invalid mailbox name");
		return FALSE;
	}

	if (strcmp(oldname, "INBOX") == 0) {
		mail_storage_set_error(storage,
				       "Renaming INBOX isn't supported.");
		return FALSE;
	}

	/* NOTE: it's possible to rename a nonexisting folder which has
	   subfolders. In that case we should ignore the rename() error. */
	oldpath = maildir_get_path(storage, oldname);
	newpath = maildir_get_path(storage, newname);

	ret = rename(oldpath, newpath);
	if (ret == 0 || errno == ENOENT) {
		(void)rename_indexes(storage, oldname, newname);

		found = ret == 0;
		ret = rename_subfolders(storage, oldname, newname);
		if (ret < 0)
			return FALSE;
		if (!found && ret == 0) {
			mail_storage_set_error(storage,
					       "Mailbox doesn't exist");
			return FALSE;
		}

		return TRUE;
	}

	if (errno == EEXIST) {
		mail_storage_set_error(storage,
				       "Target mailbox already exists");
		return FALSE;
	} else {
		mail_storage_set_critical(storage, "rename(%s, %s) failed: %m",
					  oldpath, newpath);
		return FALSE;
	}
}

static int maildir_get_mailbox_name_status(struct mail_storage *storage,
					   const char *name,
					   enum mailbox_name_status *status)
{
	struct stat st;
	const char *path;

	mail_storage_clear_error(storage);

	name = inbox_fix_case(storage, name);
	if (!maildir_is_valid_existing_name(name)) {
		*status = MAILBOX_NAME_INVALID;
		return TRUE;
	}

	path = maildir_get_path(storage, name);
	if (stat(path, &st) == 0) {
		*status = MAILBOX_NAME_EXISTS;
		return TRUE;
	}

	if (!maildir_is_valid_create_name(storage, name)) {
		*status = MAILBOX_NAME_INVALID;
		return TRUE;
	}

	if (errno == ENOENT) {
		*status = MAILBOX_NAME_VALID;
		return TRUE;
	} else {
		mail_storage_set_critical(storage, "stat(%s) failed: %m", path);
		return FALSE;
	}
}

static int maildir_storage_close(struct mailbox *box)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;
	int failed = FALSE;

        index_storage_init_lock_notify(ibox);
	if (!maildir_try_flush_dirty_flags(ibox->index, TRUE)) {
		mail_storage_set_index_error(ibox);
		failed = TRUE;
	}
	ibox->index->set_lock_notify_callback(ibox->index, NULL, NULL);

	return index_storage_mailbox_free(box) && !failed;
}

static void maildir_storage_auto_sync(struct mailbox *box,
				      enum mailbox_sync_type sync_type,
				      unsigned int min_newmail_notify_interval)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;

	ibox->autosync_type = sync_type;
	ibox->min_newmail_notify_interval = min_newmail_notify_interval;

        index_mailbox_check_remove_all(ibox);
	if (sync_type != MAILBOX_SYNC_NONE) {
		index_mailbox_check_add(ibox,
			t_strconcat(ibox->index->mailbox_path, "/new", NULL));
		index_mailbox_check_add(ibox,
			t_strconcat(ibox->index->mailbox_path, "/cur", NULL));
	}
}


struct mail_storage maildir_storage = {
	"maildir", /* name */

	'.', /* hierarchy_sep - can't be changed */

	maildir_create,
	maildir_free,
	maildir_autodetect,
	index_storage_set_callbacks,
	maildir_open_mailbox,
	maildir_create_mailbox,
	maildir_delete_mailbox,
	maildir_rename_mailbox,
	maildir_list_mailbox_init,
	maildir_list_mailbox_deinit,
	maildir_list_mailbox_next,
	subsfile_set_subscribed,
	maildir_get_mailbox_name_status,
	mail_storage_get_last_error,

	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, NULL, NULL,

	0
};

struct mailbox maildir_mailbox = {
	NULL, /* name */
	NULL, /* storage */

	maildir_storage_close,
	index_storage_get_status,
	index_storage_sync,
	maildir_storage_auto_sync,
	index_storage_expunge,
	index_storage_update_flags,
	maildir_storage_copy,
	index_storage_fetch_init,
	index_storage_fetch_deinit,
	index_storage_fetch_next,
	index_storage_fetch_uid,
	index_storage_fetch_seq,
        index_storage_search_get_sorting,
	index_storage_search_init,
	index_storage_search_deinit,
	index_storage_search_next,
	maildir_storage_save_init,
	maildir_storage_save_deinit,
	maildir_storage_save_next,
	mail_storage_is_inconsistency_error,

	FALSE,
	FALSE,
	FALSE
};
