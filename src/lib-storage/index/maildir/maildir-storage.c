/* Copyright (C) 2002-2003 Timo Sirainen */

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

static struct mail_storage *
maildir_create(const char *data, const char *user,
	       const char *namespace, char hierarchy_sep)
{
	struct mail_storage *storage;
	const char *root_dir, *inbox_dir, *index_dir, *control_dir;
	const char *home, *path, *p;
	size_t len;

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

	/* strip trailing '/' */
	len = strlen(root_dir);
	if (root_dir[len-1] == '/')
		root_dir = t_strndup(root_dir, len-1);

	if (index_dir == NULL)
		index_dir = root_dir;
	else if (strcmp(index_dir, "MEMORY") == 0)
		index_dir = NULL;

	storage = i_new(struct mail_storage, 1);
	memcpy(storage, &maildir_storage, sizeof(struct mail_storage));

	if (hierarchy_sep != '\0')
		storage->hierarchy_sep = hierarchy_sep;
	storage->namespace = i_strdup(namespace);

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

	i_free(storage->namespace);
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

static int maildir_is_valid_create_name(const char *name)
{
	size_t len;

	len = strlen(name);
	if (len == 0 || name[0] == MAILDIR_FS_SEP ||
	    strchr(name, '*') != NULL || strchr(name, '%') != NULL)
		return FALSE;

	if (full_filesystem_access)
		return TRUE;

	if (*name == '~' || strchr(name, '/') != NULL)
		return FALSE;

	return TRUE;
}

static int maildir_is_valid_existing_name(const char *name)
{
	if (name[0] == '\0')
		return FALSE;

	if (full_filesystem_access)
		return TRUE;

	if (*name == '~' || strchr(name, '/') != NULL)
		return FALSE;

	return TRUE;
}

static const char *maildir_get_absolute_path(const char *name, int unlink)
{
	const char *p;

	name = home_expand(name);

	p = strrchr(name, '/');
	if (p == NULL)
		return name;
	return t_strconcat(t_strdup_until(name, p+1),
			   unlink ? MAILDIR_FS_SEP_S MAILDIR_FS_SEP_S :
			   MAILDIR_FS_SEP_S, p+1, NULL);
}

const char *maildir_fix_mailbox_name(struct mail_storage *storage,
				     const char *name, int remove_namespace)
{
	char *dup, *p, sep;
	size_t len;

	if (strncasecmp(name, "INBOX", 5) == 0 &&
	    (name[5] == '\0' || name[5] == storage->hierarchy_sep)) {
		/* use same case with all INBOX folders or we'll get
		   into trouble */
		name = t_strconcat("INBOX", name+5, NULL);
		if (name[5] == '\0') {
			/* don't check namespace with INBOX */
			return name;
		}
	}

	if (storage->namespace != NULL && remove_namespace) {
		len = strlen(storage->namespace);
		if (strncmp(storage->namespace, name, len) != 0) {
			i_panic("maildir: expecting namespace '%s' in name "
				"'%s'", storage->namespace, name);
		}
		name += len;
	}

	if (full_filesystem_access && (*name == '/' || *name == '~'))
		return name;

	sep = storage->hierarchy_sep;
	if (sep == MAILDIR_FS_SEP)
		return name;

	dup = t_strdup_noconst(name);
	for (p = dup; *p != '\0'; p++) {
		if (*p == sep)
			*p = MAILDIR_FS_SEP;
	}

	return dup;
}

const char *maildir_get_path(struct mail_storage *storage, const char *name)
{
	if (full_filesystem_access && (*name == '/' || *name == '~'))
		return maildir_get_absolute_path(name, FALSE);

	if (strcmp(name, "INBOX") == 0) {
		return storage->inbox_file != NULL ?
			storage->inbox_file : storage->dir;
	}

	return t_strconcat(storage->dir, "/"MAILDIR_FS_SEP_S, name, NULL);
}

static const char *
maildir_get_unlink_path(struct mail_storage *storage, const char *name)
{
	if (full_filesystem_access && (*name == '/' || *name == '~'))
		return maildir_get_absolute_path(name, TRUE);

	return maildir_get_path(storage,
				t_strconcat(MAILDIR_FS_SEP_S, name, NULL));
}

static const char *maildir_get_index_path(struct mail_storage *storage,
					  const char *name)
{
	if (storage->index_dir == NULL)
		return NULL;

	if (strcmp(name, "INBOX") == 0 && storage->inbox_file != NULL)
		return storage->inbox_file;

	if (full_filesystem_access && (*name == '/' || *name == '~'))
		return maildir_get_absolute_path(name, FALSE);

	return t_strconcat(storage->index_dir, "/"MAILDIR_FS_SEP_S, name, NULL);
}

static const char *maildir_get_control_path(struct mail_storage *storage,
					    const char *name)
{
	if (storage->control_dir == NULL)
		return maildir_get_path(storage, name);

	if (full_filesystem_access && (*name == '/' || *name == '~'))
		return maildir_get_absolute_path(name, FALSE);

	return t_strconcat(storage->control_dir, "/"MAILDIR_FS_SEP_S,
			   name, NULL);
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

	dir = t_strconcat(storage->index_dir, "/"MAILDIR_FS_SEP_S, name, NULL);
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

	dir = t_strconcat(storage->control_dir, "/"MAILDIR_FS_SEP_S,
			  name, NULL);
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
		inbox = t_strconcat(storage->dir,
				    "/"MAILDIR_FS_SEP_S"INBOX", NULL);
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

static void maildir_mail_init(struct index_mail *mail)
{
	mail->mail.copy = maildir_storage_copy;
	mail->mail.expunge = maildir_storage_expunge;
}

static struct mailbox *
maildir_open(struct mail_storage *storage, const char *name,
	     enum mailbox_open_flags flags)
{
	struct index_mailbox *ibox;
	struct mail_index *index;
	const char *path, *index_dir, *control_dir;
	struct stat st;

	path = maildir_get_path(storage, name);
	index_dir = maildir_get_index_path(storage, name);
	control_dir = maildir_get_control_path(storage, name);

	index = index_storage_lookup_ref(index_dir, path);
	if (index == NULL) {
		index = maildir_index_alloc(path, index_dir, control_dir);
		index_storage_add(index);
	}

	ibox = index_storage_mailbox_init(storage, &maildir_mailbox,
					  index, name, flags);
	if (ibox != NULL)
		ibox->mail_init = maildir_mail_init;

	/* for shared mailboxes get the create mode from the
	   permissions of dovecot-shared file */
	if (stat(t_strconcat(path, "/dovecot-shared", NULL), &st) < 0)
		index->mail_create_mode = 0600;
	else {
		index->mail_create_mode = st.st_mode & 0666;
		index->private_flags_mask = MAIL_SEEN;
	}

	return (struct mailbox *) ibox;
}

static struct mailbox *
maildir_open_mailbox(struct mail_storage *storage,
		     const char *name, enum mailbox_open_flags flags)
{
	const char *path;
	struct stat st;

	mail_storage_clear_error(storage);

	name = maildir_fix_mailbox_name(storage, name, TRUE);
	if (strcmp(name, "INBOX") == 0) {
		if (!verify_inbox(storage))
			return NULL;
		return maildir_open(storage, "INBOX", flags);
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

		return maildir_open(storage, name, flags);
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
				  const char *name,
				  int directory __attr_unused__)
{
	const char *path;

	mail_storage_clear_error(storage);

	name = maildir_fix_mailbox_name(storage, name, TRUE);
	if (!maildir_is_valid_create_name(name)) {
		mail_storage_set_error(storage, "Invalid mailbox name");
		return FALSE;
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

	name = maildir_fix_mailbox_name(storage, name, TRUE);
	if (strcmp(name, "INBOX") == 0) {
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
		index_dir = t_strconcat(storage->index_dir,
					"/"MAILDIR_FS_SEP_S, name, NULL);
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
	oldpath = t_strconcat(storage->index_dir, "/"MAILDIR_FS_SEP_S,
			      oldname, NULL);
	newpath = t_strconcat(storage->index_dir, "/"MAILDIR_FS_SEP_S,
			      newname, NULL);

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
	const char *oldpath, *newpath, *new_listname, *mask;
	size_t oldnamelen;
	int ret;

	ret = 0;
	oldnamelen = strlen(oldname);

	mask = t_strdup_printf("%s%s%c*", storage->namespace != NULL ?
			       storage->namespace : "", oldname,
			       storage->hierarchy_sep);
	ctx = storage->list_mailbox_init(storage, mask,
					 MAILBOX_LIST_FAST_FLAGS);
	while ((list = maildir_list_mailbox_next(ctx)) != NULL) {
		const char *list_name;

		t_push();

		list_name = maildir_fix_mailbox_name(storage, list->name, TRUE);
		i_assert(oldnamelen <= strlen(list_name));

		new_listname = t_strconcat(newname,
					   list_name + oldnamelen, NULL);
		oldpath = maildir_get_path(storage, list_name);
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

		(void)rename_indexes(storage, list_name, new_listname);
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

	oldname = maildir_fix_mailbox_name(storage, oldname, TRUE);
	newname = maildir_fix_mailbox_name(storage, newname, TRUE);

	if (!maildir_is_valid_existing_name(oldname) ||
	    !maildir_is_valid_create_name(newname)) {
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

static int maildir_set_subscribed(struct mail_storage *storage,
				  const char *name, int set)
{
	name = maildir_fix_mailbox_name(storage, name, FALSE);
	return subsfile_set_subscribed(storage, name, set);
}

static int maildir_get_mailbox_name_status(struct mail_storage *storage,
					   const char *name,
					   enum mailbox_name_status *status)
{
	struct stat st;
	const char *path;

	mail_storage_clear_error(storage);

	name = maildir_fix_mailbox_name(storage, name, TRUE);
	if (!maildir_is_valid_existing_name(name)) {
		*status = MAILBOX_NAME_INVALID;
		return TRUE;
	}

	path = maildir_get_path(storage, name);
	if (stat(path, &st) == 0) {
		*status = MAILBOX_NAME_EXISTS;
		return TRUE;
	}

	if (!maildir_is_valid_create_name(name)) {
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
				      enum mailbox_sync_flags flags,
				      unsigned int min_newmail_notify_interval)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;

	ibox->min_newmail_notify_interval = min_newmail_notify_interval;

	if ((ibox->autosync_flags == 0 && flags == 0) ||
	    (ibox->autosync_flags != 0 && flags != 0)) {
		/* flags or interval just changed. or nothing. */
		ibox->autosync_flags = flags;
	}
	ibox->autosync_flags = flags;

	if (flags == 0) {
		index_mailbox_check_remove_all(ibox);
		return;
	}

	index_mailbox_check_add(ibox,
		t_strconcat(ibox->index->mailbox_path, "/new", NULL), TRUE);
	index_mailbox_check_add(ibox,
		t_strconcat(ibox->index->mailbox_path, "/cur", NULL), TRUE);
}

static int maildir_storage_lock(struct mailbox *box,
				enum mailbox_lock_type lock_type)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;

	if (lock_type == MAIL_LOCK_UNLOCK) {
		ibox->lock_type = MAIL_LOCK_UNLOCK;
		if (!index_storage_lock(ibox, MAIL_LOCK_UNLOCK))
			return FALSE;
		return TRUE;
	}

	i_assert(ibox->lock_type == MAIL_LOCK_UNLOCK);

	if ((lock_type & (MAILBOX_LOCK_EXPUNGE | MAILBOX_LOCK_FLAGS)) != 0) {
		if (!index_storage_lock(ibox, MAIL_LOCK_EXCLUSIVE))
			return FALSE;
	} else if ((lock_type & MAILBOX_LOCK_READ) != 0) {
		if (!index_storage_lock(ibox, MAIL_LOCK_SHARED))
			return FALSE;
	}

	ibox->lock_type = lock_type;
	return TRUE;
}

struct mail_storage maildir_storage = {
	"maildir", /* name */
	NULL, /* namespace */

	'.', /* default hierarchy separator */

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
	maildir_set_subscribed,
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

	index_storage_is_readonly,
        index_storage_allow_new_custom_flags,
	maildir_storage_close,
	maildir_storage_lock,
	index_storage_get_status,
	index_storage_sync,
	maildir_storage_auto_sync,
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
	maildir_storage_copy_init,
	maildir_storage_copy_deinit,
	maildir_storage_expunge_init,
	maildir_storage_expunge_deinit,
	maildir_storage_expunge_fetch_next,
	index_storage_is_inconsistency_error
};
