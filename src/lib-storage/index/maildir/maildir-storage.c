/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "unlink-directory.h"
#include "subscription-file/subscription-file.h"
#include "maildir-index.h"
#include "maildir-storage.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#define CREATE_MODE 0770 /* umask() should limit it more */

extern MailStorage maildir_storage;
static Mailbox maildir_mailbox;

static const char *maildirs[] = { "cur", "new", "tmp", NULL  };

static MailStorage *maildir_create(const char *data, const char *user)
{
	MailStorage *storage;
	const char *home, *path;

	if (data == NULL || *data == '\0') {
		/* we'll need to figure out the maildir location ourself.
		   it's either root dir if we've already chroot()ed, or
		   $HOME/Maildir otherwise */
		if (access("/cur", R_OK|W_OK|X_OK) == 0)
			data = "/";
		else {
			home = getenv("HOME");
			if (home != NULL) {
				path = t_strconcat(home, "/Maildir", NULL);
				if (access(path, R_OK|W_OK|X_OK) == 0)
					data = path;
			}
		}
	}

	if (data == NULL)
		return NULL;

	storage = i_new(MailStorage, 1);
	memcpy(storage, &maildir_storage, sizeof(MailStorage));

	storage->dir = i_strdup(data);
	storage->user = i_strdup(user);
	return storage;
}

static void maildir_free(MailStorage *storage)
{
	i_free(storage->dir);
	i_free(storage->user);
	i_free(storage);
}

static int maildir_autodetect(const char *data)
{
	struct stat st;

	return stat(t_strconcat(data, "/cur", NULL), &st) == 0 &&
		S_ISDIR(st.st_mode);
}

static int maildir_is_valid_name(MailStorage *storage, const char *name)
{
	return name[0] != '\0' && name[0] != storage->hierarchy_sep &&
		strchr(name, '/') == NULL && strchr(name, '\\') == NULL;
}

/* create or fix maildir, ignore if it already exists */
static int create_maildir(const char *dir, int verify)
{
	const char **tmp;
	char path[1024];

	if (mkdir(dir, CREATE_MODE) == -1 && (errno != EEXIST || !verify))
		return FALSE;

	for (tmp = maildirs; *tmp != NULL; tmp++) {
		i_snprintf(path, sizeof(path), "%s/%s", dir, *tmp);

		if (mkdir(path, CREATE_MODE) == -1 &&
		    (errno != EEXIST || !verify))
			return FALSE;
	}

	return TRUE;
}

static int verify_inbox(MailStorage *storage, const char *dir)
{
	const char **tmp;
	char src[1024], dest[1024];

	/* first make sure the cur/ new/ and tmp/ dirs exist in root dir */
	(void)create_maildir(dir, TRUE);

	/* create the .INBOX directory */
	i_snprintf(dest, sizeof(dest), "%s/.INBOX", dir);
	if (mkdir(dest, CREATE_MODE) == -1 && errno != EEXIST) {
		mail_storage_set_critical(storage, "Can't create directory "
					  "%s: %m", dest);
		return FALSE;
	}

	/* then symlink the cur/ new/ and tmp/ into the .INBOX/ directory */
	for (tmp = maildirs; *tmp != NULL; tmp++) {
		i_snprintf(src, sizeof(src), "../%s", *tmp);
		i_snprintf(dest, sizeof(dest), "%s/.INBOX/%s", dir, *tmp);

		if (symlink(src, dest) == -1 && errno != EEXIST) {
			mail_storage_set_critical(storage, "symlink(%s, %s) "
						  "failed: %m", src, dest);
			return FALSE;
		}
	}

	return TRUE;
}

static Mailbox *maildir_open(MailStorage *storage, const char *name,
			     int readonly)
{
	IndexMailbox *ibox;
	const char *path;

	path = t_strconcat(storage->dir, "/.", name, NULL);

	ibox = index_storage_init(storage, &maildir_mailbox,
				  maildir_index_alloc(path), name, readonly);
	if (ibox != NULL)
		ibox->expunge_locked = maildir_expunge_locked;
	return (Mailbox *) ibox;
}

static Mailbox *maildir_open_mailbox(MailStorage *storage, const char *name,
				     int readonly)
{
	struct stat st;
	char path[1024];

	mail_storage_clear_error(storage);

	/* INBOX is always case-insensitive */
	if (strcasecmp(name, "INBOX") == 0) {
		if (!verify_inbox(storage, storage->dir))
			return NULL;
		return maildir_open(storage, "INBOX", readonly);
	}

	if (!maildir_is_valid_name(storage, name)) {
		mail_storage_set_error(storage, "Invalid mailbox name");
		return FALSE;
	}

	i_snprintf(path, sizeof(path), "%s/.%s", storage->dir, name);
	if (stat(path, &st) == 0) {
		/* exists - make sure the required directories are also there */
		(void)create_maildir(path, TRUE);

		return maildir_open(storage, name, readonly);
	} else if (errno == ENOENT) {
		mail_storage_set_error(storage, "Mailbox doesn't exist: %s",
				       name);
		return NULL;
	} else {
		mail_storage_set_critical(storage, "Can't open mailbox %s: %m",
					  name);
		return NULL;
	}
}

static int maildir_create_mailbox(MailStorage *storage, const char *name)
{
	char path[1024];

	mail_storage_clear_error(storage);

	if (strcasecmp(name, "INBOX") == 0)
		name = "INBOX";

	if (!maildir_is_valid_name(storage, name)) {
		mail_storage_set_error(storage, "Invalid mailbox name");
		return FALSE;
	}

	i_snprintf(path, sizeof(path), "%s/.%s", storage->dir, name);
	if (create_maildir(path, FALSE))
		return TRUE;
	else if (errno == EEXIST) {
		mail_storage_set_error(storage, "Mailbox already exists");
		return FALSE;
	} else {
		mail_storage_set_critical(storage, "Can't create mailbox "
					  "%s: %m", name);
		return FALSE;
	}
}

static int maildir_delete_mailbox(MailStorage *storage, const char *name)
{
	struct stat st;
	char src[1024], dest[1024];
	int count;

	mail_storage_clear_error(storage);

	if (strcasecmp(name, "INBOX") == 0) {
		mail_storage_set_error(storage, "INBOX can't be deleted.");
		return FALSE;
	}

	if (!maildir_is_valid_name(storage, name)) {
		mail_storage_set_error(storage, "Invalid mailbox name");
		return FALSE;
	}

	/* rename the .maildir into ..maildir which marks it as being
	   deleted. this way we never see partially deleted maildirs. */
	i_snprintf(src, sizeof(src), "%s/.%s", storage->dir, name);
	i_snprintf(dest, sizeof(dest), "%s/..%s", storage->dir, name);

	if (stat(src, &st) != 0 && errno == ENOENT) {
		mail_storage_set_error(storage, "Mailbox doesn't exist: %s",
				       name);
		return FALSE;
	}

	count = 0;
	while (rename(src, dest) == -1 && count < 2) {
		if (errno != EEXIST) {
			mail_storage_set_critical(storage,
						  "rename(%s, %s) failed: %m",
						  src, dest);
			return FALSE;
		}

		/* ..dir already existed? delete it and try again */
		if (!unlink_directory(dest)) {
			mail_storage_set_critical(storage,
						  "unlink_directory(%s) "
						  "failed: %m", dest);
			return FALSE;
		}
		count++;
	}

	if (!unlink_directory(dest)) {
		mail_storage_set_critical(storage, "unlink_directory(%s) "
					  "failed: %m", dest);
		return FALSE;
	}
	return TRUE;
}

static int move_inbox_data(MailStorage *storage, const char *newdir)
{
	const char **tmp;
	char oldpath[1024], newpath[1024];

	/* newpath points to the destination folder directory, which contains
	   symlinks to real INBOX directories. unlink() the symlinks and
	   move the real cur/ directory here. */
	for (tmp = maildirs; *tmp != NULL; tmp++) {
		i_snprintf(newpath, sizeof(newpath), "%s/%s", newdir, *tmp);

		if (unlink(newpath) == -1 && errno != EEXIST) {
			mail_storage_set_critical(storage,
						  "unlink(%s) failed: %m",
						  newpath);
			return FALSE;
		}
	}

	i_snprintf(oldpath, sizeof(oldpath), "%s/cur", storage->dir);
	i_snprintf(newpath, sizeof(newpath), "%s/cur", newdir);
	if (rename(oldpath, newpath) != 0) {
		mail_storage_set_critical(storage, "rename(%s, %s) failed: %m",
					  oldpath, newpath);
		return FALSE;
	}

	/* create back the cur/ directory for INBOX */
	(void)mkdir(oldpath, CREATE_MODE);
	return TRUE;
}

static int maildir_rename_mailbox(MailStorage *storage, const char *oldname,
				  const char *newname)
{
	char oldpath[1024], newpath[1024];

	mail_storage_clear_error(storage);

	if (strcasecmp(oldname, "INBOX") == 0)
		oldname = "INBOX";

	if (!maildir_is_valid_name(storage, oldname) ||
	    !maildir_is_valid_name(storage, newname)) {
		mail_storage_set_error(storage, "Invalid mailbox name");
		return FALSE;
	}

	/* NOTE: renaming INBOX works just fine with us, it's simply created
	   the next time it's needed. Only problem with it is that it's not
	   atomic operation but that can't be really helped. */
	i_snprintf(oldpath, sizeof(oldpath), "%s/.%s", storage->dir, oldname);
	i_snprintf(newpath, sizeof(newpath), "%s/.%s", storage->dir, newname);
	if (rename(oldpath, newpath) == 0) {
		if (strcmp(oldname, "INBOX") == 0)
			return move_inbox_data(storage, newpath);
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

static int maildir_get_mailbox_name_status(MailStorage *storage,
					   const char *name,
					   MailboxNameStatus *status)
{
	struct stat st;
	char path[1024];

	mail_storage_clear_error(storage);

	if (strcasecmp(name, "INBOX") == 0)
		name = "INBOX";

	if (!maildir_is_valid_name(storage, name)) {
		*status = MAILBOX_NAME_INVALID;
		return TRUE;
	}

	i_snprintf(path, sizeof(path), "%s/.%s", storage->dir, name);
	if (stat(path, &st) == 0) {
		*status = MAILBOX_NAME_EXISTS;
		return TRUE;
	} else if (errno == ENOENT) {
		*status = MAILBOX_NAME_VALID;
		return TRUE;
	} else {
		mail_storage_set_critical(storage, "mailbox name status: "
					  "stat(%s) failed: %m", path);
		return FALSE;
	}
}

MailStorage maildir_storage = {
	"maildir", /* name */

	'.', /* hierarchy_sep - can't be changed */

	maildir_create,
	maildir_free,
	maildir_autodetect,
	maildir_open_mailbox,
	maildir_create_mailbox,
	maildir_delete_mailbox,
	maildir_rename_mailbox,
	maildir_find_mailboxes,
	subsfile_set_subscribed,
	maildir_find_subscribed,
	maildir_get_mailbox_name_status,
	mail_storage_get_last_error,

	NULL,
	NULL,
	NULL
};

static Mailbox maildir_mailbox = {
	NULL, /* name */
	NULL, /* storage */

	index_storage_close,
	index_storage_get_status,
	index_storage_sync,
	index_storage_expunge,
	index_storage_update_flags,
	maildir_storage_copy,
	index_storage_fetch,
	index_storage_search,
	maildir_storage_save,
	mail_storage_is_inconsistency_error,

	FALSE,
	FALSE
};
