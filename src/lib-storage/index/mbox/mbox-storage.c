/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "unlink-directory.h"
#include "subscription-file/subscription-file.h"
#include "mbox-index.h"
#include "mbox-storage.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#define CREATE_MODE 0770 /* umask() should limit it more */

extern MailStorage mbox_storage;
static Mailbox mbox_mailbox;

static int mbox_autodetect(const char *data)
{
	const char *path;
	struct stat st;

        path = t_strconcat(data, "/.imap", NULL);
	if (stat(path, &st) == 0 && S_ISDIR(st.st_mode) &&
	    access(path, R_OK|W_OK|X_OK) == 0)
		return TRUE;

	path = t_strconcat(data, "/inbox", NULL);
	if (stat(path, &st) == 0 && !S_ISDIR(st.st_mode) &&
	    access(path, R_OK|W_OK) == 0)
		return TRUE;

	path = t_strconcat(data, "/mbox", NULL);
	if (stat(path, &st) == 0 && !S_ISDIR(st.st_mode) &&
	    access(path, R_OK|W_OK) == 0)
		return TRUE;

	return FALSE;
}

static MailStorage *mbox_create(const char *data)
{
	MailStorage *storage;
	const char *home, *path;

	if (data == NULL || *data == '\0') {
		/* we'll need to figure out the mail location ourself.
		   it's root dir if we've already chroot()ed, otherwise
		   either $HOME/mail or $HOME/Mail */
		if (mbox_autodetect(""))
			data = "/";
		else {
			home = getenv("HOME");
			if (home != NULL) {
				path = t_strconcat(home, "/mail", NULL);
				if (access(path, R_OK|W_OK|X_OK) == 0)
					data = path;
				else {
					path = t_strconcat(home, "/Mail", NULL);
					if (access(path, R_OK|W_OK|X_OK) == 0)
						data = path;
				}
			}
		}
	}

	if (data == NULL)
		return NULL;

	storage = i_new(MailStorage, 1);
	memcpy(storage, &mbox_storage, sizeof(MailStorage));

	storage->dir = i_strdup(data);
	return storage;
}

static void mbox_free(MailStorage *storage)
{
	i_free(storage->dir);
	i_free(storage);
}

static int mbox_is_valid_name(MailStorage *storage, const char *name)
{
	return name[0] != '\0' && name[0] != storage->hierarchy_sep;
}

static const char *mbox_get_index_dir(const char *mbox_path)
{
	const char *p, *rootpath;

	p = strrchr(mbox_path, '/');
	if (p == NULL)
		return t_strconcat(".imap/", mbox_path);
	else {
		rootpath = t_strdup_until(mbox_path, p);
		return t_strconcat(rootpath, "/.imap/", p+1, NULL);
	}
}

static int create_mbox_index_dirs(const char *mbox_path, int verify)
{
	const char *index_dir, *imap_dir;

	index_dir = mbox_get_index_dir(mbox_path);
	imap_dir = t_strdup_until(index_dir, strstr(index_dir, ".imap/") + 5);

	if (mkdir(imap_dir, CREATE_MODE) == -1 && errno != EEXIST)
		return FALSE;
	if (mkdir(index_dir, CREATE_MODE) == -1 && (errno != EEXIST || !verify))
		return FALSE;

	return TRUE;
}

static void verify_inbox(MailStorage *storage)
{
	char path[1024];
	int fd;

	i_snprintf(path, sizeof(path), "%s/inbox", storage->dir);

	/* make sure inbox file itself exists */
	fd = open(path, O_RDWR | O_CREAT | O_EXCL);
	if (fd != -1)
		(void)close(fd);

	/* make sure the index directories exist */
	(void)create_mbox_index_dirs(path, TRUE);
}

static Mailbox *mbox_open(MailStorage *storage, const char *name, int readonly)
{
	IndexMailbox *ibox;
	const char *path, *index_dir;

	/* name = "foo/bar"
	   mbox_path = "/mail/foo/bar"
	   index_dir = "/mail/foo/.imap/bar" */
	path = t_strconcat(storage->dir, "/", name, NULL);
	index_dir = mbox_get_index_dir(path);

	ibox = index_storage_init(storage, &mbox_mailbox,
				  mbox_index_alloc(index_dir, path),
				  name, readonly);
	if (ibox != NULL)
		ibox->expunge_locked = mbox_expunge_locked;
	return (Mailbox *) ibox;
}

static Mailbox *mbox_open_mailbox(MailStorage *storage, const char *name,
				  int readonly)
{
	struct stat st;
	char path[1024];

	mail_storage_clear_error(storage);

	/* INBOX is always case-insensitive */
	if (strcasecmp(name, "INBOX") == 0) {
		/* make sure inbox exists */
		verify_inbox(storage);
		return mbox_open(storage, "inbox", readonly);
	}

	i_snprintf(path, sizeof(path), "%s/%s", storage->dir, name);
	if (stat(path, &st) == 0) {
		/* exists - make sure the required directories are also there */
		(void)create_mbox_index_dirs(path, TRUE);

		return mbox_open(storage, name, readonly);
	} else if (errno == ENOENT) {
		mail_storage_set_error(storage, "Mailbox doesn't exist");
		return NULL;
	} else {
		mail_storage_set_critical(storage, "Can't open mailbox %s: %m",
					  name);
		return NULL;
	}
}

static int mbox_create_mailbox(MailStorage *storage, const char *name)
{
	struct stat st;
	char path[1024];
	int fd;

	mail_storage_clear_error(storage);

	if (strcasecmp(name, "INBOX") == 0)
		name = "inbox";

	if (!mbox_is_valid_name(storage, name)) {
		mail_storage_set_error(storage, "Invalid mailbox name");
		return FALSE;
	}

	/* make sure it doesn't exist already */
	i_snprintf(path, sizeof(path), "%s/%s", storage->dir, name);
	if (stat(path, &st) == 0) {
		mail_storage_set_error(storage, "Mailbox already exists");
		return FALSE;
	}

	if (errno != EEXIST) {
		mail_storage_set_critical(storage, "stat() failed for mbox "
					  "file %s: %m", path);
		return FALSE;
	}

	/* create the mailbox file */
	fd = open(path, O_RDWR | O_CREAT | O_EXCL);
	if (fd != -1) {
		(void)close(fd);
		return TRUE;
	} else if (errno == EEXIST) {
		/* mailbox was just created between stat() and open() call.. */
		mail_storage_set_error(storage, "Mailbox already exists");
		return FALSE;
	} else {
		mail_storage_set_critical(storage, "Can't create mailbox "
					  "%s: %m", name);
		return FALSE;
	}
}

static int mbox_delete_mailbox(MailStorage *storage, const char *name)
{
	const char *index_dir;
	char path[1024];

	mail_storage_clear_error(storage);

	if (strcasecmp(name, "INBOX") == 0) {
		mail_storage_set_error(storage, "INBOX can't be deleted.");
		return FALSE;
	}

	/* first unlink the mbox file */
	i_snprintf(path, sizeof(path), "%s/%s", storage->dir, name);
	if (unlink(path) == -1) {
		if (errno == ENOENT) {
			mail_storage_set_error(storage,
					       "Mailbox doesn't exist.");
		} else {
			mail_storage_set_critical(storage, "Can't delete mbox "
						  "file %s: %m", path);
		}
		return FALSE;
	}

	/* next delete the index directory */
	index_dir = mbox_get_index_dir(path);
	if (!unlink_directory(index_dir)) {
		mail_storage_set_critical(storage, "unlink_directory(%s) "
					  "failed: %m", index_dir);
		return FALSE;
	}
	return TRUE;
}

static int mbox_rename_mailbox(MailStorage *storage, const char *oldname,
			       const char *newname)
{
	const char *old_indexdir, *new_indexdir;
	char oldpath[1024], newpath[1024];

	mail_storage_clear_error(storage);

	if (strcasecmp(oldname, "INBOX") == 0)
		oldname = "inbox";

	/* NOTE: renaming INBOX works just fine with us, it's simply created
	   the next time it's needed. */
	i_snprintf(oldpath, sizeof(oldpath), "%s/%s", storage->dir, oldname);
	i_snprintf(newpath, sizeof(newpath), "%s/%s", storage->dir, newname);
	if (link(oldpath, newpath) == 0) {
		(void)unlink(oldpath);
		/* ... */
	} else if (errno == EEXIST) {
		mail_storage_set_error(storage,
				       "Target mailbox already exists");
		return FALSE;
	} else {
		mail_storage_set_critical(storage, "link(%s, %s) failed: %m",
					  oldpath, newpath);
		return FALSE;
	}

	/* we need to rename the index directory as well */
	old_indexdir = mbox_get_index_dir(oldpath);
	new_indexdir = mbox_get_index_dir(newpath);
	(void)rename(old_indexdir, new_indexdir);

	return TRUE;
}

static int mbox_get_mailbox_name_status(MailStorage *storage, const char *name,
					MailboxNameStatus *status)
{
	struct stat st;
	char path[1024];

	mail_storage_clear_error(storage);

	if (strcasecmp(name, "INBOX") == 0)
		name = "inbox";

	if (!mbox_is_valid_name(storage, name)) {
		*status = MAILBOX_NAME_INVALID;
		return TRUE;
	}

	i_snprintf(path, sizeof(path), "%s/%s", storage->dir, name);
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

MailStorage mbox_storage = {
	"mbox", /* name */

	'/', /* hierarchy_sep - can't be changed */

	mbox_create,
	mbox_free,
	mbox_autodetect,
	mbox_open_mailbox,
	mbox_create_mailbox,
	mbox_delete_mailbox,
	mbox_rename_mailbox,
	mbox_find_mailboxes,
	subsfile_set_subscribed,
	mbox_find_subscribed,
	mbox_get_mailbox_name_status,
	mail_storage_get_last_error,

	NULL,
	NULL
};

static Mailbox mbox_mailbox = {
	NULL, /* name */
	NULL, /* storage */

	index_storage_close,
	index_storage_get_status,
	index_storage_sync,
	index_storage_expunge,
	index_storage_update_flags,
	index_storage_copy,
	index_storage_fetch,
	index_storage_search,
	mbox_storage_save,
	mail_storage_is_inconsistency_error,

	FALSE,
	FALSE
};
