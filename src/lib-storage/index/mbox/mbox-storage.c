/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "unlink-directory.h"
#include "subscription-file/subscription-file.h"
#include "mail-custom-flags.h"
#include "mbox-index.h"
#include "mbox-lock.h"
#include "mbox-storage.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#define CREATE_MODE 0770 /* umask() should limit it more */

extern MailStorage mbox_storage;
extern Mailbox mbox_mailbox;

static int mbox_autodetect(const char *data)
{
	const char *path;
	struct stat st;

	/* Is it INBOX file? */
	if (*data != '\0' && stat(data, &st) == 0 && !S_ISDIR(st.st_mode) &&
	    access(data, R_OK|W_OK) == 0)
		return TRUE;

	/* or directory for IMAP folders? */
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

static const char *get_root_dir(void)
{
	const char *home, *path;

	if (mbox_autodetect(""))
		return "/";

	home = getenv("HOME");
	if (home != NULL) {
		path = t_strconcat(home, "/mail", NULL);
		if (access(path, R_OK|W_OK|X_OK) == 0)
			return path;

		path = t_strconcat(home, "/Mail", NULL);
		if (access(path, R_OK|W_OK|X_OK) == 0)
			return path;
	}

	return NULL;
}

static MailStorage *mbox_create(const char *data, const char *user)
{
	MailStorage *storage;
	const char *root_dir, *inbox_file, *index_dir, *p;
	struct stat st;

	root_dir = inbox_file = index_dir = NULL;

	if (data == NULL || *data == '\0') {
		/* we'll need to figure out the mail location ourself.
		   it's root dir if we've already chroot()ed, otherwise
		   either $HOME/mail or $HOME/Mail */
		root_dir = get_root_dir();
	} else {
		/* <root folder> | <INBOX path>
		   [:INBOX=<path>] [:INDEX=<dir>] */
		p = strchr(data, ':');
		if (p == NULL) {
			if (stat(data, &st) == 0 && S_ISDIR(st.st_mode))
				root_dir = data;
			else {
				root_dir = get_root_dir();
				inbox_file = data;
			}
		} else {
			root_dir = t_strdup_until(data, p);
			do {
				p++;
				if (strncmp(p, "INBOX=", 6) == 0)
					inbox_file = t_strcut(p+6, ':');
				else if (strncmp(p, "INDEX=", 6) == 0)
					index_dir = t_strcut(p+6, ':');
				p = strchr(p, ':');
			} while (p != NULL);
		}
	}

	if (root_dir == NULL)
		return NULL;

	if (inbox_file == NULL)
		inbox_file = t_strconcat(root_dir, "/inbox", NULL);
	if (index_dir == NULL)
		index_dir = root_dir;

	storage = i_new(MailStorage, 1);
	memcpy(storage, &mbox_storage, sizeof(MailStorage));

	storage->dir = i_strdup(root_dir);
	storage->inbox_file = i_strdup(inbox_file);
	storage->index_dir = i_strdup(index_dir);
	storage->user = i_strdup(user);
	storage->callbacks = i_new(MailStorageCallbacks, 1);
	return storage;
}

static void mbox_free(MailStorage *storage)
{
	i_free(storage->dir);
	i_free(storage->inbox_file);
	i_free(storage->index_dir);
	i_free(storage->user);
	i_free(storage->error);
	i_free(storage->callbacks);
	i_free(storage);
}

int mbox_is_valid_mask(const char *mask)
{
	const char *p;
	int newdir;

	/* make sure there's no "../" or "..\" stuff */
	newdir = TRUE;
	for (p = mask; *p != '\0'; p++) {
		if (newdir && p[0] == '.' && p[1] == '.' &&
		    (p[2] == '/' || p[2] == '\\'))
			return FALSE;
		newdir = p[0] == '/' || p[0] == '\\';
	}

	return TRUE;
}

static int mbox_is_valid_name(MailStorage *storage, const char *name)
{
	return name[0] != '\0' && name[0] != storage->hierarchy_sep &&
		name[strlen(name)-1] != storage->hierarchy_sep &&
		strchr(name, '*') == NULL && strchr(name, '%') == NULL &&
		mbox_is_valid_mask(name);
}

static const char *mbox_get_index_dir(MailStorage *storage, const char *name)
{
	const char *p;

	p = strrchr(name, '/');
	if (p == NULL)
		return t_strconcat(storage->index_dir, "/.imap/", name, NULL);
	else {
		return t_strconcat(storage->index_dir, t_strdup_until(name, p),
				   "/.imap/", p+1, NULL);
	}
}

static int create_mbox_index_dirs(MailStorage *storage, const char *name,
				  int verify)
{
	const char *index_dir, *imap_dir;

	index_dir = mbox_get_index_dir(storage, name);
	imap_dir = t_strdup_until(index_dir, strstr(index_dir, ".imap/") + 5);

	if (mkdir(imap_dir, CREATE_MODE) == -1 && errno != EEXIST)
		return FALSE;
	if (mkdir(index_dir, CREATE_MODE) == -1 && (errno != EEXIST || !verify))
		return FALSE;

	return TRUE;
}

static void verify_inbox(MailStorage *storage)
{
	int fd;

	/* make sure inbox file itself exists */
	fd = open(storage->inbox_file, O_RDWR | O_CREAT | O_EXCL, 0660);
	if (fd != -1)
		(void)close(fd);

	/* make sure the index directories exist */
	(void)create_mbox_index_dirs(storage, "INBOX", TRUE);
}

static const char *mbox_get_path(MailStorage *storage, const char *name)
{
	if (strcasecmp(name, "INBOX") == 0)
		return storage->inbox_file;
	else
		return t_strconcat(storage->dir, "/", name, NULL);
}

static Mailbox *mbox_open(MailStorage *storage, const char *name,
			  int readonly, int fast)
{
	IndexMailbox *ibox;
	MailIndex *index;
	const char *path, *index_dir;

	if (strcasecmp(name, "INBOX") == 0) {
		/* name = "INBOX"
		   path = "<inbox_file>/INBOX"
		   index_dir = "/mail/.imap/INBOX" */
		path = storage->inbox_file;
		index_dir = mbox_get_index_dir(storage, "/INBOX");
	} else {
		/* name = "foo/bar"
		   path = "/mail/foo/bar"
		   index_dir = "/mail/foo/.imap/bar" */
		path = mbox_get_path(storage, name);
		index_dir = mbox_get_index_dir(storage, name);
	}

	index = index_storage_lookup_ref(index_dir);
	if (index == NULL) {
		index = mbox_index_alloc(index_dir, path);
		index_storage_add(index);
	}

	ibox = index_storage_init(storage, &mbox_mailbox, index,
				  name, readonly, fast);
	if (ibox != NULL) {
		ibox->expunge_locked = mbox_expunge_locked;
		index_mailbox_check_add(ibox, index->mailbox_path);
	}
	return (Mailbox *) ibox;
}

static Mailbox *mbox_open_mailbox(MailStorage *storage, const char *name,
				  int readonly, int fast)
{
	const char *path;
	struct stat st;

	mail_storage_clear_error(storage);

	/* INBOX is always case-insensitive */
	if (strcasecmp(name, "INBOX") == 0) {
		/* make sure inbox exists */
		verify_inbox(storage);
		return mbox_open(storage, "INBOX", readonly, fast);
	}

	if (!mbox_is_valid_name(storage, name)) {
		mail_storage_set_error(storage, "Invalid mailbox name");
		return FALSE;
	}

	path = mbox_get_path(storage, name);
	if (stat(path, &st) == 0) {
		/* exists - make sure the required directories are also there */
		(void)create_mbox_index_dirs(storage, name, TRUE);

		return mbox_open(storage, name, readonly, fast);
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

static int mbox_create_mailbox(MailStorage *storage, const char *name)
{
	const char *path;
	struct stat st;
	int fd;

	mail_storage_clear_error(storage);

	if (strcasecmp(name, "INBOX") == 0)
		name = "INBOX";

	if (!mbox_is_valid_name(storage, name)) {
		mail_storage_set_error(storage, "Invalid mailbox name");
		return FALSE;
	}

	/* make sure it doesn't exist already */
	path = mbox_get_path(storage, name);
	if (stat(path, &st) == 0) {
		mail_storage_set_error(storage, "Mailbox already exists");
		return FALSE;
	}

	if (errno != ENOENT) {
		mail_storage_set_critical(storage, "stat() failed for mbox "
					  "file %s: %m", path);
		return FALSE;
	}

	/* create the mailbox file */
	fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0660);
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
	const char *index_dir, *path;

	mail_storage_clear_error(storage);

	if (strcasecmp(name, "INBOX") == 0) {
		mail_storage_set_error(storage, "INBOX can't be deleted.");
		return FALSE;
	}

	if (!mbox_is_valid_name(storage, name)) {
		mail_storage_set_error(storage, "Invalid mailbox name");
		return FALSE;
	}

	/* first unlink the mbox file */
	path = mbox_get_path(storage, name);
	if (unlink(path) == -1) {
		if (errno == ENOENT) {
			mail_storage_set_error(storage,
					       "Mailbox doesn't exist: %s",
					       name);
		} else {
			mail_storage_set_critical(storage,
						  "Can't delete mbox file "
						  "%s: %m", path);
		}
		return FALSE;
	}

	/* next delete the index directory */
	index_dir = mbox_get_index_dir(storage, name);
	if (!unlink_directory(index_dir) && errno != ENOENT) {
		mail_storage_set_critical(storage, "unlink_directory(%s) "
					  "failed: %m", index_dir);
		return FALSE;
	}
	return TRUE;
}

static int mbox_rename_mailbox(MailStorage *storage, const char *oldname,
			       const char *newname)
{
	const char *oldpath, *newpath, *old_indexdir, *new_indexdir;

	mail_storage_clear_error(storage);

	if (!mbox_is_valid_name(storage, oldname) ||
	    !mbox_is_valid_name(storage, newname)) {
		mail_storage_set_error(storage, "Invalid mailbox name");
		return FALSE;
	}

	if (strcasecmp(oldname, "INBOX") == 0)
		oldname = "INBOX";

	oldpath = mbox_get_path(storage, oldname);
	newpath = mbox_get_path(storage, newname);

	/* NOTE: renaming INBOX works just fine with us, it's simply created
	   the next time it's needed. */
	if (link(oldpath, newpath) == 0)
		(void)unlink(oldpath);
	else if (errno == EEXIST) {
		mail_storage_set_error(storage,
				       "Target mailbox already exists");
		return FALSE;
	} else {
		mail_storage_set_critical(storage, "link(%s, %s) failed: %m",
					  oldpath, newpath);
		return FALSE;
	}

	/* we need to rename the index directory as well */
	old_indexdir = mbox_get_index_dir(storage, oldname);
	new_indexdir = mbox_get_index_dir(storage, newname);
	(void)rename(old_indexdir, new_indexdir);

	return TRUE;
}

static int mbox_get_mailbox_name_status(MailStorage *storage, const char *name,
					MailboxNameStatus *status)
{
	struct stat st;
	const char *path;

	mail_storage_clear_error(storage);

	if (strcasecmp(name, "INBOX") == 0)
		name = "INBOX";

	if (!mbox_is_valid_name(storage, name)) {
		*status = MAILBOX_NAME_INVALID;
		return TRUE;
	}

	path = mbox_get_path(storage, name);
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

static int mbox_storage_close(Mailbox *box)
{
	IndexMailbox *ibox = (IndexMailbox *) box;
	int failed = FALSE;

	/* update flags by rewrite mbox file */
	if (!mbox_index_rewrite(ibox->index)) {
		mail_storage_set_index_error(ibox);
		failed = TRUE;
	}

	return index_storage_close(box) && !failed;
}

MailStorage mbox_storage = {
	"mbox", /* name */

	'/', /* hierarchy_sep - can't be changed */

	mbox_create,
	mbox_free,
	mbox_autodetect,
	index_storage_set_callbacks,
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
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, NULL
};

Mailbox mbox_mailbox = {
	NULL, /* name */
	NULL, /* storage */

	mbox_storage_close,
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
	FALSE,
	FALSE
};
