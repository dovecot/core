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

typedef struct {
	int found;
	size_t oldnamelen;
	const char *newname;
} RenameContext;

extern MailStorage maildir_storage;
extern Mailbox maildir_mailbox;

static const char *maildirs[] = { "cur", "new", "tmp", NULL  };

static MailStorage *maildir_create(const char *data, const char *user)
{
	MailStorage *storage;
	const char *home, *path, *root_dir, *index_dir, *p;

	root_dir = index_dir = NULL;

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
		/* <Maildir> [:INDEX=<dir>] */
		p = strchr(data, ':');
		if (p == NULL)
			root_dir = data;
		else {
			root_dir = t_strdup_until(data, p);

			p++;
			if (strncmp(p, "INDEX=", 6) == 0)
				index_dir = t_strcut(p+6, ':');
		}
	}

	if (root_dir == NULL)
		return NULL;

	if (index_dir == NULL)
		index_dir = root_dir;

	storage = i_new(MailStorage, 1);
	memcpy(storage, &maildir_storage, sizeof(MailStorage));

	storage->dir = i_strdup(root_dir);
	storage->index_dir = i_strdup(index_dir);
	storage->user = i_strdup(user);
	storage->callbacks = i_new(MailStorageCallbacks, 1);
	return storage;
}

static void maildir_free(MailStorage *storage)
{
	i_free(storage->dir);
	i_free(storage->index_dir);
	i_free(storage->user);
	i_free(storage->error);
	i_free(storage->callbacks);
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
		name[strlen(name)-1] != storage->hierarchy_sep &&
		strchr(name, '/') == NULL && strchr(name, '\\') == NULL &&
		strchr(name, '*') == NULL && strchr(name, '%') == NULL;
}

static const char *maildir_get_path(MailStorage *storage, const char *name)
{
	return t_strconcat(storage->dir, "/.", name, NULL);
}

/* create or fix maildir, ignore if it already exists */
static int create_maildir(const char *dir, int verify)
{
	const char **tmp, *path;

	if (mkdir(dir, CREATE_MODE) == -1 && (errno != EEXIST || !verify))
		return FALSE;

	for (tmp = maildirs; *tmp != NULL; tmp++) {
		path = t_strconcat(dir, "/", *tmp, NULL);

		if (mkdir(path, CREATE_MODE) == -1 &&
		    (errno != EEXIST || !verify))
			return FALSE;
	}

	return TRUE;
}

static int create_index_dir(MailStorage *storage, const char *name)
{
	const char *dir;

	if (strcmp(storage->index_dir, storage->dir) == 0)
		return TRUE;

	dir = t_strconcat(storage->index_dir, "/.", name, NULL);
	if (mkdir(dir, CREATE_MODE) == -1 && errno != EEXIST) {
		mail_storage_set_critical(storage,
					  "Can't create directory %s: %m", dir);
		return FALSE;
	}

	return TRUE;
}

static int verify_inbox(MailStorage *storage)
{
	const char **tmp, *src, *dest, *inbox;

	/* first make sure the cur/ new/ and tmp/ dirs exist in root dir */
	(void)create_maildir(storage->dir, TRUE);

	/* create the .INBOX directory */
	inbox = maildir_get_path(storage, "INBOX");
	if (mkdir(inbox, CREATE_MODE) == -1 && errno != EEXIST) {
		mail_storage_set_critical(storage, "Can't create directory "
					  "%s: %m", inbox);
		return FALSE;
	}

	/* then symlink the cur/ new/ and tmp/ into the .INBOX/ directory */
	for (tmp = maildirs; *tmp != NULL; tmp++) {
		src = t_strconcat("../", *tmp, NULL);
		dest = t_strconcat(inbox, "/", *tmp, NULL);

		if (symlink(src, dest) == -1 && errno != EEXIST) {
			mail_storage_set_critical(storage, "symlink(%s, %s) "
						  "failed: %m", src, dest);
			return FALSE;
		}
	}

	/* make sure the index directories exist */
	return create_index_dir(storage, "INBOX");
}

static Mailbox *maildir_open(MailStorage *storage, const char *name,
			     int readonly, int fast)
{
	IndexMailbox *ibox;
	MailIndex *index;
	const char *path, *index_dir;

	path = t_strconcat(storage->dir, "/.", name, NULL);
	index_dir = t_strconcat(storage->index_dir, "/.", name, NULL);

	index = index_storage_lookup_ref(index_dir);
	if (index == NULL) {
		index = maildir_index_alloc(index_dir, path);
		index_storage_add(index);
	}

	ibox = index_storage_init(storage, &maildir_mailbox, index, name,
				  readonly, fast);
	if (ibox != NULL) {
		ibox->expunge_locked = maildir_expunge_locked;
		index_mailbox_check_add(ibox, t_strconcat(path, "/new", NULL));
	}
	return (Mailbox *) ibox;
}

static const char *inbox_fix_case(MailStorage *storage, const char *name)
{
        if (strncasecmp(name, "INBOX", 5) == 0 &&
	    (name[5] == '\0' || name[5] == storage->hierarchy_sep)) {
		/* use same case with all INBOX folders or we'll get
		   into trouble */
		name = t_strconcat("INBOX", name+5, NULL);
	}

	return name;
}

static Mailbox *maildir_open_mailbox(MailStorage *storage, const char *name,
				     int readonly, int fast)
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

	if (!maildir_is_valid_name(storage, name)) {
		mail_storage_set_error(storage, "Invalid mailbox name");
		return FALSE;
	}

	path = maildir_get_path(storage, name);
	if (stat(path, &st) == 0) {
		/* exists - make sure the required directories are also there */
		(void)create_maildir(path, TRUE);

		/* make sure the index directories exist */
		(void)create_index_dir(storage, name);

		return maildir_open(storage, name, readonly, fast);
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
	const char *path;

	mail_storage_clear_error(storage);

	name = inbox_fix_case(storage, name);
	if (!maildir_is_valid_name(storage, name)) {
		mail_storage_set_error(storage, "Invalid mailbox name");
		return FALSE;
	}

	path = maildir_get_path(storage, name);
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
	const char *src, *dest, *index_dir;
	int count;

	mail_storage_clear_error(storage);

	name = inbox_fix_case(storage, name);
	if (strcasecmp(name, "INBOX") == 0) {
		mail_storage_set_error(storage, "INBOX can't be deleted.");
		return FALSE;
	}

	if (!maildir_is_valid_name(storage, name)) {
		mail_storage_set_error(storage, "Invalid mailbox name");
		return FALSE;
	}

	/* rename the .maildir into ..maildir which marks it as being
	   deleted. delete indexes before the actual maildir. this way we
	   never see partially deleted mailboxes. */
	src = maildir_get_path(storage, name);
	dest = t_strconcat(storage->dir, "/..", name, NULL);
	if (stat(src, &st) != 0 && errno == ENOENT) {
		mail_storage_set_error(storage, "Mailbox doesn't exist: %s",
				       name);
		return FALSE;
	}

	if (strcmp(storage->index_dir, storage->dir) != 0) {
		index_dir = t_strconcat(storage->index_dir, "/.", name, NULL);
		if (unlink_directory(index_dir, TRUE) < 0) {
			mail_storage_set_critical(storage,
						  "unlink_directory(%s) "
						  "failed: %m", index_dir);
			return FALSE;
		}
	}

	count = 0;
	while (rename(src, dest) < 0 && count < 2) {
		if (errno != EEXIST) {
			mail_storage_set_critical(storage,
						  "rename(%s, %s) failed: %m",
						  src, dest);
			return FALSE;
		}

		/* ..dir already existed? delete it and try again */
		if (unlink_directory(dest, TRUE) < 0) {
			mail_storage_set_critical(storage,
						  "unlink_directory(%s) "
						  "failed: %m", dest);
			return FALSE;
		}
		count++;
	}

	if (unlink_directory(dest, TRUE) < 0) {
		mail_storage_set_critical(storage, "unlink_directory(%s) "
					  "failed: %m", dest);
		return FALSE;
	}

	return TRUE;
}

static int move_inbox_data(MailStorage *storage, const char *newdir)
{
	const char **tmp, *oldpath, *newpath;

	/* newpath points to the destination folder directory, which contains
	   symlinks to real INBOX directories. unlink() the symlinks and
	   move the real cur/ directory here. */
	for (tmp = maildirs; *tmp != NULL; tmp++) {
		newpath = t_strconcat(newdir, "/", *tmp, NULL);
		if (unlink(newpath) == -1 && errno != EEXIST) {
			mail_storage_set_critical(storage,
						  "unlink(%s) failed: %m",
						  newpath);
			return FALSE;
		}
	}

	oldpath = t_strconcat(storage->dir, "/cur", NULL);
	newpath = t_strconcat(newdir, "/cur", NULL);

	if (rename(oldpath, newpath) != 0) {
		mail_storage_set_critical(storage, "rename(%s, %s) failed: %m",
					  oldpath, newpath);
		return FALSE;
	}

	/* create back the cur/ directory for INBOX */
	(void)mkdir(oldpath, CREATE_MODE);
	return TRUE;
}

static int rename_indexes(MailStorage *storage,
			  const char *oldname, const char *newname)
{
	const char *oldpath, *newpath;

	if (strcmp(storage->index_dir, storage->dir) == 0)
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

static void rename_subfolder(MailStorage *storage, const char *name,
			     MailboxFlags flags __attr_unused__, void *context)
{
	RenameContext *ctx = context;
	const char *newname, *oldpath, *newpath;

	i_assert(ctx->oldnamelen <= strlen(name));

	newname = t_strconcat(ctx->newname, ".", name + ctx->oldnamelen, NULL);

	oldpath = maildir_get_path(storage, name);
	newpath = maildir_get_path(storage, newname);

	/* FIXME: it's possible to merge two folders if either one of them
	   doesn't have existing root folder. We could check this but I'm not
	   sure if it's worth it. It could be even considered as a feature.

	   Anyway, the bug with merging is that if both folders have
	   identically named subfolder they conflict. Just ignore those and
	   leave them under the old folder. */
	if (rename(oldpath, newpath) == 0 || errno == EEXIST)
		ctx->found = TRUE;
	else {
		mail_storage_set_critical(storage, "rename(%s, %s) failed: %m",
					  oldpath, newpath);
	}

	(void)rename_indexes(storage, name, newname);
}

static int maildir_rename_mailbox(MailStorage *storage, const char *oldname,
				  const char *newname)
{
	RenameContext ctx;
	const char *oldpath, *newpath;
	int ret;

	mail_storage_clear_error(storage);

	oldname = inbox_fix_case(storage, oldname);
	if (!maildir_is_valid_name(storage, oldname) ||
	    !maildir_is_valid_name(storage, newname)) {
		mail_storage_set_error(storage, "Invalid mailbox name");
		return FALSE;
	}

	/* NOTE: renaming INBOX works just fine with us, it's simply created
	   the next time it's needed. Only problem with it is that it's not
	   atomic operation but that can't be really helped.

	   NOTE: it's possible to rename a nonexisting folder which has
	   subfolders. In that case we should ignore the rename() error. */
	oldpath = maildir_get_path(storage, oldname);
	newpath = maildir_get_path(storage, newname);

	ret = rename(oldpath, newpath);
	if (ret == 0 || (errno == ENOENT && strcmp(oldname, "INBOX") != 0)) {
		if (strcmp(oldname, "INBOX") == 0)
			return move_inbox_data(storage, newpath);

		if (!rename_indexes(storage, oldname, newname))
			return FALSE;

		ctx.found = ret == 0;
		ctx.oldnamelen = strlen(oldname)+1;
		ctx.newname = newname;
		if (!maildir_find_mailboxes(storage,
					    t_strconcat(oldname, ".*", NULL),
					    rename_subfolder, &ctx))
			return FALSE;

		if (!ctx.found) {
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

static int maildir_get_mailbox_name_status(MailStorage *storage,
					   const char *name,
					   MailboxNameStatus *status)
{
	struct stat st;
	const char *path;

	mail_storage_clear_error(storage);

	name = inbox_fix_case(storage, name);
	if (!maildir_is_valid_name(storage, name)) {
		*status = MAILBOX_NAME_INVALID;
		return TRUE;
	}

	path = maildir_get_path(storage, name);
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
	index_storage_set_callbacks,
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
	NULL,
	NULL,
	NULL,
	NULL, NULL,

	0
};

Mailbox maildir_mailbox = {
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
	FALSE,
	FALSE
};
