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
	storage->callbacks = i_new(MailStorageCallbacks, 1);
	return storage;
}

static void maildir_free(MailStorage *storage)
{
	i_free(storage->callbacks);
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
		name[strlen(name)-1] != storage->hierarchy_sep &&
		strchr(name, '/') == NULL && strchr(name, '\\') == NULL &&
		strchr(name, '*') == NULL && strchr(name, '%') == NULL;
}

/* create or fix maildir, ignore if it already exists */
static int create_maildir(const char *dir, int verify)
{
	const char **tmp;
	char path[PATH_MAX];

	if (mkdir(dir, CREATE_MODE) == -1 && (errno != EEXIST || !verify))
		return FALSE;

	for (tmp = maildirs; *tmp != NULL; tmp++) {
		if (str_path(path, sizeof(path), dir, *tmp) < 0)
			return FALSE;

		if (mkdir(path, CREATE_MODE) == -1 &&
		    (errno != EEXIST || !verify))
			return FALSE;
	}

	return TRUE;
}

static int verify_inbox(MailStorage *storage, const char *dir)
{
	const char **tmp;
	char src[PATH_MAX], dest[PATH_MAX];

	/* first make sure the cur/ new/ and tmp/ dirs exist in root dir */
	(void)create_maildir(dir, TRUE);

	/* create the .INBOX directory */
	if (str_path(dest, sizeof(dest), dir, ".INBOX") < 0) {
		mail_storage_set_critical(storage, "Path too long: %s", dir);
		return FALSE;
	}

	if (mkdir(dest, CREATE_MODE) == -1 && errno != EEXIST) {
		mail_storage_set_critical(storage, "Can't create directory "
					  "%s: %m", dest);
		return FALSE;
	}

	/* then symlink the cur/ new/ and tmp/ into the .INBOX/ directory */
	for (tmp = maildirs; *tmp != NULL; tmp++) {
		if (str_path(src, sizeof(src), "..", *tmp) < 0) {
			mail_storage_set_critical(storage, "Path too long: %s",
						  *tmp);
			return FALSE;
		}
		if (str_ppath(dest, sizeof(dest), dir, ".INBOX/", *tmp) < 0) {
			mail_storage_set_critical(storage, "Path too long: %s",
						  dir);
			return FALSE;
		}

		if (symlink(src, dest) == -1 && errno != EEXIST) {
			mail_storage_set_critical(storage, "symlink(%s, %s) "
						  "failed: %m", src, dest);
			return FALSE;
		}
	}

	return TRUE;
}

static Mailbox *maildir_open(MailStorage *storage, const char *name,
			     int readonly, int fast)
{
	IndexMailbox *ibox;
	MailIndex *index;
	const char *path;

	path = t_strconcat(storage->dir, "/.", name, NULL);

	index = index_storage_lookup_ref(path);
	if (index == NULL) {
		index = maildir_index_alloc(path);
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
	struct stat st;
	char path[PATH_MAX];

	mail_storage_clear_error(storage);

	name = inbox_fix_case(storage, name);
	if (strcmp(name, "INBOX") == 0) {
		if (!verify_inbox(storage, storage->dir))
			return NULL;
		return maildir_open(storage, "INBOX", readonly, fast);
	}

	if (!maildir_is_valid_name(storage, name)) {
		mail_storage_set_error(storage, "Invalid mailbox name");
		return FALSE;
	}

	if (str_ppath(path, sizeof(path), storage->dir, ".", name) < 0) {
		mail_storage_set_critical(storage, "Mailbox name too long: %s",
					  name);
		return FALSE;
	}

	if (stat(path, &st) == 0) {
		/* exists - make sure the required directories are also there */
		(void)create_maildir(path, TRUE);

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
	char path[PATH_MAX];

	mail_storage_clear_error(storage);

	name = inbox_fix_case(storage, name);
	if (!maildir_is_valid_name(storage, name)) {
		mail_storage_set_error(storage, "Invalid mailbox name");
		return FALSE;
	}

	if (str_ppath(path, sizeof(path), storage->dir, ".", name) < 0) {
		mail_storage_set_critical(storage, "Mailbox name too long: %s",
					  name);
		return FALSE;
	}

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
	char src[PATH_MAX], dest[PATH_MAX];
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
	   deleted. this way we never see partially deleted maildirs. */
	if (str_ppath(src, sizeof(src), storage->dir, ".", name) < 0) {
		mail_storage_set_critical(storage, "Mailbox name too long: %s",
					  name);
		return FALSE;
	}

	if (str_ppath(dest, sizeof(dest), storage->dir, "..", name) < 0) {
		mail_storage_set_critical(storage, "Mailbox name too long: %s",
					  name);
		return FALSE;
	}

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
	char oldpath[PATH_MAX], newpath[PATH_MAX];

	/* newpath points to the destination folder directory, which contains
	   symlinks to real INBOX directories. unlink() the symlinks and
	   move the real cur/ directory here. */
	for (tmp = maildirs; *tmp != NULL; tmp++) {
		if (str_path(newpath, sizeof(newpath), newdir, *tmp) < 0) {
			mail_storage_set_critical(storage, "Path too long: %s",
						  newdir);
			return FALSE;
		}

		if (unlink(newpath) == -1 && errno != EEXIST) {
			mail_storage_set_critical(storage,
						  "unlink(%s) failed: %m",
						  newpath);
			return FALSE;
		}
	}

	if (str_path(oldpath, sizeof(oldpath), storage->dir, "cur") < 0) {
		mail_storage_set_critical(storage, "Path too long: %s",
					  storage->dir);
		return FALSE;
	}
	if (str_path(newpath, sizeof(newpath), newdir, "cur") < 0) {
		mail_storage_set_critical(storage, "Path too long: %s", newdir);
		return FALSE;
	}

	if (rename(oldpath, newpath) != 0) {
		mail_storage_set_critical(storage, "rename(%s, %s) failed: %m",
					  oldpath, newpath);
		return FALSE;
	}

	/* create back the cur/ directory for INBOX */
	(void)mkdir(oldpath, CREATE_MODE);
	return TRUE;
}

static void rename_subfolder(MailStorage *storage, const char *name,
			     MailboxFlags flags __attr_unused__, void *context)
{
	RenameContext *ctx = context;
	char oldpath[PATH_MAX], newpath[PATH_MAX];

	i_assert(ctx->oldnamelen <= strlen(name));

	if (str_ppath(oldpath, sizeof(oldpath), storage->dir, ".", name) < 0) {
		mail_storage_set_critical(storage, "Mailbox name too long: %s",
					  name);
		return;
	}

	if (i_snprintf(newpath, sizeof(newpath), "%s/.%s.%s", storage->dir,
		       ctx->newname, name + ctx->oldnamelen) < 0) {
		mail_storage_set_critical(storage, "Mailbox name too long: %s",
					  newpath);
		return;
	}

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
}

static int maildir_rename_mailbox(MailStorage *storage, const char *oldname,
				  const char *newname)
{
	RenameContext ctx;
	char oldpath[PATH_MAX], newpath[PATH_MAX];
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
	if (str_ppath(oldpath, sizeof(oldpath),
		      storage->dir, ".", oldname) < 0) {
		mail_storage_set_critical(storage, "Mailbox name too long: %s",
					  oldname);
		return FALSE;
	}

	if (str_ppath(newpath, sizeof(newpath),
		      storage->dir, ".", newname) < 0) {
		mail_storage_set_critical(storage, "Mailbox name too long: %s",
					  newname);
		return FALSE;
	}

	ret = rename(oldpath, newpath);
	if (ret == 0 || (errno == ENOENT && strcmp(oldname, "INBOX") != 0)) {
		if (strcmp(oldname, "INBOX") == 0)
			return move_inbox_data(storage, newpath);

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
	char path[PATH_MAX];

	mail_storage_clear_error(storage);

	name = inbox_fix_case(storage, name);
	if (!maildir_is_valid_name(storage, name)) {
		*status = MAILBOX_NAME_INVALID;
		return TRUE;
	}

	if (str_ppath(path, sizeof(path), storage->dir, ".", name) == 0 &&
	    stat(path, &st) == 0) {
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
	NULL, NULL
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
