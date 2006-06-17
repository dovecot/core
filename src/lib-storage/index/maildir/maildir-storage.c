/* Copyright (C) 2002-2003 Timo Sirainen */

#include "lib.h"
#include "hostpid.h"
#include "home-expand.h"
#include "mkdir-parents.h"
#include "unlink-directory.h"
#include "subscription-file/subscription-file.h"
#include "maildir-storage.h"
#include "maildir-uidlist.h"
#include "maildir-keywords.h"
#include "index-mail.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#define CREATE_MODE 0770 /* umask() should limit it more */

/* Don't allow creating too long mailbox names. They could start causing
   problems when they reach the limit. */
#define MAILDIR_MAX_MAILBOX_NAME_LENGTH (PATH_MAX/2)

struct rename_context {
	bool found;
	size_t oldnamelen;
	const char *newname;
};

extern struct mail_storage maildir_storage;
extern struct mailbox maildir_mailbox;

static const char *maildirs[] = { "cur", "new", "tmp", NULL  };

static int verify_inbox(struct maildir_storage *storage);

static struct mail_storage *
maildir_create(const char *data, const char *user,
	       enum mail_storage_flags flags,
	       enum mail_storage_lock_method lock_method)
{
	bool debug = (flags & MAIL_STORAGE_FLAG_DEBUG) != 0;
	struct maildir_storage *storage;
	struct index_storage *istorage;
	const char *root_dir, *inbox_dir, *index_dir, *control_dir;
	const char *home, *path, *p;
	size_t len;
	pool_t pool;

	inbox_dir = root_dir = index_dir = control_dir = NULL;

	if (data == NULL || *data == '\0') {
		/* we'll need to figure out the maildir location ourself.
		   It's $HOME/Maildir unless we are chrooted. */
		if ((home = getenv("HOME")) != NULL) {
			path = t_strconcat(home, "/Maildir", NULL);
			if (access(path, R_OK|W_OK|X_OK) == 0) {
				if (debug) {
					i_info("maildir: root exists (%s)",
					       path);
				}
				root_dir = path;
			} else {
				if (debug) {
					i_info("maildir: access(%s, rwx): "
					       "failed: %m", path);
				}
			}
		} else {
			if (debug)
				i_info("maildir: HOME not set");
		}

		if (access("/cur", R_OK|W_OK|X_OK) == 0) {
			if (debug)
				i_info("maildir: /cur exists, assuming chroot");
			root_dir = "/";
		}
	} else {
		/* <Maildir> [:INBOX=<dir>] [:INDEX=<dir>] [:CONTROL=<dir>] */
		if (debug)
			i_info("maildir: data=%s", data);
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

	if (root_dir == NULL) {
		if (debug)
			i_info("maildir: couldn't find root dir");
		return NULL;
	}

	/* strip trailing '/' */
	len = strlen(root_dir);
	if (root_dir[len-1] == '/')
		root_dir = t_strndup(root_dir, len-1);

	if (index_dir == NULL)
		index_dir = root_dir;
	else if (strcmp(index_dir, "MEMORY") == 0)
		index_dir = NULL;

	if (debug) {
		i_info("maildir: root=%s, index=%s, control=%s, inbox=%s",
		       root_dir, index_dir == NULL ? "" : index_dir,
		       control_dir == NULL ? "" : control_dir,
		       inbox_dir == NULL ? "" : inbox_dir);
	}

	pool = pool_alloconly_create("storage", 512);
	storage = p_new(pool, struct maildir_storage, 1);
	storage->control_dir = p_strdup(pool, home_expand(control_dir));
	storage->copy_with_hardlinks =
		getenv("MAILDIR_COPY_WITH_HARDLINKS") != NULL;

	istorage = INDEX_STORAGE(storage);
	istorage->storage = maildir_storage;
	istorage->storage.pool = pool;

	/* the default ".temp.xxx" prefix would be treated as directory */
	istorage->temp_prefix =
		p_strconcat(pool, "temp.", my_hostname, ".", my_pid, ".", NULL);

	istorage->dir = p_strdup(pool, home_expand(root_dir));
	istorage->inbox_path = p_strdup(pool, home_expand(inbox_dir));
	istorage->index_dir = p_strdup(pool, home_expand(index_dir));
	istorage->user = p_strdup(pool, user);
	istorage->callbacks = p_new(pool, struct mail_storage_callbacks, 1);
	index_storage_init(istorage, flags, lock_method);

	(void)verify_inbox(storage);
	return STORAGE(storage);
}

static void maildir_free(struct mail_storage *_storage)
{
	struct index_storage *storage = (struct index_storage *) _storage;

	index_storage_deinit(storage);
	pool_unref(storage->storage.pool);
}

static bool maildir_autodetect(const char *data, enum mail_storage_flags flags)
{
	bool debug = (flags & MAIL_STORAGE_FLAG_DEBUG) != 0;
	struct stat st;
	const char *path;

	data = t_strcut(data, ':');

	path = t_strconcat(data, "/cur", NULL);
	if (stat(path, &st) < 0) {
		if (debug)
			i_info("maildir autodetect: stat(%s) failed: %m", path);
		return FALSE;
	}

	if (!S_ISDIR(st.st_mode)) {
		if (debug)
			i_info("maildir autodetect: %s not a directory", path);
		return FALSE;
	}
	return TRUE;
}

static bool maildir_is_valid_create_name(struct mail_storage *storage,
					 const char *name)
{
	size_t len;

	/* check that there are no adjacent hierarchy separators */
	for (len = 0; name[len] != '\0'; len++) {
		if (name[len] == MAILDIR_FS_SEP &&
		    name[len+1] == MAILDIR_FS_SEP)
			return FALSE;
	}

	if (len == 0 || len > MAILDIR_MAX_MAILBOX_NAME_LENGTH ||
	    name[0] == MAILDIR_FS_SEP || name[len-1] == MAILDIR_FS_SEP)
		return FALSE;

	if ((storage->flags & MAIL_STORAGE_FLAG_FULL_FS_ACCESS) != 0)
		return TRUE;

	if (*name == '~' || strchr(name, '/') != NULL)
		return FALSE;

	if (name[0] == '.' && (name[1] == '\0' ||
			       (name[1] == '.' && name[2] == '\0'))) {
		/* "." and ".." aren't allowed. */
		return FALSE;
	}

	if (mailbox_name_is_too_large(name, '.'))
		return FALSE;

	return TRUE;
}

static bool maildir_is_valid_existing_name(struct mail_storage *storage,
					   const char *name)
{
	if (name[0] == '\0' || name[strlen(name)-1] == '/')
		return FALSE;

	if ((storage->flags & MAIL_STORAGE_FLAG_FULL_FS_ACCESS) != 0)
		return TRUE;

	if (*name == '~' || strchr(name, '/') != NULL)
		return FALSE;

	if (name[0] == '.' && (name[1] == '\0' ||
			       (name[1] == '.' && name[2] == '\0'))) {
		/* "." and ".." aren't allowed. */
		return FALSE;
	}

	return TRUE;
}

static const char *maildir_get_absolute_path(const char *name)
{
	const char *p;

	name = home_expand(name);

	p = strrchr(name, '/');
	if (p == NULL)
		return name;
	return t_strconcat(t_strdup_until(name, p+1),
			   MAILDIR_FS_SEP_S, p+1, NULL);
}

const char *maildir_get_path(struct index_storage *storage, const char *name)
{
	if ((storage->storage.flags & MAIL_STORAGE_FLAG_FULL_FS_ACCESS) != 0 &&
	    (*name == '/' || *name == '~'))
		return maildir_get_absolute_path(name);

	if (strcmp(name, "INBOX") == 0) {
		return storage->inbox_path != NULL ?
			storage->inbox_path : storage->dir;
	}

	return t_strconcat(storage->dir, "/"MAILDIR_FS_SEP_S, name, NULL);
}

static const char *
maildir_get_unlink_dest(struct index_storage *storage, const char *name)
{
	if ((storage->storage.flags & MAIL_STORAGE_FLAG_FULL_FS_ACCESS) != 0 &&
	    (*name == '/' || *name == '~'))
		return NULL;

	return maildir_get_path(storage, MAILDIR_UNLINK_DIRNAME);
}

static const char *maildir_get_index_path(struct index_storage *storage,
					  const char *name)
{
	if (storage->index_dir == NULL)
		return NULL;

	if (strcmp(name, "INBOX") == 0 &&
	    strcmp(storage->index_dir, storage->dir) == 0)
		return storage->dir;

	if ((storage->storage.flags & MAIL_STORAGE_FLAG_FULL_FS_ACCESS) != 0 &&
	    (*name == '/' || *name == '~'))
		return maildir_get_absolute_path(name);

	return t_strconcat(storage->index_dir, "/"MAILDIR_FS_SEP_S, name, NULL);
}

static const char *maildir_get_control_path(struct maildir_storage *storage,
					    const char *name)
{
	if (storage->control_dir == NULL)
		return maildir_get_path(INDEX_STORAGE(storage), name);

	if ((STORAGE(storage)->flags & MAIL_STORAGE_FLAG_FULL_FS_ACCESS) != 0 &&
	    (*name == '/' || *name == '~'))
		return maildir_get_absolute_path(name);

	return t_strconcat(storage->control_dir, "/"MAILDIR_FS_SEP_S,
			   name, NULL);
}

static int mkdir_verify(struct index_storage *storage,
			const char *dir, bool verify)
{
	struct stat st;

	if (verify) {
		if (lstat(dir, &st) == 0)
			return 0;

		if (errno != ENOENT) {
			mail_storage_set_critical(&storage->storage,
						  "lstat(%s) failed: %m", dir);
			return -1;
		}
	}

	if (mkdir_parents(dir, CREATE_MODE) < 0 &&
	    (errno != EEXIST || !verify)) {
		if (errno != EEXIST && (!verify || errno != ENOENT)) {
			mail_storage_set_critical(&storage->storage,
						  "mkdir(%s) failed: %m", dir);
		}
		return -1;
	}

	return 0;
}

/* create or fix maildir, ignore if it already exists */
static int create_maildir(struct index_storage *storage,
			  const char *dir, bool verify)
{
	const char **tmp, *path;

	if (!verify && mkdir_verify(storage, dir, verify) < 0)
		return -1;

	for (tmp = maildirs; *tmp != NULL; tmp++) {
		path = t_strconcat(dir, "/", *tmp, NULL);

		if (mkdir_verify(storage, path, verify) < 0) {
			if (!verify || errno != ENOENT)
				return -1;

			/* small optimization. if we're verifying, we don't
			   check that the root dir actually exists unless we
			   fail here. */
			if (mkdir_verify(storage, dir, verify) < 0)
				return -1;
			if (mkdir_verify(storage, path, verify) < 0)
				return -1;
		}
	}

	return 0;
}

static int create_index_dir(struct index_storage *storage, const char *name)
{
	const char *dir;

	if (storage->index_dir == NULL)
		return 0;

	if (strcmp(storage->index_dir, storage->dir) == 0 ||
	    (strcmp(name, "INBOX") == 0 && storage->inbox_path != NULL &&
	     strcmp(storage->index_dir, storage->inbox_path) == 0))
		return 0;

	dir = t_strconcat(storage->index_dir, "/"MAILDIR_FS_SEP_S, name, NULL);
	if (mkdir_parents(dir, CREATE_MODE) < 0 && errno != EEXIST) {
		mail_storage_set_critical(&storage->storage,
					  "mkdir(%s) failed: %m", dir);
		return -1;
	}

	return 0;
}

static int create_control_dir(struct maildir_storage *storage, const char *name)
{
	const char *dir;

	if (storage->control_dir == NULL)
		return 0;

	dir = t_strconcat(storage->control_dir, "/"MAILDIR_FS_SEP_S,
			  name, NULL);
	if (mkdir_parents(dir, CREATE_MODE) < 0 && errno != EEXIST) {
		mail_storage_set_critical(STORAGE(storage),
					  "mkdir(%s) failed: %m", dir);
		return -1;
	}

	return 0;
}

static int verify_inbox(struct maildir_storage *storage)
{
	struct index_storage *istorage = INDEX_STORAGE(storage);
	const char *path;

	path = istorage->inbox_path != NULL ?
		istorage->inbox_path : istorage->dir;

	if (create_maildir(istorage, path, TRUE) < 0)
		return -1;

	/* make sure the index directories exist */
	if (create_index_dir(istorage, "INBOX") < 0)
		return -1;
	if (create_control_dir(storage, "INBOX") < 0)
		return -1;
	return 0;
}

static bool maildir_is_recent(struct index_mailbox *ibox, uint32_t uid)
{
	struct maildir_mailbox *mbox = (struct maildir_mailbox *)ibox;

	return maildir_uidlist_is_recent(mbox->uidlist, uid);
}

static struct mailbox *
maildir_open(struct maildir_storage *storage, const char *name,
	     enum mailbox_open_flags flags)
{
	struct index_storage *istorage = INDEX_STORAGE(storage);
	struct maildir_mailbox *mbox;
	struct mail_index *index;
	const char *path, *index_dir, *control_dir;
	struct stat st;
	int shared;
	pool_t pool;

	path = maildir_get_path(istorage, name);
	index_dir = maildir_get_index_path(istorage, name);
	control_dir = maildir_get_control_path(storage, name);

	if ((flags & MAILBOX_OPEN_NO_INDEX_FILES) != 0)
		index_dir = NULL;

	index = index_storage_alloc(index_dir, path,
				    MAILDIR_INDEX_PREFIX);

	/* for shared mailboxes get the create mode from the
	   permissions of dovecot-shared file. */
	shared = stat(t_strconcat(path, "/dovecot-shared", NULL), &st) == 0;
	if (shared)
		mail_index_set_permissions(index, st.st_mode & 0666, st.st_gid);

	pool = pool_alloconly_create("mailbox", 1024);
	mbox = p_new(pool, struct maildir_mailbox, 1);
	mbox->ibox.box = maildir_mailbox;
	mbox->ibox.box.pool = pool;
	mbox->ibox.storage = istorage;
	mbox->ibox.mail_vfuncs = &maildir_mail_vfuncs;
	mbox->ibox.is_recent = maildir_is_recent;

	if (index_storage_mailbox_init(&mbox->ibox, index, name, flags,
				       FALSE) < 0) {
		/* the memory was already freed */
		return NULL;
	}

	mbox->storage = storage;
	mbox->path = p_strdup(pool, path);
	mbox->control_dir = p_strdup(pool, control_dir);

	mbox->uidlist = maildir_uidlist_init(mbox);
	mbox->keywords = maildir_keywords_init(mbox);

	if (!shared)
		mbox->mail_create_mode = 0600;
	else {
		mbox->mail_create_mode = st.st_mode & 0666;
		mbox->private_flags_mask = MAIL_SEEN;
	}

	if (mbox->ibox.keep_locked) {
		if (maildir_uidlist_lock(mbox->uidlist) <= 0) {
			struct mailbox *box = &mbox->ibox.box;

			mailbox_close(&box);
			return NULL;
		}
	}

	return &mbox->ibox.box;
}

static const char *
maildir_get_mailbox_path(struct mail_storage *_storage,
			 const char *name, bool *is_file_r)
{
	struct maildir_storage *storage = (struct maildir_storage *)_storage;
	struct index_storage *istorage = INDEX_STORAGE(storage);

	*is_file_r = FALSE;
	if (*name == '\0')
		return istorage->dir;
	return maildir_get_path(istorage, name);
}

static const char *
maildir_get_mailbox_control_dir(struct mail_storage *_storage, const char *name)
{
	struct maildir_storage *storage = (struct maildir_storage *)_storage;

	return maildir_get_control_path(storage, name);
}

static struct mailbox *
maildir_mailbox_open(struct mail_storage *_storage, const char *name,
		     struct istream *input, enum mailbox_open_flags flags)
{
	struct maildir_storage *storage = (struct maildir_storage *)_storage;
	struct index_storage *istorage = INDEX_STORAGE(storage);
	const char *path;
	struct stat st;

	mail_storage_clear_error(_storage);

	if (input != NULL) {
		mail_storage_set_critical(_storage,
			"Maildir doesn't support streamed mailboxes");
		return NULL;
	}

	if (strcmp(name, "INBOX") == 0) {
		if (verify_inbox(storage) < 0)
			return NULL;
		return maildir_open(storage, "INBOX", flags);
	}

	if (!maildir_is_valid_existing_name(_storage, name)) {
		mail_storage_set_error(_storage, "Invalid mailbox name");
		return NULL;
	}

	path = maildir_get_path(istorage, name);
	if (stat(path, &st) == 0) {
		/* exists - make sure the required directories are also there */
		if (create_maildir(istorage, path, TRUE) < 0 ||
		    create_control_dir(storage, name) < 0)
			return NULL;

		if ((flags & MAILBOX_OPEN_NO_INDEX_FILES) == 0) {
			if (create_index_dir(istorage, name) < 0)
				return NULL;
		}

		return maildir_open(storage, name, flags);
	} else if (errno == ENOENT) {
		mail_storage_set_error(_storage,
			MAIL_STORAGE_ERR_MAILBOX_NOT_FOUND, name);
		return NULL;
	} else {
		mail_storage_set_critical(_storage, "stat(%s) failed: %m",
					  path);
		return NULL;
	}
}

static int maildir_create_shared(struct mail_storage *storage,
				 const char *path, mode_t mode, gid_t gid)
{
	mode_t old_mask = umask(0);
	int fd;

	fd = open(path, O_WRONLY | O_CREAT, mode);
	umask(old_mask);

	if (fd == -1) {
		mail_storage_set_critical(storage,
					  "open(%s) failed: %m", path);
		return -1;
	}

	if (fchown(fd, (uid_t)-1, gid) < 0) {
		mail_storage_set_critical(storage,
					  "fchown(%s) failed: %m", path);
	}
	(void)close(fd);
	return 0;
}

static int maildir_mailbox_create(struct mail_storage *_storage,
				  const char *name,
				  bool directory __attr_unused__)
{
	struct index_storage *storage = (struct index_storage *)_storage;
	struct stat st;
	const char *path, *shared_path;

	mail_storage_clear_error(_storage);

	if (!maildir_is_valid_create_name(_storage, name)) {
		mail_storage_set_error(_storage, "Invalid mailbox name");
		return -1;
	}

	path = maildir_get_path(storage, name);
	if (create_maildir(storage, path, FALSE) < 0) {
		if (errno == EEXIST) {
			mail_storage_set_error(_storage,
					       "Mailbox already exists");
		}
		return -1;
	}

	/* if dovecot-shared exists in the root dir, copy it to the
	   created mailbox */
	shared_path = t_strconcat(storage->dir, "/dovecot-shared", NULL);
	if (stat(shared_path, &st) == 0) {
		path = t_strconcat(path, "/dovecot-shared", NULL);
		(void)maildir_create_shared(_storage, path,
					    st.st_mode & 0666, st.st_gid);
	}

	return 0;
}

static int maildir_mailbox_delete(struct mail_storage *_storage,
				  const char *name)
{
	struct index_storage *storage = (struct index_storage *)_storage;
	struct stat st;
	const char *src, *dest, *index_dir;
	int count;

	mail_storage_clear_error(_storage);

	if (strcmp(name, "INBOX") == 0) {
		mail_storage_set_error(_storage, "INBOX can't be deleted.");
		return -1;
	}

	if (!maildir_is_valid_existing_name(_storage, name)) {
		mail_storage_set_error(_storage, "Invalid mailbox name");
		return -1;
	}

	/* rename the .maildir into ..DOVECOT-TRASH which marks it as being
	   deleted. delete indexes before the actual maildir. this way we
	   never see partially deleted mailboxes. */
	src = maildir_get_path(storage, name);
	dest = maildir_get_unlink_dest(storage, name);
	if (stat(src, &st) != 0 && errno == ENOENT) {
		mail_storage_set_error(_storage,
			MAIL_STORAGE_ERR_MAILBOX_NOT_FOUND, name);
		return -1;
	}

	/* Make sure the indexes are closed before trying to delete the
	   directory that contains them. It can still fail with some NFS
	   implementations if indexes are opened by another session, but
	   can't really help that. */
	index_storage_destroy_unrefed();

	if (storage->index_dir != NULL && *name != '/' && *name != '~' &&
	    strcmp(storage->index_dir, storage->dir) != 0) {
		index_dir = t_strconcat(storage->index_dir,
					"/"MAILDIR_FS_SEP_S, name, NULL);
		if (unlink_directory(index_dir, TRUE) < 0 &&
		    errno != ENOTEMPTY) {
			mail_storage_set_critical(_storage,
				"unlink_directory(%s) failed: %m", index_dir);
			return -1;
		}
	}

	if (dest == NULL) {
		/* absolute maildir path, delete the directory directly
		   without any renaming */
		dest = src;
	} else {
		count = 0;
		while (rename(src, dest) < 0 && count < 2) {
			/* EBUSY is given by some NFS implementations */
			if (errno != EEXIST && errno != ENOTEMPTY &&
			    errno != EBUSY) {
				mail_storage_set_critical(_storage,
					"rename(%s, %s) failed: %m", src, dest);
				return -1;
			}

			/* already existed, delete it and try again */
			if (unlink_directory(dest, TRUE) < 0) {
				mail_storage_set_critical(_storage,
					"unlink_directory(%s) failed: %m",
					dest);
				return -1;
			}
			count++;
		}
	}

	if (unlink_directory(dest, TRUE) < 0 && errno != ENOTEMPTY) {
		mail_storage_set_critical(_storage,
			"unlink_directory(%s) failed: %m", dest);

		/* it's already renamed to ..dir, which means it's deleted
		   as far as client is concerned. Report success. */
	}

	return 0;
}

static int rename_indexes(struct index_storage *storage,
			  const char *oldname, const char *newname)
{
	const char *oldpath, *newpath;

	if (storage->index_dir == NULL ||
	    strcmp(storage->index_dir, storage->dir) == 0)
		return 0;

	/* Rename it's index. */
	oldpath = t_strconcat(storage->index_dir, "/"MAILDIR_FS_SEP_S,
			      oldname, NULL);
	newpath = t_strconcat(storage->index_dir, "/"MAILDIR_FS_SEP_S,
			      newname, NULL);

	if (rename(oldpath, newpath) < 0 && errno != ENOENT) {
		mail_storage_set_critical(&storage->storage,
					  "rename(%s, %s) failed: %m",
					  oldpath, newpath);
		return -1;
	}

	return 0;
}

static int rename_subfolders(struct index_storage *storage,
			     const char *oldname, const char *newname)
{
	struct mailbox_list_context *ctx;
        struct mailbox_list *list;
	const char *oldpath, *newpath, *new_listname;
	size_t oldnamelen;
	int ret;

	ret = 0;
	oldnamelen = strlen(oldname);

	ctx = maildir_mailbox_list_init(&storage->storage, oldname, "*",
					MAILBOX_LIST_FAST_FLAGS);
	while ((list = maildir_mailbox_list_next(ctx)) != NULL) {
		t_push();

		i_assert(oldnamelen <= strlen(list->name));

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
			mail_storage_set_critical(&storage->storage,
						  "rename(%s, %s) failed: %m",
						  oldpath, newpath);
			ret = -1;
			t_pop();
			break;
		}

		(void)rename_indexes(storage, list->name, new_listname);
		t_pop();
	}

	if (maildir_mailbox_list_deinit(ctx) < 0)
		return -1;
	return ret;
}

static int maildir_mailbox_rename(struct mail_storage *_storage,
				  const char *oldname, const char *newname)
{
	struct index_storage *storage = (struct index_storage *)_storage;
	const char *oldpath, *newpath;
	int ret;
        bool found;

	mail_storage_clear_error(_storage);

	if (!maildir_is_valid_existing_name(_storage, oldname) ||
	    !maildir_is_valid_create_name(_storage, newname)) {
		mail_storage_set_error(_storage, "Invalid mailbox name");
		return -1;
	}

	if (strcmp(oldname, "INBOX") == 0) {
		mail_storage_set_error(_storage,
				       "Renaming INBOX isn't supported.");
		return -1;
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
			return -1;
		if (!found && ret == 0) {
			mail_storage_set_error(_storage,
				MAIL_STORAGE_ERR_MAILBOX_NOT_FOUND, oldname);
			return -1;
		}

		return 0;
	}

	if (errno == EEXIST) {
		mail_storage_set_error(_storage,
				       "Target mailbox already exists");
		return -1;
	} else {
		mail_storage_set_critical(_storage, "rename(%s, %s) failed: %m",
					  oldpath, newpath);
		return -1;
	}
}

static int maildir_set_subscribed(struct mail_storage *_storage,
				  const char *name, bool set)
{
	struct maildir_storage *storage = (struct maildir_storage *)_storage;
	const char *path;

	path = t_strconcat(storage->control_dir != NULL ?
			   storage->control_dir : INDEX_STORAGE(storage)->dir,
			   "/" SUBSCRIPTION_FILE_NAME, NULL);

	return subsfile_set_subscribed(_storage, path,
				       INDEX_STORAGE(storage)->temp_prefix,
				       name, set);
}

static int maildir_get_mailbox_name_status(struct mail_storage *_storage,
					   const char *name,
					   enum mailbox_name_status *status)
{
	struct index_storage *storage = (struct index_storage *)_storage;
	struct stat st;
	const char *path;

	mail_storage_clear_error(_storage);

	if (!maildir_is_valid_existing_name(_storage, name)) {
		*status = MAILBOX_NAME_INVALID;
		return 0;
	}

	path = maildir_get_path(storage, name);
	if (strcmp(name, "INBOX") == 0 || stat(path, &st) == 0) {
		*status = MAILBOX_NAME_EXISTS;
		return 0;
	}

	if (!maildir_is_valid_create_name(_storage, name)) {
		*status = MAILBOX_NAME_INVALID;
		return 0;
	}

	if (errno == ENOENT) {
		*status = MAILBOX_NAME_VALID;
		return 0;
	} else {
		mail_storage_set_critical(_storage, "stat(%s) failed: %m",
					  path);
		return -1;
	}
}

static int maildir_storage_close(struct mailbox *box)
{
	struct maildir_mailbox *mbox = (struct maildir_mailbox *)box;
	int ret = 0;

	/*FIXME:if (!maildir_try_flush_dirty_flags(ibox->index, TRUE)) {
		mail_storage_set_index_error(ibox);
		ret = -1;
	}*/

	if (mbox->ibox.keep_locked)
		maildir_uidlist_unlock(mbox->uidlist);

	maildir_keywords_deinit(mbox->keywords);
	maildir_uidlist_deinit(mbox->uidlist);
        index_storage_mailbox_free(box);
	return ret;
}

static void
maildir_notify_changes(struct mailbox *box, unsigned int min_interval,
		       mailbox_notify_callback_t *callback, void *context)
{
	struct maildir_mailbox *mbox = (struct maildir_mailbox *)box;

	mbox->ibox.min_notify_interval = min_interval;
	mbox->ibox.notify_callback = callback;
	mbox->ibox.notify_context = context;

	if (callback == NULL) {
		index_mailbox_check_remove_all(&mbox->ibox);
		return;
	}

	index_mailbox_check_add(&mbox->ibox,
		t_strconcat(mbox->path, "/new", NULL));
	index_mailbox_check_add(&mbox->ibox,
		t_strconcat(mbox->path, "/cur", NULL));
}

struct mail_storage maildir_storage = {
	MEMBER(name) "maildir",
	MEMBER(hierarchy_sep) MAILDIR_FS_SEP,

	{
		maildir_create,
		maildir_free,
		maildir_autodetect,
		index_storage_set_callbacks,
		maildir_get_mailbox_path,
		maildir_get_mailbox_control_dir,
		maildir_mailbox_open,
		maildir_mailbox_create,
		maildir_mailbox_delete,
		maildir_mailbox_rename,
		maildir_mailbox_list_init,
		maildir_mailbox_list_next,
		maildir_mailbox_list_deinit,
		maildir_set_subscribed,
		maildir_get_mailbox_name_status,
		index_storage_get_last_error
	}
};

struct mailbox maildir_mailbox = {
	MEMBER(name) NULL, 
	MEMBER(storage) NULL, 

	{
		index_storage_is_readonly,
		index_storage_allow_new_keywords,
		maildir_storage_close,
		index_storage_get_status,
		maildir_storage_sync_init,
		index_mailbox_sync_next,
		index_mailbox_sync_deinit,
		maildir_notify_changes,
		maildir_transaction_begin,
		maildir_transaction_commit,
		maildir_transaction_rollback,
		index_keywords_create,
		index_keywords_free,
		index_storage_get_uids,
		index_mail_alloc,
		index_header_lookup_init,
		index_header_lookup_deinit,
		index_storage_search_init,
		index_storage_search_deinit,
		index_storage_search_next,
		index_storage_search_next_update_seq,
		maildir_save_init,
		maildir_save_continue,
		maildir_save_finish,
		maildir_save_cancel,
		maildir_copy,
		index_storage_is_inconsistent
	}
};
