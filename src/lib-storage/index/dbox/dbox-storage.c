/* Copyright (C) 2005 Timo Sirainen */

#include "lib.h"
#include "home-expand.h"
#include "mkdir-parents.h"
#include "unlink-directory.h"
#include "subscription-file/subscription-file.h"
#include "mail-copy.h"
#include "index-mail.h"
#include "dbox-uidlist.h"
#include "dbox-sync.h"
#include "dbox-file.h"
#include "dbox-storage.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#define CREATE_MODE 0770 /* umask() should limit it more */

/* Don't allow creating too long mailbox names. They could start causing
   problems when they reach the limit. */
#define DBOX_MAX_MAILBOX_NAME_LENGTH (PATH_MAX/2)

extern struct mail_storage dbox_storage;
extern struct mailbox dbox_mailbox;

static bool dbox_handle_errors(struct index_storage *istorage)
{
	struct mail_storage *storage = &istorage->storage;

	if (ENOACCESS(errno))
		mail_storage_set_error(storage, MAIL_STORAGE_ERR_NO_PERMISSION);
	else if (ENOSPACE(errno))
		mail_storage_set_error(storage, "Not enough disk space");
	else if (ENOTFOUND(errno))
		mail_storage_set_error(storage, "Directory structure is broken");
	else
		return FALSE;
	return TRUE;
}

static struct mail_storage *
dbox_create(const char *data, const char *user,
	    enum mail_storage_flags flags,
	    enum mail_storage_lock_method lock_method)
{
	bool debug = (flags & MAIL_STORAGE_FLAG_DEBUG) != 0;
	struct dbox_storage *storage;
	struct index_storage *istorage;
	const char *root_dir, *index_dir, *p;
	size_t len;
	pool_t pool;

	root_dir = index_dir = NULL;

	if (data == NULL || *data == '\0') {
		/* we won't do any guessing for this format. */
		if (debug)
			i_info("dbox: mailbox location not given");
		return NULL;
	}

	/* <root dir> [:INDEX=<dir>] */
	if (debug)
		i_info("dbox: data=%s", data);
	p = strchr(data, ':');
	if (p == NULL)
		root_dir = data;
	else {
		root_dir = t_strdup_until(data, p);

		do {
			p++;
			if (strncmp(p, "INDEX=", 6) == 0)
				index_dir = t_strcut(p+6, ':');
			p = strchr(p, ':');
		} while (p != NULL);
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
		i_info("dbox: root=%s, index=%s",
		       root_dir, index_dir == NULL ? "" : index_dir);
	}

        root_dir = home_expand(root_dir);
	if (mkdir_parents(root_dir, CREATE_MODE) < 0 && errno != EEXIST) {
		i_error("mkdir_parents(%s) failed: %m", root_dir);
		return NULL;
	}

	pool = pool_alloconly_create("storage", 512);
	storage = p_new(pool, struct dbox_storage, 1);

	istorage = INDEX_STORAGE(storage);
	istorage->storage = dbox_storage;
	istorage->storage.pool = pool;

	istorage->dir = p_strdup(pool, root_dir);
	istorage->index_dir = p_strdup(pool, home_expand(index_dir));
	istorage->user = p_strdup(pool, user);
	istorage->callbacks = p_new(pool, struct mail_storage_callbacks, 1);
	index_storage_init(istorage, flags, lock_method);

	return STORAGE(storage);
}

static void dbox_free(struct mail_storage *_storage)
{
	struct index_storage *storage = (struct index_storage *) _storage;

	index_storage_deinit(storage);
	pool_unref(storage->storage.pool);
}

static bool dbox_autodetect(const char *data, enum mail_storage_flags flags)
{
	bool debug = (flags & MAIL_STORAGE_FLAG_DEBUG) != 0;
	struct stat st;
	const char *path;

	data = t_strcut(data, ':');

	path = t_strconcat(data, "/inbox/Mails", NULL);
	if (stat(path, &st) < 0) {
		if (debug)
			i_info("dbox autodetect: stat(%s) failed: %m", path);
		return FALSE;
	}

	if (!S_ISDIR(st.st_mode)) {
		if (debug)
			i_info("dbox autodetect: %s not a directory", path);
		return FALSE;
	}
	return TRUE;
}

bool dbox_is_valid_mask(struct mail_storage *storage, const char *mask)
{
	const char *p;
	bool newdir;

	if ((storage->flags & MAIL_STORAGE_FLAG_FULL_FS_ACCESS) != 0)
		return TRUE;

	/* make sure it's not absolute path */
	if (*mask == '/' || *mask == '~')
		return FALSE;

	/* make sure the mailbox name doesn't contain any foolishness:
	   "../" could give access outside the mailbox directory.
	   "./" and "//" could fool ACL checks. */
	newdir = TRUE;
	for (p = mask; *p != '\0'; p++) {
		if (newdir) {
			if (p[0] == '/')
				return FALSE; /* // */
			if (p[0] == '.') {
				if (p[1] == '/')
					return FALSE; /* ./ */
				if (p[1] == '.' && p[2] == '/')
					return FALSE; /* ../ */
			}
		} 
		newdir = p[0] == '/';
	}

	return TRUE;
}

static bool dbox_is_valid_create_name(struct mail_storage *storage,
				      const char *name)
{
	size_t len;

	len = strlen(name);
	if (name[0] == '\0' || name[len-1] == '/' ||
	    len > DBOX_MAX_MAILBOX_NAME_LENGTH)
		return FALSE;

	return dbox_is_valid_mask(storage, name);
}

static bool dbox_is_valid_existing_name(struct mail_storage *storage,
					const char *name)
{
	size_t len;

	len = strlen(name);
	if (name[0] == '\0' || name[len-1] == '/')
		return FALSE;

	return dbox_is_valid_mask(storage, name);
}

static const char *
dbox_get_path(struct index_storage *storage, const char *name)
{
	if ((storage->storage.flags & MAIL_STORAGE_FLAG_FULL_FS_ACCESS) != 0 &&
	    (*name == '/' || *name == '~'))
		return home_expand(name);

	return t_strconcat(storage->dir, "/", name, NULL);
}

static int create_dbox(struct index_storage *storage, const char *dir)
{
	const char *path;

	path = t_strconcat(dir, "/", DBOX_MAILDIR_NAME, NULL);
	if (mkdir_parents(path, CREATE_MODE) < 0 && errno != EEXIST) {
		if (dbox_handle_errors(storage))
			return -1;

		mail_storage_set_critical(&storage->storage,
					  "mkdir(%s) failed: %m", dir);
		return -1;
	}
	return 0;
}

static int create_index_dir(struct index_storage *storage, const char *name)
{
	const char *dir;

	if (storage->index_dir == NULL)
		return 0;

	if (strcmp(storage->index_dir, storage->dir) == 0)
		return 0;

	dir = t_strconcat(storage->index_dir, "/", name,
			  "/"DBOX_MAILDIR_NAME, NULL);
	if (mkdir_parents(dir, CREATE_MODE) < 0 && errno != EEXIST) {
		mail_storage_set_critical(&storage->storage,
					  "mkdir(%s) failed: %m", dir);
		return -1;
	}

	return 0;
}

static bool dbox_is_recent(struct index_mailbox *ibox __attr_unused__,
			   uint32_t uid __attr_unused__)
{
	return FALSE;
}

static const char *
dbox_get_index_dir(struct index_storage *storage, const char *name)
{
	const char *p;

	if (storage->index_dir == NULL)
		return NULL;

	if ((storage->storage.flags & MAIL_STORAGE_FLAG_FULL_FS_ACCESS) != 0 &&
	    (*name == '/' || *name == '~')) {
		name = home_expand(name);
		p = strrchr(name, '/');
		return t_strconcat(t_strdup_until(name, p),
				   "/"DBOX_MAILDIR_NAME"/", p+1, NULL);
	}

	return t_strconcat(storage->index_dir,
			   "/", name, "/"DBOX_MAILDIR_NAME, NULL);
}

static const char *
dbox_get_mailbox_path(struct mail_storage *_storage,
		      const char *name, bool *is_file_r)
{
	struct dbox_storage *storage = (struct dbox_storage *)_storage;
	struct index_storage *istorage = INDEX_STORAGE(storage);

	*is_file_r = FALSE;
	if (*name == '\0')
		return istorage->dir;
	return dbox_get_path(istorage, name);
}

static const char *
dbox_get_mailbox_control_dir(struct mail_storage *_storage, const char *name)
{
	struct dbox_storage *storage = (struct dbox_storage *)_storage;
	struct index_storage *istorage = INDEX_STORAGE(storage);

	return dbox_get_path(istorage, name);
}

static struct mailbox *
dbox_open(struct dbox_storage *storage, const char *name,
	  enum mailbox_open_flags flags)
{
	struct index_storage *istorage = INDEX_STORAGE(storage);
	struct dbox_mailbox *mbox;
	struct mail_index *index;
	const char *path, *index_dir, *value;
	pool_t pool;

	path = dbox_get_path(istorage, name);
	index_dir = dbox_get_index_dir(istorage, name);

	if (create_dbox(istorage, path) < 0)
		return NULL;
	if (create_index_dir(istorage, name) < 0)
		return NULL;

	index = index_storage_alloc(index_dir, path, DBOX_INDEX_PREFIX);

	pool = pool_alloconly_create("mailbox", 1024);
	mbox = p_new(pool, struct dbox_mailbox, 1);
	mbox->ibox.box = dbox_mailbox;
	mbox->ibox.box.pool = pool;
	mbox->ibox.storage = istorage;
	mbox->ibox.mail_vfuncs = &dbox_mail_vfuncs;
	mbox->ibox.is_recent = dbox_is_recent;

	if (index_storage_mailbox_init(&mbox->ibox, index, name, flags,
				       FALSE) < 0) {
		/* the memory was already freed */
		return NULL;
	}

	value = getenv("DBOX_ROTATE_SIZE");
	if (value != NULL)
		mbox->rotate_size = (uoff_t)strtoul(value, NULL, 10) * 1024;
	else
		mbox->rotate_size = DBOX_DEFAULT_ROTATE_SIZE;
	value = getenv("DBOX_ROTATE_MIN_SIZE");
	if (value != NULL)
		mbox->rotate_min_size = (uoff_t)strtoul(value, NULL, 10) * 1024;
	else
		mbox->rotate_min_size = DBOX_DEFAULT_ROTATE_MIN_SIZE;
	value = getenv("DBOX_ROTATE_DAYS");
	if (value != NULL)
		mbox->rotate_days = (unsigned int)strtoul(value, NULL, 10);
	else
		mbox->rotate_days = DBOX_DEFAULT_ROTATE_DAYS;

	mbox->storage = storage;
	mbox->path = p_strdup(pool, path);
	mbox->dbox_file_ext_idx =
		mail_index_ext_register(index, "dbox-seq", 0,
					sizeof(uint32_t), sizeof(uint32_t));
	mbox->dbox_offset_ext_idx =
		mail_index_ext_register(index, "dbox-off", 0,
					sizeof(uint64_t), sizeof(uint64_t));

	mbox->uidlist = dbox_uidlist_init(mbox);
	return &mbox->ibox.box;
}

static struct mailbox *
dbox_mailbox_open(struct mail_storage *_storage, const char *name,
		  struct istream *input, enum mailbox_open_flags flags)
{
	struct dbox_storage *storage = (struct dbox_storage *)_storage;
	struct index_storage *istorage = INDEX_STORAGE(storage);
	const char *path;
	struct stat st;

	mail_storage_clear_error(_storage);

	if (input != NULL) {
		mail_storage_set_critical(_storage,
			"dbox doesn't support streamed mailboxes");
		return NULL;
	}

	if (strcmp(name, "INBOX") == 0)
		return dbox_open(storage, "INBOX", flags);

	if (!dbox_is_valid_existing_name(_storage, name)) {
		mail_storage_set_error(_storage, "Invalid mailbox name");
		return NULL;
	}

	path = dbox_get_path(istorage, name);
	if (stat(path, &st) == 0) {
		return dbox_open(storage, name, flags);
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

static int dbox_mailbox_create(struct mail_storage *_storage,
			       const char *name,
			       bool directory __attr_unused__)
{
	struct dbox_storage *storage = (struct dbox_storage *)_storage;
	struct index_storage *istorage = INDEX_STORAGE(storage);
	const char *path, *mail_path;
	struct stat st;

	mail_storage_clear_error(_storage);

	if (!dbox_is_valid_create_name(_storage, name)) {
		mail_storage_set_error(_storage, "Invalid mailbox name");
		return -1;
	}

	path = dbox_get_path(istorage, name);
	mail_path = t_strconcat(path, "/", DBOX_MAILDIR_NAME, NULL);

	if (stat(mail_path, &st) == 0) {
		mail_storage_set_error(_storage, "Mailbox already exists");
		return -1;
	}

	return create_dbox(istorage, path);
}

static int dbox_mailbox_delete(struct mail_storage *_storage,
			       const char *name)
{
	struct dbox_storage *storage = (struct dbox_storage *)_storage;
	struct index_storage *istorage = INDEX_STORAGE(storage);
	const char *path, *mail_path;
	struct stat st;

	mail_storage_clear_error(_storage);

	if (strcmp(name, "INBOX") == 0) {
		mail_storage_set_error(_storage, "INBOX can't be deleted.");
		return -1;
	}

	if (!dbox_is_valid_existing_name(_storage, name)) {
		mail_storage_set_error(_storage, "Invalid mailbox name");
		return -1;
	}

	path = dbox_get_path(istorage, name);
	mail_path = t_strconcat(path, "/", DBOX_MAILDIR_NAME, NULL);

	if (stat(mail_path, &st) < 0 && ENOTFOUND(errno)) {
		if (stat(path, &st) < 0) {
			mail_storage_set_error(_storage,
				MAIL_STORAGE_ERR_MAILBOX_NOT_FOUND, name);
			return -1;
		}

		/* exists as a \NoSelect mailbox */
		if (rmdir(path) == 0)
			return 0;

		if (errno == ENOTEMPTY) {
			mail_storage_set_error(_storage,
				"Mailbox has only submailboxes: %s", name);
		} else {
			mail_storage_set_critical(_storage,
				"rmdir() failed for %s: %m", path);
		}

		return -1;
	}

	if (unlink_directory(mail_path, TRUE) < 0) {
		if (!dbox_handle_errors(istorage)) {
			mail_storage_set_critical(_storage,
				"unlink_directory() failed for %s: %m",
				mail_path);
		}
		return -1;
	}
	/* try also removing the root directory. it can fail if the deleted
	   mailbox had submailboxes. do it as long as we can. */
	while (rmdir(path) == 0) {
		const char *p = strrchr(name, '/');

		if (p == NULL)
			break;

		name = t_strdup_until(name, p);
		path = dbox_get_path(istorage, name);
	}
	return 0;
}

static int dbox_mailbox_rename(struct mail_storage *_storage,
			       const char *oldname, const char *newname)
{
	struct index_storage *storage = (struct index_storage *)_storage;
	const char *oldpath, *newpath, *p;
	struct stat st;

	mail_storage_clear_error(_storage);

	if (!dbox_is_valid_existing_name(_storage, oldname) ||
	    !dbox_is_valid_create_name(_storage, newname)) {
		mail_storage_set_error(_storage, "Invalid mailbox name");
		return -1;
	}

	oldpath = dbox_get_path(storage, oldname);
	newpath = dbox_get_path(storage, newname);

	/* create the hierarchy */
	p = strrchr(newpath, '/');
	if (p != NULL) {
		p = t_strdup_until(newpath, p);
		if (mkdir_parents(p, CREATE_MODE) < 0) {
			if (dbox_handle_errors(storage))
				return -1;

			mail_storage_set_critical(_storage,
				"mkdir_parents(%s) failed: %m", p);
			return -1;
		}
	}

	/* first check that the destination mailbox doesn't exist.
	   this is racy, but we need to be atomic and there's hardly any
	   possibility that someone actually tries to rename two mailboxes
	   to same new one */
	if (lstat(newpath, &st) == 0) {
		mail_storage_set_error(_storage,
				       "Target mailbox already exists");
		return -1;
	} else if (errno == ENOTDIR) {
		mail_storage_set_error(_storage,
			"Target mailbox doesn't allow inferior mailboxes");
		return -1;
	} else if (errno != ENOENT && errno != EACCES) {
		mail_storage_set_critical(_storage, "lstat(%s) failed: %m",
					  newpath);
		return -1;
	}

	/* NOTE: renaming INBOX works just fine with us, it's simply recreated
	   the next time it's needed. */
	if (rename(oldpath, newpath) < 0) {
		if (ENOTFOUND(errno)) {
			mail_storage_set_error(_storage,
				MAIL_STORAGE_ERR_MAILBOX_NOT_FOUND, oldname);
		} else if (!dbox_handle_errors(storage)) {
			mail_storage_set_critical(_storage,
				"rename(%s, %s) failed: %m", oldpath, newpath);
		}
		return -1;
	}

	return 0;
}

static int dbox_set_subscribed(struct mail_storage *_storage,
			       const char *name, bool set)
{
	struct dbox_storage *storage = (struct dbox_storage *)_storage;
	const char *path;

	path = t_strconcat(INDEX_STORAGE(storage)->dir,
			   "/"DBOX_SUBSCRIPTION_FILE_NAME, NULL);

	return subsfile_set_subscribed(_storage, path,
				       INDEX_STORAGE(storage)->temp_prefix,
				       name, set);
}

static int dbox_get_mailbox_name_status(struct mail_storage *_storage,
					const char *name,
					enum mailbox_name_status *status)
{
	struct index_storage *storage = (struct index_storage *)_storage;
	struct stat st;
	const char *path, *mail_path;

	mail_storage_clear_error(_storage);

	if (!dbox_is_valid_existing_name(_storage, name)) {
		*status = MAILBOX_NAME_INVALID;
		return 0;
	}

	path = dbox_get_path(storage, name);
	mail_path = t_strconcat(path, "/", DBOX_MAILDIR_NAME, NULL);

	if (strcmp(name, "INBOX") == 0 || stat(mail_path, &st) == 0) {
		*status = MAILBOX_NAME_EXISTS;
		return 0;
	}

	if (!dbox_is_valid_create_name(_storage, name)) {
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

static int dbox_storage_close(struct mailbox *box)
{
	struct dbox_mailbox *mbox = (struct dbox_mailbox *)box;

	dbox_uidlist_deinit(mbox->uidlist);
	if (mbox->file != NULL)
		dbox_file_close(mbox->file);
        index_storage_mailbox_free(box);
	return 0;
}

static void
dbox_notify_changes(struct mailbox *box, unsigned int min_interval,
		    mailbox_notify_callback_t *callback, void *context)
{
	struct dbox_mailbox *mbox = (struct dbox_mailbox *)box;

	mbox->ibox.min_notify_interval = min_interval;
	mbox->ibox.notify_callback = callback;
	mbox->ibox.notify_context = context;

	if (callback == NULL) {
		index_mailbox_check_remove_all(&mbox->ibox);
		return;
	}

	index_mailbox_check_add(&mbox->ibox,
		t_strconcat(mbox->path, "/Mails", NULL));
}

struct mail_storage dbox_storage = {
	MEMBER(name) "dbox",
	MEMBER(hierarchy_sep) '/',

	{
		dbox_create,
		dbox_free,
		dbox_autodetect,
		index_storage_set_callbacks,
		dbox_get_mailbox_path,
		dbox_get_mailbox_control_dir,
		dbox_mailbox_open,
		dbox_mailbox_create,
		dbox_mailbox_delete,
		dbox_mailbox_rename,
		dbox_mailbox_list_init,
		dbox_mailbox_list_next,
		dbox_mailbox_list_deinit,
		dbox_set_subscribed,
		dbox_get_mailbox_name_status,
		index_storage_get_last_error
	}
};

struct mailbox dbox_mailbox = {
	MEMBER(name) NULL, 
	MEMBER(storage) NULL, 

	{
		index_storage_is_readonly,
		index_storage_allow_new_keywords,
		dbox_storage_close,
		index_storage_get_status,
		dbox_storage_sync_init,
		index_mailbox_sync_next,
		index_mailbox_sync_deinit,
		dbox_notify_changes,
		dbox_transaction_begin,
		dbox_transaction_commit,
		dbox_transaction_rollback,
		index_keywords_create,
		index_keywords_free,
		index_storage_get_uids,
		index_mail_alloc,
		index_header_lookup_init,
		index_header_lookup_deinit,
		index_storage_search_get_sorting,
		index_storage_search_init,
		index_storage_search_deinit,
		index_storage_search_next,
		index_storage_search_next_update_seq,
		dbox_save_init,
		dbox_save_continue,
		dbox_save_finish,
		dbox_save_cancel,
		mail_storage_copy,
		index_storage_is_inconsistent
	}
};
