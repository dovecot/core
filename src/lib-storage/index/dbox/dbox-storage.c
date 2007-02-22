/* Copyright (C) 2005-2007 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "mkdir-parents.h"
#include "unlink-directory.h"
#include "index-mail.h"
#include "mail-copy.h"
#include "dbox-uidlist.h"
#include "dbox-sync.h"
#include "dbox-file.h"
#include "dbox-storage.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#define CREATE_MODE 0770 /* umask() should limit it more */

/* How often to touch the uidlist lock file when using KEEP_LOCKED flag */
#define DBOX_LOCK_TOUCH_MSECS (10*1000)

const struct dotlock_settings default_uidlist_dotlock_set = {
	MEMBER(temp_prefix) NULL,
	MEMBER(lock_suffix) NULL,

	MEMBER(timeout) 120,
	MEMBER(stale_timeout) 60,

	MEMBER(callback) NULL,
	MEMBER(context) NULL,

	MEMBER(use_excl_lock) FALSE
};

const struct dotlock_settings default_file_dotlock_set = {
	MEMBER(temp_prefix) NULL,
	MEMBER(lock_suffix) NULL,

	MEMBER(timeout) 120,
	MEMBER(stale_timeout) 60,

	MEMBER(callback) NULL,
	MEMBER(context) NULL,

	MEMBER(use_excl_lock) FALSE
};

static const struct dotlock_settings default_new_file_dotlock_set = {
	MEMBER(temp_prefix) NULL,
	MEMBER(lock_suffix) NULL,

	MEMBER(timeout) 60,
	MEMBER(stale_timeout) 30,

	MEMBER(callback) NULL,
	MEMBER(context) NULL,

	MEMBER(use_excl_lock) FALSE
};

extern struct mail_storage dbox_storage;
extern struct mailbox dbox_mailbox;

static bool dbox_handle_errors(struct mail_storage *storage)
{
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

static int
dbox_get_list_settings(struct mailbox_list_settings *list_set,
		       const char *data, enum mail_storage_flags flags)
{
	bool debug = (flags & MAIL_STORAGE_FLAG_DEBUG) != 0;
	const char *p;
	size_t len;

	memset(list_set, 0, sizeof(*list_set));
	list_set->subscription_fname = DBOX_SUBSCRIPTION_FILE_NAME;
	list_set->maildir_name = "";

	if (data == NULL || *data == '\0') {
		/* we won't do any guessing for this format. */
		if (debug)
			i_info("dbox: mailbox location not given");
		return -1;
	}

	/* <root dir> [:INDEX=<dir>] */
	if (debug)
		i_info("dbox: data=%s", data);
	p = strchr(data, ':');
	if (p == NULL)
		list_set->root_dir = data;
	else {
		list_set->root_dir = t_strdup_until(data, p);

		do {
			p++;
			if (strncmp(p, "INDEX=", 6) == 0)
				list_set->index_dir = t_strcut(p+6, ':');
			p = strchr(p, ':');
		} while (p != NULL);
	}

	/* strip trailing '/' */
	len = strlen(list_set->root_dir);
	if (list_set->root_dir[len-1] == '/')
		list_set->root_dir = t_strndup(list_set->root_dir, len-1);

	if (list_set->index_dir != NULL &&
	    strcmp(list_set->index_dir, "MEMORY") == 0)
		list_set->index_dir = "";
	return 0;
}

static struct mail_storage *
dbox_create(const char *data, const char *user,
	    enum mail_storage_flags flags,
	    enum file_lock_method lock_method)
{
	struct dbox_storage *storage;
	struct index_storage *istorage;
	struct mailbox_list_settings list_set;
	struct mailbox_list *list;
	const char *error;
	struct stat st;
	pool_t pool;

	if (dbox_get_list_settings(&list_set, data, flags) < 0)
		return NULL;
	list_set.mail_storage_flags = &flags;
	list_set.lock_method = &lock_method;

	if ((flags & MAIL_STORAGE_FLAG_NO_AUTOCREATE) != 0) {
		if (stat(list_set.root_dir, &st) < 0) {
			if (errno != ENOENT) {
				i_error("stat(%s) failed: %m",
					list_set.root_dir);
			}
			return NULL;
		}
	}

	if (mkdir_parents(list_set.root_dir, CREATE_MODE) < 0 &&
	    errno != EEXIST) {
		i_error("mkdir_parents(%s) failed: %m", list_set.root_dir);
		return NULL;
	}

	pool = pool_alloconly_create("storage", 512+256);
	storage = p_new(pool, struct dbox_storage, 1);

	if (mailbox_list_init("fs", &list_set,
			      mail_storage_get_list_flags(flags),
			      mailbox_storage_list_is_mailbox, storage,
			      &list, &error) < 0) {
		i_error("dbox fs: %s", error);
		pool_unref(pool);
		return NULL;
	}

	storage->uidlist_dotlock_set = default_uidlist_dotlock_set;
	storage->file_dotlock_set = default_file_dotlock_set;
	storage->new_file_dotlock_set = default_new_file_dotlock_set;
	if ((flags & MAIL_STORAGE_FLAG_DOTLOCK_USE_EXCL) != 0) {
		storage->uidlist_dotlock_set.use_excl_lock = TRUE;
		storage->file_dotlock_set.use_excl_lock = TRUE;
		storage->new_file_dotlock_set.use_excl_lock = TRUE;
	}

	istorage = INDEX_STORAGE(storage);
	istorage->storage = dbox_storage;
	istorage->storage.pool = pool;

	istorage->user = p_strdup(pool, user);
	index_storage_init(istorage, list, flags, lock_method);

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

	path = t_strconcat(data, "/inbox/"DBOX_MAILDIR_NAME, NULL);
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

static int create_dbox(struct mail_storage *storage, const char *path)
{
	if (mkdir_parents(path, CREATE_MODE) < 0 && errno != EEXIST) {
		if (dbox_handle_errors(storage))
			return -1;

		mail_storage_set_critical(storage, "mkdir(%s) failed: %m",
					  path);
		return -1;
	}
	return 0;
}

static int create_index_dir(struct mail_storage *storage, const char *name)
{
	const char *root_dir, *index_dir;

	root_dir = mailbox_list_get_path(storage->list, name,
					 MAILBOX_LIST_PATH_TYPE_MAILBOX);
	index_dir = mailbox_list_get_path(storage->list, name,
					  MAILBOX_LIST_PATH_TYPE_INDEX);
	if (strcmp(index_dir, root_dir) == 0)
		return 0;

	if (mkdir_parents(index_dir, CREATE_MODE) < 0 && errno != EEXIST) {
		mail_storage_set_critical(storage, "mkdir(%s) failed: %m",
					  index_dir);
		return -1;
	}

	return 0;
}

static bool dbox_is_recent(struct index_mailbox *ibox __attr_unused__,
			   uint32_t uid __attr_unused__)
{
	return FALSE;
}

static void dbox_lock_touch_timeout(void *context)
{
	struct dbox_mailbox *mbox = context;

	(void)dbox_uidlist_lock_touch(mbox->uidlist);
}

static struct mailbox *
dbox_open(struct dbox_storage *storage, const char *name,
	  enum mailbox_open_flags flags)
{
	struct index_storage *istorage = INDEX_STORAGE(storage);
	struct mail_storage *_storage = STORAGE(storage);
	struct dbox_mailbox *mbox;
	struct mail_index *index;
	const char *path, *index_dir, *value;
	pool_t pool;

	path = mailbox_list_get_path(_storage->list, name,
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);
	index_dir = mailbox_list_get_path(_storage->list, name,
					  MAILBOX_LIST_PATH_TYPE_INDEX);

	if (create_dbox(_storage, path) < 0)
		return NULL;
	if (create_index_dir(_storage, name) < 0)
		return NULL;

	index = index_storage_alloc(index_dir, path, DBOX_INDEX_PREFIX);

	pool = pool_alloconly_create("dbox mailbox", 1024+512);
	mbox = p_new(pool, struct dbox_mailbox, 1);
	mbox->ibox.box = dbox_mailbox;
	mbox->ibox.box.pool = pool;
	mbox->ibox.storage = istorage;
	mbox->ibox.mail_vfuncs = &dbox_mail_vfuncs;
	mbox->ibox.is_recent = dbox_is_recent;

	index_storage_mailbox_init(&mbox->ibox, index, name, flags, FALSE);

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
	if (mbox->ibox.keep_locked) {
		if (dbox_uidlist_lock(mbox->uidlist) < 0) {
			struct mailbox *box = &mbox->ibox.box;

			mailbox_close(&box);
			return NULL;
		}
		mbox->keep_lock_to = timeout_add(DBOX_LOCK_TOUCH_MSECS,
						 dbox_lock_touch_timeout,
						 mbox);
	}
	return &mbox->ibox.box;
}

static struct mailbox *
dbox_mailbox_open(struct mail_storage *_storage, const char *name,
		  struct istream *input, enum mailbox_open_flags flags)
{
	struct dbox_storage *storage = (struct dbox_storage *)_storage;
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

	if (!mailbox_list_is_valid_existing_name(_storage->list, name)) {
		mail_storage_set_error(_storage, "Invalid mailbox name");
		return NULL;
	}

	path = mailbox_list_get_path(_storage->list, name,
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);
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
	const char *path;
	struct stat st;

	mail_storage_clear_error(_storage);

	if (!mailbox_list_is_valid_create_name(_storage->list, name)) {
		mail_storage_set_error(_storage, "Invalid mailbox name");
		return -1;
	}

	path = mailbox_list_get_path(_storage->list, name,
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);
	if (stat(path, &st) == 0) {
		mail_storage_set_error(_storage, "Mailbox already exists");
		return -1;
	}

	return create_dbox(_storage, path);
}

static int dbox_mailbox_delete(struct mail_storage *_storage,
			       const char *name)
{
	const char *path, *mail_path;
	struct stat st;

	mail_storage_clear_error(_storage);

	if (strcmp(name, "INBOX") == 0) {
		mail_storage_set_error(_storage, "INBOX can't be deleted.");
		return -1;
	}

	if (!mailbox_list_is_valid_existing_name(_storage->list, name)) {
		mail_storage_set_error(_storage, "Invalid mailbox name");
		return -1;
	}

	path = mailbox_list_get_path(_storage->list, name,
				     MAILBOX_LIST_PATH_TYPE_DIR);
	mail_path = mailbox_list_get_path(_storage->list, name,
					  MAILBOX_LIST_PATH_TYPE_MAILBOX);

	if (stat(mail_path, &st) < 0 && ENOTFOUND(errno)) {
		if (stat(path, &st) < 0) {
			/* doesn't exist at all */
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

	/* make sure the indexes are closed before trying to delete the
	   directory that contains them */
	index_storage_destroy_unrefed();

	if (unlink_directory(mail_path, TRUE) < 0) {
		if (!dbox_handle_errors(_storage)) {
			mail_storage_set_critical(_storage,
				"unlink_directory() failed for %s: %m",
				mail_path);
		}
		return -1;
	}
	/* try also removing the root directory. it can fail if the deleted
	   mailbox had submailboxes. do it as long as we can. */
	while (rmdir(path) == 0 || errno == ENOENT) {
		const char *p = strrchr(name, '/');

		if (p == NULL)
			break;

		name = t_strdup_until(name, p);
		path = mailbox_list_get_path(_storage->list, name,
					     MAILBOX_LIST_PATH_TYPE_DIR);
	}
	return 0;
}

static int dbox_mailbox_rename(struct mail_storage *_storage,
			       const char *oldname, const char *newname)
{
	const char *oldpath, *newpath, *p;
	struct stat st;

	mail_storage_clear_error(_storage);

	if (!mailbox_list_is_valid_existing_name(_storage->list, oldname) ||
	    !mailbox_list_is_valid_create_name(_storage->list, newname)) {
		mail_storage_set_error(_storage, "Invalid mailbox name");
		return -1;
	}

	oldpath = mailbox_list_get_path(_storage->list, oldname,
					MAILBOX_LIST_PATH_TYPE_DIR);
	newpath = mailbox_list_get_path(_storage->list, newname,
					MAILBOX_LIST_PATH_TYPE_DIR);

	/* create the hierarchy */
	p = strrchr(newpath, '/');
	if (p != NULL) {
		p = t_strdup_until(newpath, p);
		if (mkdir_parents(p, CREATE_MODE) < 0) {
			if (dbox_handle_errors(_storage))
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
		} else if (!dbox_handle_errors(_storage)) {
			mail_storage_set_critical(_storage,
				"rename(%s, %s) failed: %m", oldpath, newpath);
		}
		return -1;
	}

	return 0;
}

static int dbox_storage_close(struct mailbox *box)
{
	struct dbox_mailbox *mbox = (struct dbox_mailbox *)box;

	if (mbox->ibox.keep_locked)
		dbox_uidlist_unlock(mbox->uidlist);
	if (mbox->keep_lock_to != NULL)
		timeout_remove(&mbox->keep_lock_to);

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
		t_strconcat(mbox->path, "/"DBOX_MAILDIR_NAME, NULL));
}

static int dbox_is_mailbox(struct mail_storage *storage,
			   const char *dir, const char *fname,
			   enum mailbox_list_iter_flags iter_flags,
			   enum mailbox_info_flags *flags,
			   enum mailbox_list_file_type type)
{
	const char *path, *mail_path;
	size_t len;
	struct stat st;
	int ret = 1;

	if (strcmp(fname, DBOX_MAILDIR_NAME) == 0) {
		*flags = MAILBOX_NOSELECT;
		return 0;
	}

	/* skip all .lock files */
	len = strlen(fname);
	if (len > 5 && strcmp(fname+len-5, ".lock") == 0) {
		*flags = MAILBOX_NOSELECT | MAILBOX_NOINFERIORS;
		return 0;
	}

	/* try to avoid stat() with these checks */
	if (type != MAILBOX_LIST_FILE_TYPE_DIR &&
	    type != MAILBOX_LIST_FILE_TYPE_SYMLINK &&
	    type != MAILBOX_LIST_FILE_TYPE_UNKNOWN &&
	    (iter_flags & MAILBOX_LIST_ITER_FAST_FLAGS) != 0) {
		/* it's a file */
		*flags |= MAILBOX_NOSELECT | MAILBOX_NOINFERIORS;
		return 0;
	}

	/* need to stat() then */
	t_push();
	path = t_strconcat(dir, "/", fname, NULL);
	mail_path = t_strconcat(path, "/"DBOX_MAILDIR_NAME, NULL);

	if (stat(mail_path, &st) == 0) {
		if (!S_ISDIR(st.st_mode)) {
			/* non-directory */
			*flags |= MAILBOX_NOSELECT | MAILBOX_NOINFERIORS;
			ret = 0;
		}
	} else {
		/* non-selectable, but may contain subdirs */
		*flags |= MAILBOX_NOSELECT;
		if (stat(path, &st) < 0) {
			if (ENOTFOUND(errno)) {
				/* just lost it */
				ret = 0;
			} else if (errno != EACCES && errno != ELOOP) {
				mail_storage_set_critical(storage,
					"stat(%s) failed: %m", path);
				ret = -1;
			}
		}
	}
	t_pop();

	return ret;
}

static void dbox_class_init(void)
{
	dbox_transaction_class_init();
}

static void dbox_class_deinit(void)
{
	dbox_transaction_class_deinit();
}

struct mail_storage dbox_storage = {
	MEMBER(name) DBOX_STORAGE_NAME,
	MEMBER(mailbox_is_file) FALSE,

	{
		dbox_class_init,
		dbox_class_deinit,
		dbox_create,
		dbox_free,
		dbox_autodetect,
		index_storage_set_callbacks,
		dbox_mailbox_open,
		dbox_mailbox_create,
		dbox_mailbox_delete,
		dbox_mailbox_rename,
		dbox_is_mailbox,
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
		index_transaction_begin,
		index_transaction_commit,
		index_transaction_rollback,
		index_keywords_create,
		index_keywords_free,
		index_storage_get_uids,
		index_mail_alloc,
		index_header_lookup_init,
		index_header_lookup_deinit,
		index_storage_search_init,
		index_storage_search_deinit,
		index_storage_search_next_nonblock,
		index_storage_search_next_update_seq,
		dbox_save_init,
		dbox_save_continue,
		dbox_save_finish,
		dbox_save_cancel,
		mail_storage_copy,
		index_storage_is_inconsistent
	}
};
