/* Copyright (C) 2005-2007 Timo Sirainen */

#include "lib.h"
#include "array.h"
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

#define DBOX_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, dbox_mailbox_list_module)

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

static MODULE_CONTEXT_DEFINE_INIT(dbox_mailbox_list_module,
				  &mailbox_list_module_register);

static int
dbox_list_delete_mailbox(struct mailbox_list *list, const char *name);
static int dbox_list_iter_is_mailbox(struct mailbox_list_iterate_context *ctx,
				     const char *dir, const char *fname,
				     enum mailbox_list_file_type type,
				     enum mailbox_info_flags *flags);

static bool
dbox_storage_is_valid_existing_name(struct mailbox_list *list, const char *name)
{
	struct dbox_storage *storage = DBOX_LIST_CONTEXT(list);
	const char *p;

	if (!storage->list_module_ctx.super.is_valid_existing_name(list, name))
		return FALSE;

	/* Don't allow the mailbox name to end in dbox-Mails */
	p = strrchr(name, '/');
	if (p != NULL)
		name = p + 1;
	return strcmp(name, DBOX_MAILDIR_NAME) != 0;
}

static bool
dbox_storage_is_valid_create_name(struct mailbox_list *list, const char *name)
{
	struct dbox_storage *storage = DBOX_LIST_CONTEXT(list);
	const char *const *tmp;
	bool ret = TRUE;

	if (!storage->list_module_ctx.super.is_valid_create_name(list, name))
		return FALSE;

	/* Don't allow creating mailboxes under dbox-Mails */
	t_push();
	for (tmp = t_strsplit(name, "/"); *tmp != NULL; tmp++) {
		if (strcmp(*tmp, DBOX_MAILDIR_NAME) == 0) {
			ret = FALSE;
			break;
		}
	}
	t_pop();
	return ret;
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
	list_set->maildir_name = DBOX_MAILDIR_NAME;

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

static struct mail_storage *dbox_alloc(void)
{
	struct dbox_storage *storage;
	pool_t pool;

	pool = pool_alloconly_create("dbox storage", 512+256);
	storage = p_new(pool, struct dbox_storage, 1);
	storage->storage = dbox_storage;
	storage->storage.pool = pool;

	return &storage->storage;
}

static int dbox_create(struct mail_storage *_storage, const char *data)
{
	struct dbox_storage *storage = (struct dbox_storage *)_storage;
	struct mailbox_list_settings list_set;
	struct mailbox_list *list;
	const char *error;
	struct stat st;

	if (dbox_get_list_settings(&list_set, data, _storage->flags) < 0)
		return -1;
	list_set.mail_storage_flags = &_storage->flags;
	list_set.lock_method = &_storage->lock_method;

	if ((_storage->flags & MAIL_STORAGE_FLAG_NO_AUTOCREATE) != 0) {
		if (stat(list_set.root_dir, &st) < 0) {
			if (errno != ENOENT) {
				i_error("stat(%s) failed: %m",
					list_set.root_dir);
			}
			return -1;
		}
	} else {
		if (mkdir_parents(list_set.root_dir, CREATE_MODE) < 0 &&
		    errno != EEXIST) {
			i_error("mkdir_parents(%s) failed: %m",
				list_set.root_dir);
			return -1;
		}
	}

	if (mailbox_list_init("fs", &list_set,
			      mail_storage_get_list_flags(_storage->flags),
			      &list, &error) < 0) {
		i_error("dbox fs: %s", error);
		return -1;
	}
	_storage->list = list;
	storage->list_module_ctx.super = list->v;
	list->v.is_valid_existing_name = dbox_storage_is_valid_existing_name;
	list->v.is_valid_create_name = dbox_storage_is_valid_create_name;
	list->v.iter_is_mailbox = dbox_list_iter_is_mailbox;
	list->v.delete_mailbox = dbox_list_delete_mailbox;

	MODULE_CONTEXT_SET_FULL(list, dbox_mailbox_list_module,
				storage, &storage->list_module_ctx);

	storage->uidlist_dotlock_set = default_uidlist_dotlock_set;
	storage->file_dotlock_set = default_file_dotlock_set;
	storage->new_file_dotlock_set = default_new_file_dotlock_set;
	if ((_storage->flags & MAIL_STORAGE_FLAG_DOTLOCK_USE_EXCL) != 0) {
		storage->uidlist_dotlock_set.use_excl_lock = TRUE;
		storage->file_dotlock_set.use_excl_lock = TRUE;
		storage->new_file_dotlock_set.use_excl_lock = TRUE;
	}
	return 0;
}

static bool dbox_autodetect(const char *data, enum mail_storage_flags flags)
{
	bool debug = (flags & MAIL_STORAGE_FLAG_DEBUG) != 0;
	struct stat st;
	const char *path;

	data = t_strcut(data, ':');

	path = t_strconcat(data, "/INBOX/"DBOX_MAILDIR_NAME, NULL);
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
	const char *error;

	if (mkdir_parents(path, CREATE_MODE) < 0 && errno != EEXIST) {
		if (mail_storage_errno2str(&error)) {
			mail_storage_set_error(storage, "%s", error);
			return -1;
		}

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

static void dbox_lock_touch_timeout(struct dbox_mailbox *mbox)
{
	(void)dbox_uidlist_lock_touch(mbox->uidlist);
}

static struct mailbox *
dbox_open(struct dbox_storage *storage, const char *name,
	  enum mailbox_open_flags flags)
{
	struct mail_storage *_storage = &storage->storage;
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
	mbox->ibox.storage = &storage->storage;
	mbox->ibox.mail_vfuncs = &dbox_mail_vfuncs;
	mbox->ibox.index = index;

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
	if ((flags & MAILBOX_OPEN_KEEP_LOCKED) != 0) {
		if (dbox_uidlist_lock(mbox->uidlist) < 0) {
			struct mailbox *box = &mbox->ibox.box;

			mailbox_close(&box);
			return NULL;
		}
		mbox->keep_lock_to = timeout_add(DBOX_LOCK_TOUCH_MSECS,
						 dbox_lock_touch_timeout,
						 mbox);
	}

	index_storage_mailbox_init(&mbox->ibox, name, flags, FALSE);
	return &mbox->ibox.box;
}

static struct mailbox *
dbox_mailbox_open(struct mail_storage *_storage, const char *name,
		  struct istream *input, enum mailbox_open_flags flags)
{
	struct dbox_storage *storage = (struct dbox_storage *)_storage;
	const char *path;
	struct stat st;

	if (input != NULL) {
		mail_storage_set_critical(_storage,
			"dbox doesn't support streamed mailboxes");
		return NULL;
	}

	if (strcmp(name, "INBOX") == 0)
		return dbox_open(storage, "INBOX", flags);

	path = mailbox_list_get_path(_storage->list, name,
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);
	if (stat(path, &st) == 0) {
		return dbox_open(storage, name, flags);
	} else if (errno == ENOENT) {
		mail_storage_set_error(_storage,
			MAILBOX_LIST_ERR_MAILBOX_NOT_FOUND, name);
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

	path = mailbox_list_get_path(_storage->list, name,
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);
	if (stat(path, &st) == 0) {
		mail_storage_set_error(_storage, "Mailbox already exists");
		return -1;
	}

	return create_dbox(_storage, path);
}

static int
dbox_list_delete_mailbox(struct mailbox_list *list, const char *name)
{
	struct dbox_storage *storage = DBOX_LIST_CONTEXT(list);
	struct stat st;
	const char *path, *mail_path, *error;

	/* make sure the indexes are closed before trying to delete the
	   directory that contains them */
	index_storage_destroy_unrefed();

	/* delete the index and control directories */
	if (storage->list_module_ctx.super.delete_mailbox(list, name) < 0)
		return -1;

	path = mailbox_list_get_path(list, name, MAILBOX_LIST_PATH_TYPE_DIR);
	mail_path = mailbox_list_get_path(list, name,
					  MAILBOX_LIST_PATH_TYPE_MAILBOX);

	if (stat(mail_path, &st) < 0 && ENOTFOUND(errno)) {
		if (stat(path, &st) < 0) {
			/* doesn't exist at all */
			mailbox_list_set_error(list, t_strdup_printf(
				MAILBOX_LIST_ERR_MAILBOX_NOT_FOUND, name));
			return -1;
		}

		/* exists as a \NoSelect mailbox */
		if (rmdir(path) == 0)
			return 0;

		if (errno == ENOTEMPTY) {
			mailbox_list_set_error(list, t_strdup_printf(
				"Directory %s isn't empty, can't delete it.",
				name));
		} else {
			mailbox_list_set_critical(list,
				"rmdir() failed for %s: %m", path);
		}

		return -1;
	}


	if (unlink_directory(mail_path, TRUE) < 0) {
		if (mail_storage_errno2str(&error))
			mailbox_list_set_error(list, error);
		else {
			mailbox_list_set_critical(list,
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
		path = mailbox_list_get_path(list, name,
					     MAILBOX_LIST_PATH_TYPE_DIR);
	}
	return 0;
}

static int dbox_storage_close(struct mailbox *box)
{
	struct dbox_mailbox *mbox = (struct dbox_mailbox *)box;

	if (mbox->keep_lock_to != NULL) {
		dbox_uidlist_unlock(mbox->uidlist);
		timeout_remove(&mbox->keep_lock_to);
	}

	dbox_uidlist_deinit(mbox->uidlist);
	if (mbox->file != NULL)
		dbox_file_close(mbox->file);
        return index_storage_mailbox_close(box);
}

static void dbox_notify_changes(struct mailbox *box)
{
	struct dbox_mailbox *mbox = (struct dbox_mailbox *)box;

	if (box->notify_callback == NULL)
		index_mailbox_check_remove_all(&mbox->ibox);
	else
		index_mailbox_check_add(&mbox->ibox, mbox->path);
}

static int dbox_list_iter_is_mailbox(struct mailbox_list_iterate_context *ctx,
				     const char *dir, const char *fname,
				     enum mailbox_list_file_type type,
				     enum mailbox_info_flags *flags)
{
	const char *mail_path;
	struct stat st;
	int ret = 1;

	if (strcmp(fname, DBOX_MAILDIR_NAME) == 0) {
		*flags = MAILBOX_NOSELECT;
		return 0;
	}

	/* try to avoid stat() with these checks */
	if (type != MAILBOX_LIST_FILE_TYPE_DIR &&
	    type != MAILBOX_LIST_FILE_TYPE_SYMLINK &&
	    type != MAILBOX_LIST_FILE_TYPE_UNKNOWN &&
	    (ctx->flags & MAILBOX_LIST_ITER_FAST_FLAGS) != 0) {
		/* it's a file */
		*flags |= MAILBOX_NOSELECT | MAILBOX_NOINFERIORS;
		return 0;
	}

	/* need to stat() then */
	t_push();
	mail_path = t_strconcat(dir, "/", fname, "/"DBOX_MAILDIR_NAME, NULL);

	if (stat(mail_path, &st) == 0) {
		if (!S_ISDIR(st.st_mode)) {
			/* non-directory */
			*flags |= MAILBOX_NOSELECT | MAILBOX_NOINFERIORS;
			ret = 0;
		}
	} else {
		/* non-selectable, but may contain subdirs */
		if (errno != ENOTDIR)
			*flags |= MAILBOX_CHILDREN;
		*flags |= MAILBOX_NOSELECT;
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
		dbox_alloc,
		dbox_create,
		NULL,
		dbox_autodetect,
		dbox_mailbox_open,
		dbox_mailbox_create
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
