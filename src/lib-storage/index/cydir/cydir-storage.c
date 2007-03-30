/* Copyright (C) 2007 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "str.h"
#include "mkdir-parents.h"
#include "unlink-directory.h"
#include "index-mail.h"
#include "mail-copy.h"
#include "cydir-sync.h"
#include "cydir-storage.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#define CREATE_MODE 0770 /* umask() should limit it more */

#define CYDIR_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, cydir_mailbox_list_module)

extern struct mail_storage cydir_storage;
extern struct mailbox cydir_mailbox;

static MODULE_CONTEXT_DEFINE_INIT(cydir_mailbox_list_module,
				  &mailbox_list_module_register);

static int
cydir_list_delete_mailbox(struct mailbox_list *list, const char *name);
static int cydir_list_iter_is_mailbox(struct mailbox_list_iterate_context *ctx,
				      const char *dir, const char *fname,
				      enum mailbox_list_file_type type,
				      enum mailbox_info_flags *flags);

static int
cydir_get_list_settings(struct mailbox_list_settings *list_set,
			const char *data, enum mail_storage_flags flags)
{
	bool debug = (flags & MAIL_STORAGE_FLAG_DEBUG) != 0;
	const char *p;
	size_t len;

	memset(list_set, 0, sizeof(*list_set));
	list_set->subscription_fname = CYDIR_SUBSCRIPTION_FILE_NAME;
	list_set->maildir_name = "";

	if (data == NULL || *data == '\0') {
		/* we won't do any guessing for this format. */
		if (debug)
			i_info("cydir: mailbox location not given");
		return -1;
	}

	/* <root dir> [:INDEX=<dir>] */
	if (debug)
		i_info("cydir: data=%s", data);
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

static struct mail_storage *cydir_alloc(void)
{
	struct cydir_storage *storage;
	pool_t pool;

	pool = pool_alloconly_create("cydir storage", 512+256);
	storage = p_new(pool, struct cydir_storage, 1);
	storage->storage = cydir_storage;
	storage->storage.pool = pool;

	return &storage->storage;
}

static int
cydir_create(struct mail_storage *_storage, const char *data, const char *user,
	     enum mail_storage_flags flags, enum file_lock_method lock_method)
{
	struct cydir_storage *storage = (struct cydir_storage *)_storage;
	struct mailbox_list_settings list_set;
	struct mailbox_list *list;
	const char *error;
	struct stat st;

	if (cydir_get_list_settings(&list_set, data, flags) < 0)
		return -1;
	list_set.mail_storage_flags = &flags;
	list_set.lock_method = &lock_method;

	if ((flags & MAIL_STORAGE_FLAG_NO_AUTOCREATE) != 0) {
		if (stat(list_set.root_dir, &st) < 0) {
			if (errno != ENOENT) {
				i_error("stat(%s) failed: %m",
					list_set.root_dir);
			}
			return -1;
		}
	}

	if (mkdir_parents(list_set.root_dir, CREATE_MODE) < 0 &&
	    errno != EEXIST) {
		i_error("mkdir_parents(%s) failed: %m", list_set.root_dir);
		return -1;
	}

	if (mailbox_list_init("fs", &list_set,
			      mail_storage_get_list_flags(flags),
			      &list, &error) < 0) {
		i_error("cydir fs: %s", error);
		return -1;
	}
	storage->list_module_ctx.super = list->v;
	list->v.iter_is_mailbox = cydir_list_iter_is_mailbox;
	list->v.delete_mailbox = cydir_list_delete_mailbox;

	MODULE_CONTEXT_SET_FULL(list, cydir_mailbox_list_module,
				storage, &storage->list_module_ctx);

	_storage->user = p_strdup(_storage->pool, user);
	index_storage_init(_storage, list, flags, lock_method);
	return 0;
}

static void cydir_free(struct mail_storage *storage)
{
	index_storage_deinit(storage);
	pool_unref(storage->pool);
}

static bool cydir_autodetect(const char *data __attr_unused__,
			     enum mail_storage_flags flags __attr_unused__)
{
	return FALSE;
}

static int create_cydir(struct mail_storage *storage, const char *path)
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

static bool cydir_is_recent(struct index_mailbox *ibox __attr_unused__,
			    uint32_t uid __attr_unused__)
{
	return FALSE;
}

static struct mailbox *
cydir_open(struct cydir_storage *storage, const char *name,
	   enum mailbox_open_flags flags)
{
	struct mail_storage *_storage = &storage->storage;
	struct cydir_mailbox *mbox;
	struct mail_index *index;
	const char *path, *index_dir;
	pool_t pool;

	path = mailbox_list_get_path(_storage->list, name,
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);
	index_dir = mailbox_list_get_path(_storage->list, name,
					  MAILBOX_LIST_PATH_TYPE_INDEX);

	if (create_cydir(_storage, path) < 0)
		return NULL;
	if (create_index_dir(_storage, name) < 0)
		return NULL;

	index = index_storage_alloc(index_dir, path, CYDIR_INDEX_PREFIX);

	pool = pool_alloconly_create("cydir mailbox", 1024+512);
	mbox = p_new(pool, struct cydir_mailbox, 1);
	mbox->ibox.box = cydir_mailbox;
	mbox->ibox.box.pool = pool;
	mbox->ibox.storage = &storage->storage;
	mbox->ibox.mail_vfuncs = &cydir_mail_vfuncs;
	mbox->ibox.is_recent = cydir_is_recent;
	mbox->ibox.index = index;

	mbox->storage = storage;
	mbox->path = p_strdup(pool, path);

	index_storage_mailbox_init(&mbox->ibox, name, flags, FALSE);
	return &mbox->ibox.box;
}

static struct mailbox *
cydir_mailbox_open(struct mail_storage *_storage, const char *name,
		   struct istream *input, enum mailbox_open_flags flags)
{
	struct cydir_storage *storage = (struct cydir_storage *)_storage;
	const char *path;
	struct stat st;

	mail_storage_clear_error(_storage);

	if (input != NULL) {
		mail_storage_set_critical(_storage,
			"cydir doesn't support streamed mailboxes");
		return NULL;
	}

	if (strcmp(name, "INBOX") == 0)
		return cydir_open(storage, "INBOX", flags);

	if (!mailbox_list_is_valid_existing_name(_storage->list, name)) {
		mail_storage_set_error(_storage, "Invalid mailbox name");
		return NULL;
	}

	path = mailbox_list_get_path(_storage->list, name,
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);
	if (stat(path, &st) == 0) {
		return cydir_open(storage, name, flags);
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

static int cydir_mailbox_create(struct mail_storage *_storage,
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

	return create_cydir(_storage, path);
}

static int
cydir_delete_nonrecursive(struct mailbox_list *list, const char *path,
			  const char *name)
{
	DIR *dir;
	struct dirent *d;
	string_t *full_path;
	unsigned int dir_len;
	bool unlinked_something = FALSE;

	dir = opendir(path);
	if (dir == NULL) {
		if (errno == ENOENT) {
			mailbox_list_set_error(list, t_strdup_printf(
				MAILBOX_LIST_ERR_MAILBOX_NOT_FOUND, name));
		} else {
			mailbox_list_set_critical(list,
				"opendir(%s) failed: %m", path);
		}
		return -1;
	}

	full_path = t_str_new(256);
	str_append(full_path, path);
	str_append_c(full_path, '/');
	dir_len = str_len(full_path);

	errno = 0;
	while ((d = readdir(dir)) != NULL) {
		if (d->d_name[0] == '.') {
			/* skip . and .. */
			if (d->d_name[1] == '\0')
				continue;
			if (d->d_name[1] == '.' && d->d_name[2] == '\0')
				continue;
		}

		str_truncate(full_path, dir_len);
		str_append(full_path, d->d_name);

		/* trying to unlink() a directory gives either EPERM or EISDIR
		   (non-POSIX). it doesn't really work anywhere in practise,
		   so don't bother stat()ing the file first */
		if (unlink(str_c(full_path)) == 0)
			unlinked_something = TRUE;
		else if (errno != ENOENT && errno != EISDIR && errno != EPERM) {
			mailbox_list_set_critical(list,
				"unlink_directory(%s) failed: %m",
				str_c(full_path));
		}
	}

	if (closedir(dir) < 0) {
		mailbox_list_set_critical(list, "closedir(%s) failed: %m",
					  path);
	}

	if (rmdir(path) == 0)
		unlinked_something = TRUE;
	else if (errno != ENOENT && errno != ENOTEMPTY) {
		mailbox_list_set_critical(list, "rmdir(%s) failed: %m", path);
		return -1;
	}

	if (!unlinked_something) {
		mailbox_list_set_error(list, t_strdup_printf(
			"Directory %s isn't empty, can't delete it.", name));
		return -1;
	}
	return 0;
}

static int
cydir_list_delete_mailbox(struct mailbox_list *list, const char *name)
{
	struct cydir_storage *storage = CYDIR_LIST_CONTEXT(list);
	struct stat st;
	const char *src;

	/* Make sure the indexes are closed before trying to delete the
	   directory that contains them. It can still fail with some NFS
	   implementations if indexes are opened by another session, but
	   that can't really be helped. */
	index_storage_destroy_unrefed();

	/* delete the index and control directories */
	if (storage->list_module_ctx.super.delete_mailbox(list, name) < 0)
		return -1;

	/* check if the mailbox actually exists */
	src = mailbox_list_get_path(list, name, MAILBOX_LIST_PATH_TYPE_MAILBOX);
	if (stat(src, &st) != 0 && errno == ENOENT) {
		mailbox_list_set_error(list, t_strdup_printf(
			MAILBOX_LIST_ERR_MAILBOX_NOT_FOUND, name));
		return -1;
	}

	return cydir_delete_nonrecursive(list, src, name);
}

static int cydir_storage_close(struct mailbox *box)
{
        index_storage_mailbox_free(box);
	return 0;
}

static void
cydir_notify_changes(struct mailbox *box, unsigned int min_interval,
		     mailbox_notify_callback_t *callback, void *context)
{
	struct cydir_mailbox *mbox = (struct cydir_mailbox *)box;

	mbox->ibox.min_notify_interval = min_interval;
	mbox->ibox.notify_callback = callback;
	mbox->ibox.notify_context = context;

	if (callback == NULL) {
		index_mailbox_check_remove_all(&mbox->ibox);
		return;
	}

	index_mailbox_check_add(&mbox->ibox, mbox->path);
}

static int cydir_list_iter_is_mailbox(struct mailbox_list_iterate_context *ctx,
				      const char *dir, const char *fname,
				      enum mailbox_list_file_type type,
				      enum mailbox_info_flags *flags)
{
	const char *mail_path;
	struct stat st;
	int ret = 1;

	if (strchr(fname, '.') != NULL) {
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
	mail_path = t_strconcat(dir, "/", fname, NULL);

	if (stat(mail_path, &st) == 0) {
		if (!S_ISDIR(st.st_mode)) {
			/* non-directory */
			*flags |= MAILBOX_NOSELECT | MAILBOX_NOINFERIORS;
			ret = 0;
		}
	} else {
		/* non-selectable, but may contain subdirs */
		*flags |= MAILBOX_NOSELECT;
	}
	t_pop();

	return ret;
}

static void cydir_class_init(void)
{
	cydir_transaction_class_init();
}

static void cydir_class_deinit(void)
{
	cydir_transaction_class_deinit();
}

struct mail_storage cydir_storage = {
	MEMBER(name) CYDIR_STORAGE_NAME,
	MEMBER(mailbox_is_file) FALSE,

	{
		cydir_class_init,
		cydir_class_deinit,
		cydir_alloc,
		cydir_create,
		cydir_free,
		cydir_autodetect,
		index_storage_set_callbacks,
		cydir_mailbox_open,
		cydir_mailbox_create,
		index_storage_get_last_error
	}
};

struct mailbox cydir_mailbox = {
	MEMBER(name) NULL, 
	MEMBER(storage) NULL, 

	{
		index_storage_is_readonly,
		index_storage_allow_new_keywords,
		cydir_storage_close,
		index_storage_get_status,
		cydir_storage_sync_init,
		index_mailbox_sync_next,
		index_mailbox_sync_deinit,
		cydir_notify_changes,
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
		cydir_save_init,
		cydir_save_continue,
		cydir_save_finish,
		cydir_save_cancel,
		mail_storage_copy,
		index_storage_is_inconsistent
	}
};
