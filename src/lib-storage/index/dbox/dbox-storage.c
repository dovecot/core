/* Copyright (c) 2007-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "str.h"
#include "mkdir-parents.h"
#include "unlink-directory.h"
#include "unlink-old-files.h"
#include "index-mail.h"
#include "mail-copy.h"
#include "dbox-sync.h"
#include "dbox-index.h"
#include "dbox-file.h"
#include "dbox-storage.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#define CREATE_MODE 0770 /* umask() should limit it more */

#define DBOX_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, dbox_mailbox_list_module)

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

static int
dbox_get_list_settings(struct mailbox_list_settings *list_set,
		       const char *data, enum mail_storage_flags flags,
		       const char **layout_r, const char **alt_dir_r,
		       const char **error_r)
{
	bool debug = (flags & MAIL_STORAGE_FLAG_DEBUG) != 0;

	*layout_r = "fs";

	memset(list_set, 0, sizeof(*list_set));
	list_set->subscription_fname = DBOX_SUBSCRIPTION_FILE_NAME;
	list_set->maildir_name = DBOX_MAILDIR_NAME;

	if (data == NULL || *data == '\0' || *data == ':') {
		/* we won't do any guessing for this format. */
		if (debug)
			i_info("dbox: mailbox location not given");
		*error_r = "Root mail directory not given";
		return -1;
	}

	if (debug)
		i_info("dbox: data=%s", data);
	return mailbox_list_settings_parse(data, list_set, layout_r, alt_dir_r,
					   error_r);
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

static int dbox_create(struct mail_storage *_storage, const char *data,
		       const char **error_r)
{
	struct dbox_storage *storage = (struct dbox_storage *)_storage;
	struct mailbox_list_settings list_set;
	struct stat st;
	const char *layout, *alt_dir;

	if (dbox_get_list_settings(&list_set, data, _storage->flags,
				   &layout, &alt_dir, error_r) < 0)
		return -1;
	list_set.mail_storage_flags = &_storage->flags;
	list_set.lock_method = &_storage->lock_method;

	if ((_storage->flags & MAIL_STORAGE_FLAG_NO_AUTOCREATE) != 0) {
		if (stat(list_set.root_dir, &st) < 0) {
			if (errno == ENOENT) {
				*error_r = t_strdup_printf(
					"Root mail directory doesn't exist: %s",
					list_set.root_dir);
			} else if (errno == EACCES) {
				*error_r = mail_storage_eacces_msg("stat",
							list_set.root_dir);
			} else {
				*error_r = t_strdup_printf(
							"stat(%s) failed: %m",
							list_set.root_dir);
			}
			return -1;
		}
	} else if (mkdir_parents(list_set.root_dir,
				 CREATE_MODE) == 0 || errno == EEXIST) {
	} else if (errno == EACCES) {
		*error_r = mail_storage_eacces_msg("mkdir", list_set.root_dir);
		return -1;
	} else {
		*error_r = t_strdup_printf("mkdir(%s) failed: %m",
					   list_set.root_dir);
		return -1;
	}

	if (mailbox_list_alloc(layout, &_storage->list, error_r) < 0)
		return -1;
	storage->list_module_ctx.super = _storage->list->v;
	storage->alt_dir = p_strdup(_storage->pool, alt_dir);
	_storage->list->v.iter_is_mailbox = dbox_list_iter_is_mailbox;
	_storage->list->v.delete_mailbox = dbox_list_delete_mailbox;

	MODULE_CONTEXT_SET_FULL(_storage->list, dbox_mailbox_list_module,
				storage, &storage->list_module_ctx);

	/* finish list init after we've overridden vfuncs */
	mailbox_list_init(_storage->list, _storage->ns, &list_set,
			  mail_storage_get_list_flags(_storage->flags));
	return 0;
}

static int create_dbox(struct mail_storage *storage, const char *path)
{
	if (mkdir_parents(path, CREATE_MODE) < 0 && errno != EEXIST) {
		if (!mail_storage_set_error_from_errno(storage)) {
			mail_storage_set_critical(storage,
				"mkdir(%s) failed: %m", path);
		}
		return -1;
	}
	return 0;
}

static const char *
dbox_get_alt_path(struct dbox_storage *storage, const char *path)
{
	unsigned int len;

	if (storage->alt_dir == NULL)
		return NULL;

	len = strlen(storage->alt_dir);
	if (strncmp(path, storage->alt_dir, len) != 0)
		return t_strconcat(storage->alt_dir, path + len, NULL);
	else
		return NULL;
}

static struct mailbox *
dbox_open(struct dbox_storage *storage, const char *name,
	  enum mailbox_open_flags flags)
{
	struct mail_storage *_storage = &storage->storage;
	struct dbox_mailbox *mbox;
	struct mail_index *index;
	const char *path, *value;
	pool_t pool;

	path = mailbox_list_get_path(_storage->list, name,
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);

	index = index_storage_alloc(_storage, name, flags, DBOX_INDEX_PREFIX);
	mail_index_set_fsync_types(index, MAIL_INDEX_SYNC_TYPE_APPEND |
				   MAIL_INDEX_SYNC_TYPE_EXPUNGE);

	pool = pool_alloconly_create("dbox mailbox", 1024+512);
	mbox = p_new(pool, struct dbox_mailbox, 1);
	mbox->ibox.box = dbox_mailbox;
	mbox->ibox.box.pool = pool;
	mbox->ibox.storage = &storage->storage;
	mbox->ibox.mail_vfuncs = &dbox_mail_vfuncs;
	mbox->ibox.index = index;
	mbox->path = p_strdup(pool, path);
	mbox->alt_path = p_strdup(pool, dbox_get_alt_path(storage, path));
	mbox->storage = storage;
	mbox->last_interactive_change = ioloop_time;

	value = getenv("DBOX_ROTATE_SIZE");
	if (value != NULL)
		mbox->rotate_size = (uoff_t)strtoul(value, NULL, 10) * 1024;
	else
		mbox->rotate_size = DBOX_DEFAULT_ROTATE_SIZE;
	mbox->rotate_size = 0; /* FIXME: currently anything else doesn't work */
	value = getenv("DBOX_ROTATE_MIN_SIZE");
	if (value != NULL)
		mbox->rotate_min_size = (uoff_t)strtoul(value, NULL, 10) * 1024;
	else
		mbox->rotate_min_size = DBOX_DEFAULT_ROTATE_MIN_SIZE;
	if (mbox->rotate_min_size > mbox->rotate_size)
		mbox->rotate_min_size = mbox->rotate_size;
	value = getenv("DBOX_ROTATE_DAYS");
	if (value != NULL)
		mbox->rotate_days = (unsigned int)strtoul(value, NULL, 10);
	else
		mbox->rotate_days = DBOX_DEFAULT_ROTATE_DAYS;

	value = getenv("DBOX_MAX_OPEN_FILES");
	if (value != NULL)
		mbox->max_open_files = (unsigned int)strtoul(value, NULL, 10);
	else
		mbox->max_open_files = DBOX_DEFAULT_MAX_OPEN_FILES;
	i_array_init(&mbox->open_files, I_MIN(mbox->max_open_files, 128));

	mbox->dbox_ext_id =
		mail_index_ext_register(index, "dbox", 0,
					sizeof(struct dbox_mail_index_record),
					sizeof(uint32_t));
	mbox->dbox_hdr_ext_id =
		mail_index_ext_register(index, "dbox-hdr",
					sizeof(struct dbox_index_header), 0, 0);
	mbox->dbox_index = dbox_index_init(mbox);

	index_storage_mailbox_init(&mbox->ibox, name, flags, FALSE);
	return &mbox->ibox.box;
}

static bool
dbox_cleanup_if_exists(struct mail_storage *storage, const char *path)
{
	struct stat st;

	if (stat(path, &st) < 0)
		return FALSE;

	/* check once in a while if there are temp files to clean up */
	if (st.st_atime > st.st_ctime + DBOX_TMP_DELETE_SECS) {
		/* there haven't been any changes to this directory since we
		   last checked it. */
	} else if (st.st_atime < ioloop_time - DBOX_TMP_SCAN_SECS) {
		/* time to scan */
		const char *prefix =
			mailbox_list_get_global_temp_prefix(storage->list);

		(void)unlink_old_files(path, prefix,
				       ioloop_time - DBOX_TMP_DELETE_SECS);
	}
	return TRUE;
}

static struct mailbox *
dbox_mailbox_open(struct mail_storage *_storage, const char *name,
		  struct istream *input, enum mailbox_open_flags flags)
{
	struct dbox_storage *storage = (struct dbox_storage *)_storage;
	const char *path;

	if (input != NULL) {
		mail_storage_set_critical(_storage,
			"dbox doesn't support streamed mailboxes");
		return NULL;
	}

	path = mailbox_list_get_path(_storage->list, name,
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);
	if (dbox_cleanup_if_exists(_storage, path))
		return dbox_open(storage, name, flags);
	else if (errno == ENOENT) {
		if (strcmp(name, "INBOX") == 0) {
			/* INBOX always exists, create it */
			if (create_dbox(_storage, path) < 0)
				return NULL;
			return dbox_open(storage, name, flags);
		}

		mail_storage_set_error(_storage, MAIL_ERROR_NOTFOUND,
			T_MAIL_ERR_MAILBOX_NOT_FOUND(name));
	} else if (errno == EACCES) {
		mail_storage_set_critical(_storage, "%s",
			mail_storage_eacces_msg("stat", path));
	} else {
		mail_storage_set_critical(_storage, "stat(%s) failed: %m",
					  path);
	}
	return NULL;
}

static int dbox_storage_mailbox_close(struct mailbox *box)
{
	struct dbox_mailbox *mbox = (struct dbox_mailbox *)box;
	int ret;

	ret = dbox_sync(mbox, TRUE);

	dbox_index_deinit(&mbox->dbox_index);
	dbox_files_free(mbox);
	array_free(&mbox->open_files);

	return index_storage_mailbox_close(box) < 0 ? -1 : ret;
}

static int dbox_mailbox_create(struct mail_storage *_storage,
			       const char *name, bool directory ATTR_UNUSED)
{
	const char *path;
	struct stat st;

	path = mailbox_list_get_path(_storage->list, name,
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);
	if (stat(path, &st) == 0) {
		mail_storage_set_error(_storage, MAIL_ERROR_NOTPOSSIBLE,
				       "Mailbox already exists");
		return -1;
	}

	return create_dbox(_storage, path);
}

static int
dbox_delete_nonrecursive(struct mailbox_list *list, const char *path,
			 const char *name)
{
	DIR *dir;
	struct dirent *d;
	string_t *full_path;
	unsigned int dir_len;
	bool unlinked_something = FALSE;

	dir = opendir(path);
	if (dir == NULL) {
		if (!mailbox_list_set_error_from_errno(list)) {
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
		mailbox_list_set_error(list, MAIL_ERROR_NOTPOSSIBLE,
			t_strdup_printf("Directory %s isn't empty, "
					"can't delete it.", name));
		return -1;
	}
	return 0;
}

static int
dbox_list_delete_mailbox(struct mailbox_list *list, const char *name)
{
	struct dbox_storage *storage = DBOX_LIST_CONTEXT(list);
	struct stat st;
	const char *path, *alt_path;
	bool deleted = FALSE;

	/* Make sure the indexes are closed before trying to delete the
	   directory that contains them. It can still fail with some NFS
	   implementations if indexes are opened by another session, but
	   that can't really be helped. */
	index_storage_destroy_unrefed();

	/* delete the index and control directories */
	if (storage->list_module_ctx.super.delete_mailbox(list, name) < 0)
		return -1;

	/* check if the mailbox actually exists */
	path = mailbox_list_get_path(list, name,
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);
	if (stat(path, &st) == 0) {
		/* delete the mailbox first */
		if (dbox_delete_nonrecursive(list, path, name) < 0)
			return -1;

		alt_path = dbox_get_alt_path(storage, path);
		if (alt_path != NULL) {
			if (dbox_delete_nonrecursive(list, alt_path, name) < 0)
				return -1;
		}
		/* try to delete the directory also */
		deleted = TRUE;
		path = mailbox_list_get_path(list, name,
					     MAILBOX_LIST_PATH_TYPE_DIR);
	} else if (errno != ENOENT) {
		mailbox_list_set_critical(list, "stat(%s) failed: %m", path);
		return -1;
	} else {
		/* mailbox not found - what about the directory? */
		path = mailbox_list_get_path(list, name,
					     MAILBOX_LIST_PATH_TYPE_DIR);
		if (stat(path, &st) == 0) {
			/* delete the directory */
		} else if (errno == ENOENT) {
			mailbox_list_set_error(list, MAIL_ERROR_NOTFOUND,
				T_MAIL_ERR_MAILBOX_NOT_FOUND(name));
			return -1;
		} else if (!mailbox_list_set_error_from_errno(list)) {
			mailbox_list_set_critical(list, "stat(%s) failed: %m",
						  path);
			return -1;
		}
	}

	if (rmdir(path) == 0)
		return 0;
	else if (errno == ENOTEMPTY) {
		if (deleted)
			return 0;
		mailbox_list_set_error(list, MAIL_ERROR_NOTPOSSIBLE,
			t_strdup_printf("Directory %s isn't empty, "
					"can't delete it.", name));
	} else if (!mailbox_list_set_error_from_errno(list)) {
		mailbox_list_set_critical(list, "rmdir() failed for %s: %m",
					  path);
	}
	return -1;
}

static void dbox_notify_changes(struct mailbox *box)
{
	struct dbox_mailbox *mbox = (struct dbox_mailbox *)box;
	const char *path;

	if (box->notify_callback == NULL)
		index_mailbox_check_remove_all(&mbox->ibox);
	else {
		path = t_strdup_printf("%s/"DBOX_INDEX_PREFIX".log",
				       mbox->path);
		index_mailbox_check_add(&mbox->ibox, path);
	}
}

static int dbox_list_iter_is_mailbox(struct mailbox_list_iterate_context *ctx
				      			ATTR_UNUSED,
				     const char *dir, const char *fname,
				     enum mailbox_list_file_type type,
				     enum mailbox_info_flags *flags)
{
	const char *mail_path;
	struct stat st;
	int ret = 1;

	/* try to avoid stat() with these checks */
	if (type != MAILBOX_LIST_FILE_TYPE_DIR &&
	    type != MAILBOX_LIST_FILE_TYPE_SYMLINK &&
	    type != MAILBOX_LIST_FILE_TYPE_UNKNOWN) {
		/* it's a file */
		*flags |= MAILBOX_NOSELECT | MAILBOX_NOINFERIORS;
		return 0;
	}

	/* need to stat() then */
	mail_path = t_strconcat(dir, "/", fname, NULL);
	if (stat(mail_path, &st) == 0) {
		if (!S_ISDIR(st.st_mode)) {
			/* non-directory */
			*flags |= MAILBOX_NOSELECT | MAILBOX_NOINFERIORS;
			ret = 0;
		} else if (st.st_nlink == 2) {
			/* no subdirectories */
			*flags |= MAILBOX_NOCHILDREN;
		} else if (*ctx->list->set.maildir_name != '\0') {
			/* default configuration: we have one directory
			   containing the mailboxes. if there are 3 links,
			   either this is a selectable mailbox without children
			   or non-selectable mailbox with children */
			if (st.st_nlink > 3)
				*flags |= MAILBOX_CHILDREN;
		} else {
			/* non-default configuration: all subdirectories are
			   child mailboxes. */
			if (st.st_nlink > 2)
				*flags |= MAILBOX_CHILDREN;
		}
	} else {
		/* non-selectable. probably either access denied, or symlink
		   destination not found. don't bother logging errors. */
		*flags |= MAILBOX_NOSELECT;
	}
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
		index_storage_destroy,
		NULL,
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
		dbox_storage_mailbox_close,
		index_storage_get_status,
		NULL,
		NULL,
		dbox_storage_sync_init,
		index_mailbox_sync_next,
		index_mailbox_sync_deinit,
		NULL,
		dbox_notify_changes,
		index_transaction_begin,
		index_transaction_commit,
		index_transaction_rollback,
		index_keywords_create,
		index_keywords_free,
		index_storage_get_uids,
		dbox_mail_alloc,
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
