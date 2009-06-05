/* Copyright (c) 2007-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "mkdir-parents.h"
#include "index-mail.h"
#include "mail-copy.h"
#include "cydir-sync.h"
#include "cydir-storage.h"

#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#define CYDIR_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, cydir_mailbox_list_module)

struct cydir_mailbox_list {
	union mailbox_list_module_context module_ctx;
};

extern struct mail_storage cydir_storage;
extern struct mailbox cydir_mailbox;

static MODULE_CONTEXT_DEFINE_INIT(cydir_mailbox_list_module,
				  &mailbox_list_module_register);

static struct mail_storage *cydir_storage_alloc(void)
{
	struct cydir_storage *storage;
	pool_t pool;

	pool = pool_alloconly_create("cydir storage", 512+256);
	storage = p_new(pool, struct cydir_storage, 1);
	storage->storage = cydir_storage;
	storage->storage.pool = pool;
	return &storage->storage;
}

static void
cydir_storage_get_list_settings(const struct mail_namespace *ns ATTR_UNUSED,
				struct mailbox_list_settings *set)
{
	if (set->layout == NULL)
		set->layout = MAILBOX_LIST_NAME_FS;
	if (set->subscription_fname == NULL)
		set->subscription_fname = CYDIR_SUBSCRIPTION_FILE_NAME;
}

static int create_cydir(struct mail_storage *storage, struct mail_namespace *ns,
			const char *path)
{
	mode_t mode;
	gid_t gid;

	mailbox_list_get_dir_permissions(ns->list, NULL, &mode, &gid);
	if (mkdir_parents_chown(path, mode, (uid_t)-1, gid) < 0 &&
	    errno != EEXIST) {
		if (!mail_storage_set_error_from_errno(storage)) {
			mail_storage_set_critical(storage,
				"mkdir(%s) failed: %m", path);
		}
		return -1;
	}
	return 0;
}

static struct mailbox *
cydir_open(struct mail_storage *storage, struct mailbox_list *list,
	   const char *name, enum mailbox_open_flags flags)
{
	struct cydir_mailbox *mbox;
	struct mail_index *index;
	const char *path;
	pool_t pool;

	path = mailbox_list_get_path(list, name,
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);
	index = index_storage_alloc(list, name, flags, CYDIR_INDEX_PREFIX);
	mail_index_set_fsync_types(index, MAIL_INDEX_SYNC_TYPE_APPEND |
				   MAIL_INDEX_SYNC_TYPE_EXPUNGE);

	pool = pool_alloconly_create("cydir mailbox", 1024+512);
	mbox = p_new(pool, struct cydir_mailbox, 1);
	mbox->ibox.box = cydir_mailbox;
	mbox->ibox.box.pool = pool;
	mbox->ibox.box.storage = storage;
	mbox->ibox.mail_vfuncs = &cydir_mail_vfuncs;
	mbox->ibox.index = index;

	mbox->storage = (struct cydir_storage *)storage;
	mbox->path = p_strdup(pool, path);

	index_storage_mailbox_init(&mbox->ibox, name, flags, FALSE);
	return &mbox->ibox.box;
}

static struct mailbox *
cydir_mailbox_open(struct mail_storage *storage, struct mailbox_list *list,
		   const char *name, struct istream *input,
		   enum mailbox_open_flags flags)
{
	const char *path;
	struct stat st;

	if (input != NULL) {
		mailbox_list_set_critical(list,
			"cydir doesn't support streamed mailboxes");
		return NULL;
	}

	/* cydir can't work without index files */
	flags &= ~MAILBOX_OPEN_NO_INDEX_FILES;

	path = mailbox_list_get_path(list, name,
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);
	if (stat(path, &st) == 0)
		return cydir_open(storage, list, name, flags);
	else if (errno == ENOENT) {
		if (strcmp(name, "INBOX") == 0) {
			/* INBOX always exists, create it */
			if (create_cydir(storage, list->ns, path) < 0) {
				mailbox_list_set_error_from_storage(list,
								    storage);
				return NULL;
			}
			return cydir_open(storage, list, "INBOX", flags);
		}
		mail_storage_set_error(storage, MAIL_ERROR_NOTFOUND,
			T_MAIL_ERR_MAILBOX_NOT_FOUND(name));
	} else if (errno == EACCES) {
		mail_storage_set_critical(storage, "%s",
			mail_error_eacces_msg("stat", path));
	} else {
		mail_storage_set_critical(storage, "stat(%s) failed: %m",
					  path);
	}
	return NULL;
}

static int
cydir_mailbox_create(struct mail_storage *storage, struct mailbox_list *list,
		     const char *name, bool directory ATTR_UNUSED)
{
	const char *path;
	struct stat st;

	path = mailbox_list_get_path(list, name,
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);
	if (stat(path, &st) == 0) {
		mail_storage_set_error(storage, MAIL_ERROR_EXISTS,
				       "Mailbox already exists");
		return -1;
	}

	return create_cydir(storage, list->ns, path);
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
			mailbox_list_set_critical(list, "unlink(%s) failed: %m",
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
		mailbox_list_set_error(list, MAIL_ERROR_NOTFOUND,
			t_strdup_printf("Directory %s isn't empty, "
					"can't delete it.", name));
		return -1;
	}
	return 0;
}

static int
cydir_list_delete_mailbox(struct mailbox_list *list, const char *name)
{
	struct cydir_mailbox_list *mlist = CYDIR_LIST_CONTEXT(list);
	struct stat st;
	const char *src;

	/* Make sure the indexes are closed before trying to delete the
	   directory that contains them. It can still fail with some NFS
	   implementations if indexes are opened by another session, but
	   that can't really be helped. */
	index_storage_destroy_unrefed();

	/* delete the index and control directories */
	if (mlist->module_ctx.super.delete_mailbox(list, name) < 0)
		return -1;

	/* check if the mailbox actually exists */
	src = mailbox_list_get_path(list, name, MAILBOX_LIST_PATH_TYPE_MAILBOX);
	if (stat(src, &st) != 0 && errno == ENOENT) {
		mailbox_list_set_error(list, MAIL_ERROR_NOTFOUND,
			T_MAIL_ERR_MAILBOX_NOT_FOUND(name));
		return -1;
	}

	return cydir_delete_nonrecursive(list, src, name);
}

static void cydir_notify_changes(struct mailbox *box)
{
	struct cydir_mailbox *mbox = (struct cydir_mailbox *)box;

	if (box->notify_callback == NULL)
		index_mailbox_check_remove_all(&mbox->ibox);
	else
		index_mailbox_check_add(&mbox->ibox, mbox->path);
}

static int cydir_list_iter_is_mailbox(struct mailbox_list_iterate_context *ctx
				      			ATTR_UNUSED,
				      const char *dir, const char *fname,
				      const char *mailbox_name ATTR_UNUSED,
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
			/* non-default configuration: we have one directory
			   containing the mailboxes. if there are 3 links,
			   either this is a selectable mailbox without children
			   or non-selectable mailbox with children */
			if (st.st_nlink > 3)
				*flags |= MAILBOX_CHILDREN;
		} else {
			/* default configuration: all subdirectories are
			   child mailboxes. */
			if (st.st_nlink > 2)
				*flags |= MAILBOX_CHILDREN;
		}
	} else if (errno == ENOENT) {
		/* doesn't exist - probably a non-existing subscribed mailbox */
		*flags |= MAILBOX_NONEXISTENT;
	} else {
		/* non-selectable. probably either access denied, or symlink
		   destination not found. don't bother logging errors. */
		*flags |= MAILBOX_NOSELECT;
	}
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

static void cydir_storage_add_list(struct mail_storage *storage ATTR_UNUSED,
				   struct mailbox_list *list)
{
	struct cydir_mailbox_list *mlist;

	mlist = p_new(list->pool, struct cydir_mailbox_list, 1);
	mlist->module_ctx.super = list->v;

	list->v.iter_is_mailbox = cydir_list_iter_is_mailbox;
	list->v.delete_mailbox = cydir_list_delete_mailbox;

	MODULE_CONTEXT_SET(list, cydir_mailbox_list_module, mlist);
}

struct mail_storage cydir_storage = {
	MEMBER(name) CYDIR_STORAGE_NAME,
	MEMBER(class_flags) 0,

	{
		NULL,
		cydir_class_init,
		cydir_class_deinit,
		cydir_storage_alloc,
		NULL,
		index_storage_destroy,
		cydir_storage_add_list,
		cydir_storage_get_list_settings,
		NULL,
		cydir_mailbox_open,
		cydir_mailbox_create,
		NULL
	}
};

struct mailbox cydir_mailbox = {
	MEMBER(name) NULL, 
	MEMBER(storage) NULL, 
	MEMBER(list) NULL,

	{
		index_storage_is_readonly,
		index_storage_allow_new_keywords,
		index_storage_mailbox_enable,
		index_storage_mailbox_close,
		index_storage_get_status,
		NULL,
		NULL,
		cydir_storage_sync_init,
		index_mailbox_sync_next,
		index_mailbox_sync_deinit,
		NULL,
		cydir_notify_changes,
		index_transaction_begin,
		index_transaction_commit,
		index_transaction_rollback,
		index_transaction_set_max_modseq,
		index_keywords_create,
		index_keywords_create_from_indexes,
		index_keywords_free,
		index_keyword_is_valid,
		index_storage_get_seq_range,
		index_storage_get_uid_range,
		index_storage_get_expunged_uids,
		NULL,
		NULL,
		NULL,
		index_mail_alloc,
		index_header_lookup_init,
		index_header_lookup_deinit,
		index_storage_search_init,
		index_storage_search_deinit,
		index_storage_search_next_nonblock,
		index_storage_search_next_update_seq,
		cydir_save_alloc,
		cydir_save_begin,
		cydir_save_continue,
		cydir_save_finish,
		cydir_save_cancel,
		mail_storage_copy,
		index_storage_is_inconsistent
	}
};
