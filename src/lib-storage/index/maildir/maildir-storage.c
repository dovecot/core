/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "mkdir-parents.h"
#include "eacces-error.h"
#include "unlink-old-files.h"
#include "mailbox-uidvalidity.h"
#include "mailbox-list-private.h"
#include "maildir-storage.h"
#include "maildir-uidlist.h"
#include "maildir-keywords.h"
#include "maildir-sync.h"
#include "index-mail.h"

#include <sys/stat.h>

#define MAILDIR_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, maildir_mailbox_list_module)
#define MAILDIR_SUBFOLDER_FILENAME "maildirfolder"

struct maildir_mailbox_list_context {
	union mailbox_list_module_context module_ctx;
	const struct maildir_settings *set;
};

extern struct mail_storage maildir_storage;
extern struct mailbox maildir_mailbox;

static struct event_category event_category_maildir = {
	.name = "maildir",
	.parent = &event_category_storage,
};

static MODULE_CONTEXT_DEFINE_INIT(maildir_mailbox_list_module,
				  &mailbox_list_module_register);
static const char *maildir_subdirs[] = { "cur", "new", "tmp" };

static void maildir_mailbox_close(struct mailbox *box);

static struct mail_storage *maildir_storage_alloc(void)
{
	struct maildir_storage *storage;
	pool_t pool;

	pool = pool_alloconly_create("maildir storage", 512+256);
	storage = p_new(pool, struct maildir_storage, 1);
	storage->storage = maildir_storage;
	storage->storage.pool = pool;
	return &storage->storage;
}

static int
maildir_storage_create(struct mail_storage *_storage, struct mail_namespace *ns,
		       const char **error_r ATTR_UNUSED)
{
	struct maildir_storage *storage = MAILDIR_STORAGE(_storage);
	struct mailbox_list *list = ns->list;
	const char *dir;

	storage->set = mail_namespace_get_driver_settings(ns, _storage);

	storage->temp_prefix = p_strdup(_storage->pool,
					mailbox_list_get_temp_prefix(list));

	if (list->set.control_dir == NULL && list->set.inbox_path == NULL &&
	    (ns->flags & NAMESPACE_FLAG_INBOX_ANY) != 0) {
		/* put the temp files into tmp/ directory preferably */
		storage->temp_prefix = p_strconcat(_storage->pool, "tmp/",
						   storage->temp_prefix, NULL);
		dir = mailbox_list_get_root_forced(list, MAILBOX_LIST_PATH_TYPE_DIR);
	} else {
		/* control dir should also be writable */
		dir = mailbox_list_get_root_forced(list, MAILBOX_LIST_PATH_TYPE_CONTROL);
	}
	_storage->temp_path_prefix = p_strconcat(_storage->pool, dir, "/",
						 storage->temp_prefix, NULL);
	return 0;
}

static void maildir_storage_get_list_settings(const struct mail_namespace *ns,
					      struct mailbox_list_settings *set)
{
	if (set->layout == NULL)
		set->layout = MAILBOX_LIST_NAME_MAILDIRPLUSPLUS;
	if (set->subscription_fname == NULL)
		set->subscription_fname = MAILDIR_SUBSCRIPTION_FILE_NAME;

	if (set->inbox_path == NULL && *set->maildir_name == '\0' &&
	    (strcmp(set->layout, MAILBOX_LIST_NAME_MAILDIRPLUSPLUS) == 0 ||
	     strcmp(set->layout, MAILBOX_LIST_NAME_FS) == 0) &&
	    (ns->flags & NAMESPACE_FLAG_INBOX_ANY) != 0) {
		/* Maildir++ INBOX is the Maildir base itself */
		set->inbox_path = set->root_dir;
	}
}

static const char *
maildir_storage_find_root_dir(const struct mail_namespace *ns)
{
	bool debug = ns->mail_set->mail_debug;
	const char *home, *path;

	/* we'll need to figure out the maildir location ourself.
	   It's ~/Maildir unless we are chrooted. */
	if (ns->owner != NULL &&
	    mail_user_get_home(ns->owner, &home) > 0) {
		path = t_strconcat(home, "/Maildir", NULL);
		if (access(path, R_OK|W_OK|X_OK) == 0) {
			if (debug)
				i_debug("maildir: root exists (%s)", path);
			return path;
		} 
		if (debug)
			i_debug("maildir: access(%s, rwx): failed: %m", path);
	} else {
		if (debug)
			i_debug("maildir: Home directory not set");
		if (access("/cur", R_OK|W_OK|X_OK) == 0) {
			if (debug)
				i_debug("maildir: /cur exists, assuming chroot");
			return "/";
		}
	}
	return NULL;
}

static bool maildir_storage_autodetect(const struct mail_namespace *ns,
				       struct mailbox_list_settings *set)
{
	bool debug = ns->mail_set->mail_debug;
	struct stat st;
	const char *path, *root_dir;

	if (set->root_dir != NULL)
		root_dir = set->root_dir;
	else {
		root_dir = maildir_storage_find_root_dir(ns);
		if (root_dir == NULL) {
			if (debug)
				i_debug("maildir: couldn't find root dir");
			return FALSE;
		}
	}

	path = t_strconcat(root_dir, "/cur", NULL);
	if (stat(path, &st) < 0) {
		if (debug)
			i_debug("maildir autodetect: stat(%s) failed: %m", path);
		return FALSE;
	}

	if (!S_ISDIR(st.st_mode)) {
		if (debug)
			i_debug("maildir autodetect: %s not a directory", path);
		return FALSE;
	}

	set->root_dir = root_dir;
	maildir_storage_get_list_settings(ns, set);
	return TRUE;
}

static int
mkdir_verify(struct mailbox *box, const char *dir, bool verify)
{
	const struct mailbox_permissions *perm;
	struct stat st;

	if (verify) {
		if (stat(dir, &st) == 0)
			return 0;

		if (errno != ENOENT) {
			mailbox_set_critical(box, "stat(%s) failed: %m", dir);
			return -1;
		}
	}

	perm = mailbox_get_permissions(box);
	if (mkdir_parents_chgrp(dir, perm->dir_create_mode,
				perm->file_create_gid,
				perm->file_create_gid_origin) == 0)
		return 0;

	if (errno == EEXIST) {
		if (verify)
			return 0;
		mail_storage_set_error(box->storage, MAIL_ERROR_EXISTS,
				       "Mailbox already exists");
	} else if (errno == ENOENT) {
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTFOUND,
			"Mailbox was deleted while it was being created");
	} else if (errno == EACCES) {
		if (box->list->ns->type == MAIL_NAMESPACE_TYPE_SHARED) {
			/* shared namespace, don't log permission errors */
			mail_storage_set_error(box->storage, MAIL_ERROR_PERM,
					       MAIL_ERRSTR_NO_PERMISSION);
			return -1;
		}
		mailbox_set_critical(box, "%s",
			mail_error_create_eacces_msg("mkdir", dir));
	} else {
		mailbox_set_critical(box, "mkdir(%s) failed: %m", dir);
	}
	return -1;
}

static int maildir_check_tmp(struct mail_storage *storage, const char *dir)
{
	unsigned int interval = storage->set->mail_temp_scan_interval;
	const char *path;
	struct stat st;

	/* if tmp/ directory exists, we need to clean it up once in a while */
	path = t_strconcat(dir, "/tmp", NULL);
	if (stat(path, &st) < 0) {
		if (errno == ENOENT || errno == ENAMETOOLONG)
			return 0;
		if (errno == EACCES) {
			mail_storage_set_critical(storage, "%s",
				mail_error_eacces_msg("stat", path));
			return -1;
		}
		mail_storage_set_critical(storage, "stat(%s) failed: %m", path);
		return -1;
	}

	if (interval == 0) {
		/* disabled */
	} else if (st.st_atime > st.st_ctime + MAILDIR_TMP_DELETE_SECS) {
		/* the directory should be empty. we won't do anything
		   until ctime changes. */
	} else if (st.st_atime < ioloop_time - (time_t)interval) {
		/* time to scan */
		(void)unlink_old_files(path, "",
				       ioloop_time - MAILDIR_TMP_DELETE_SECS);
	}
	return 1;
}

/* create or fix maildir, ignore if it already exists */
static int create_maildir_subdirs(struct mailbox *box, bool verify)
{
	const char *path, *box_path;
	unsigned int i;
	enum mail_error error;
	int ret = 0;

	if (mailbox_get_path_to(box, MAILBOX_LIST_PATH_TYPE_MAILBOX,
				&box_path) < 0)
		return -1;

	for (i = 0; i < N_ELEMENTS(maildir_subdirs); i++) {
		path = t_strconcat(box_path, "/", maildir_subdirs[i], NULL);
		if (mkdir_verify(box, path, verify) < 0) {
			error = mailbox_get_last_mail_error(box);
			if (error != MAIL_ERROR_EXISTS)
				return -1;
			/* try to create all of the directories in case one
			   of them doesn't exist */
			ret = -1;
		}
	}
	return ret;
}

static void maildir_lock_touch_timeout(struct maildir_mailbox *mbox)
{
	(void)maildir_uidlist_lock_touch(mbox->uidlist);
}

static struct mailbox *
maildir_mailbox_alloc(struct mail_storage *storage, struct mailbox_list *list,
		      const char *vname, enum mailbox_flags flags)
{
	struct maildir_mailbox *mbox;
	pool_t pool;

	pool = pool_alloconly_create("maildir mailbox", 1024*3);
	mbox = p_new(pool, struct maildir_mailbox, 1);
	mbox->box = maildir_mailbox;
	mbox->box.pool = pool;
	mbox->box.storage = storage;
	mbox->box.list = list;
	mbox->box.mail_vfuncs = &maildir_mail_vfuncs;
	mbox->maildir_list_index_ext_id = (uint32_t)-1;

	index_storage_mailbox_alloc(&mbox->box, vname, flags, MAIL_INDEX_PREFIX);

	mbox->storage = MAILDIR_STORAGE(storage);
	return &mbox->box;
}

static int maildir_mailbox_open_existing(struct mailbox *box)
{
	struct maildir_mailbox *mbox = MAILDIR_MAILBOX(box);

	mbox->uidlist = maildir_uidlist_init(mbox);
	mbox->keywords = maildir_keywords_init(mbox);

	if ((box->flags & MAILBOX_FLAG_KEEP_LOCKED) != 0) {
		if (maildir_uidlist_lock(mbox->uidlist) <= 0) {
			maildir_mailbox_close(box);
			return -1;
		}
		mbox->keep_lock_to = timeout_add(MAILDIR_LOCK_TOUCH_SECS * 1000,
						 maildir_lock_touch_timeout,
						 mbox);
	}

	if (index_storage_mailbox_open(box, FALSE) < 0) {
		maildir_mailbox_close(box);
		return -1;
	}

	mbox->maildir_ext_id =
		mail_index_ext_register(mbox->box.index, "maildir",
					sizeof(mbox->maildir_hdr), 0, 0);
	return 0;
}

static bool maildir_storage_is_readonly(struct mailbox *box)
{
	struct maildir_mailbox *mbox = MAILDIR_MAILBOX(box);

	if (index_storage_is_readonly(box))
		return TRUE;

	if (maildir_is_backend_readonly(mbox)) {
		/* return read-only only if there are no private flags
		   (that are stored in index files) */
		if (mailbox_get_private_flags_mask(box) == 0)
			return TRUE;
	}
	return FALSE;
}

static int
maildir_mailbox_exists(struct mailbox *box, bool auto_boxes ATTR_UNUSED,
		       enum mailbox_existence *existence_r)
{
	return index_storage_mailbox_exists_full(box, "cur", existence_r);
}

static int maildir_mailbox_open(struct mailbox *box)
{
	const char *box_path = mailbox_get_path(box);
	const char *root_dir;
	struct stat st;
	int ret;

	/* begin by checking if tmp/ directory exists and if it should be
	   cleaned up. */
	ret = maildir_check_tmp(box->storage, box_path);
	if (ret > 0) {
		/* exists */
		return maildir_mailbox_open_existing(box);
	}
	if (ret < 0)
		return -1;

	/* tmp/ directory doesn't exist. does the maildir? autocreate missing
	   dirs only with Maildir++ and imapdir layouts. */
	if (strcmp(box->list->name, MAILBOX_LIST_NAME_MAILDIRPLUSPLUS) != 0 &&
	    strcmp(box->list->name, MAILBOX_LIST_NAME_IMAPDIR) != 0) {
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTFOUND,
			T_MAIL_ERR_MAILBOX_NOT_FOUND(box->vname));
		return -1;
	}
	root_dir = mailbox_list_get_root_forced(box->list,
						MAILBOX_LIST_PATH_TYPE_MAILBOX);
	if (strcmp(box_path, root_dir) == 0 && !box->inbox_any) {
		/* root directory for some namespace. */
		errno = ENOENT;
	} else if (stat(box_path, &st) == 0) {
		/* yes, we'll need to create the missing dirs */
		if (create_maildir_subdirs(box, TRUE) < 0)
			return -1;

		return maildir_mailbox_open_existing(box);
	}

	if (errno == ENOENT || errno == ENAMETOOLONG) {
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTFOUND,
			T_MAIL_ERR_MAILBOX_NOT_FOUND(box->vname));
		return -1;
	} else {
		mailbox_set_critical(box, "stat(%s) failed: %m", box_path);
		return -1;
	}
}

static int maildir_create_shared(struct mailbox *box)
{
	const struct mailbox_permissions *perm = mailbox_get_permissions(box);
	const char *path;
	mode_t old_mask;
	int fd, ret;

	ret = mailbox_get_path_to(box, MAILBOX_LIST_PATH_TYPE_MAILBOX,
				  &path);
	if (ret < 0)
		return -1;
	i_assert(ret > 0);

	old_mask = umask(0);
	path = t_strconcat(path, "/dovecot-shared", NULL);
	fd = open(path, O_WRONLY | O_CREAT, perm->file_create_mode);
	umask(old_mask);

	if (fd == -1) {
		mailbox_set_critical(box, "open(%s) failed: %m", path);
		return -1;
	}

	if (fchown(fd, (uid_t)-1, perm->file_create_gid) < 0) {
		if (errno == EPERM) {
			mailbox_set_critical(box, "%s",
				eperm_error_get_chgrp("fchown", path,
					perm->file_create_gid,
					perm->file_create_gid_origin));
		} else {
			mailbox_set_critical(box,
				"fchown(%s) failed: %m", path);
		}
	}
	i_close_fd(&fd);
	return 0;
}

static int
maildir_mailbox_update(struct mailbox *box, const struct mailbox_update *update)
{
	struct maildir_mailbox *mbox = MAILDIR_MAILBOX(box);
	struct maildir_uidlist *uidlist;
	bool locked = FALSE;
	int ret = 0;

	if (!box->opened) {
		if (mailbox_open(box) < 0)
			return -1;
	}
	uidlist = mbox->uidlist;

	if (update->uid_validity != 0 || update->min_next_uid != 0 ||
	    !guid_128_is_empty(update->mailbox_guid)) {
		if (maildir_uidlist_lock(uidlist) <= 0)
			return -1;

		locked = TRUE;
		if (!guid_128_is_empty(update->mailbox_guid))
			maildir_uidlist_set_mailbox_guid(uidlist, update->mailbox_guid);
		if (update->uid_validity != 0)
			maildir_uidlist_set_uid_validity(uidlist, update->uid_validity);
		if (update->min_next_uid != 0) {
			maildir_uidlist_set_next_uid(uidlist, update->min_next_uid,
						     FALSE);
		}
		ret = maildir_uidlist_update(uidlist);
	}
	if (ret == 0)
		ret = index_storage_mailbox_update(box, update);
	if (locked)
		maildir_uidlist_unlock(uidlist);
	return ret;
}

static int maildir_create_maildirfolder_file(struct mailbox *box)
{
	const struct mailbox_permissions *perm;
	const char *path;
	mode_t old_mask;
	int fd;

	/* Maildir++ spec wants that maildirfolder named file is created for
	   all subfolders. Do this only with Maildir++ layout. */
	if (strcmp(box->list->name, MAILBOX_LIST_NAME_MAILDIRPLUSPLUS) != 0)
		return 0;
	perm = mailbox_get_permissions(box);

	path = t_strconcat(mailbox_get_path(box),
			   "/"MAILDIR_SUBFOLDER_FILENAME, NULL);
	old_mask = umask(0);
	fd = open(path, O_CREAT | O_WRONLY, perm->file_create_mode);
	umask(old_mask);
	if (fd != -1) {
		/* ok */
	} else if (errno == ENOENT) {
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTFOUND,
			"Mailbox was deleted while it was being created");
		return -1;
	} else {
		mailbox_set_critical(box, "open(%s, O_CREAT) failed: %m", path);
		return -1;
	}

	if (perm->file_create_gid != (gid_t)-1) {
		if (fchown(fd, (uid_t)-1, perm->file_create_gid) == 0) {
			/* ok */
		} else if (errno == EPERM) {
			mailbox_set_critical(box, "%s",
				eperm_error_get_chgrp("fchown", path,
						      perm->file_create_gid,
						      perm->file_create_gid_origin));
		} else {
			mailbox_set_critical(box, "fchown(%s) failed: %m", path);
		}
	}
	i_close_fd(&fd);
	return 0;
}

static int
maildir_mailbox_create(struct mailbox *box, const struct mailbox_update *update,
		       bool directory)
{
	const char *root_dir, *shared_path;
	struct stat st;
	int ret;

	if ((ret = index_storage_mailbox_create(box, directory)) <= 0)
		return ret;
	ret = 0;
	/* the maildir is created now. finish the creation as best as we can */
	if (create_maildir_subdirs(box, FALSE) < 0)
		ret = -1;
	if (maildir_create_maildirfolder_file(box) < 0)
		ret = -1;
	/* if dovecot-shared exists in the root dir, copy it to newly
	   created mailboxes */
	root_dir = mailbox_list_get_root_forced(box->list,
						MAILBOX_LIST_PATH_TYPE_MAILBOX);
	shared_path = t_strconcat(root_dir, "/dovecot-shared", NULL);
	if (stat(shared_path, &st) == 0) {
		if (maildir_create_shared(box) < 0)
			ret = -1;
	}
	if (update != NULL) {
		if (maildir_mailbox_update(box, update) < 0)
			ret = -1;
	}
	return ret;
}

static int
maildir_mailbox_get_metadata(struct mailbox *box,
			     enum mailbox_metadata_items items,
			     struct mailbox_metadata *metadata_r)
{
	struct maildir_mailbox *mbox = MAILDIR_MAILBOX(box);

	if (index_mailbox_get_metadata(box, items, metadata_r) < 0)
		return -1;

	if ((items & MAILBOX_METADATA_GUID) != 0) {
		if (maildir_uidlist_get_mailbox_guid(mbox->uidlist,
						     metadata_r->guid) < 0)
			return -1;
	}
	return 0;
}

static void maildir_mailbox_close(struct mailbox *box)
{
	struct maildir_mailbox *mbox = MAILDIR_MAILBOX(box);

	if (mbox->keep_lock_to != NULL) {
		maildir_uidlist_unlock(mbox->uidlist);
		timeout_remove(&mbox->keep_lock_to);
	}

	if (mbox->flags_view != NULL)
		mail_index_view_close(&mbox->flags_view);
	if (mbox->keywords != NULL)
		maildir_keywords_deinit(&mbox->keywords);
	maildir_uidlist_deinit(&mbox->uidlist);
	index_storage_mailbox_close(box);
}

static void maildir_notify_changes(struct mailbox *box)
{
	struct maildir_mailbox *mbox = MAILDIR_MAILBOX(box);
	const char *box_path = mailbox_get_path(box);

	if (box->notify_callback == NULL)
		mailbox_watch_remove_all(&mbox->box);
	else {
		mailbox_watch_add(&mbox->box,
			t_strconcat(box_path, "/new", NULL));
		mailbox_watch_add(&mbox->box,
			t_strconcat(box_path, "/cur", NULL));
	}
}

static bool
maildir_is_internal_name(struct mailbox_list *list ATTR_UNUSED,
			 const char *name)
{
	return strcmp(name, "cur") == 0 ||
		strcmp(name, "new") == 0 ||
		strcmp(name, "tmp") == 0;
}

static void maildir_storage_add_list(struct mail_storage *storage,
				     struct mailbox_list *list)
{
	struct maildir_mailbox_list_context *mlist;

	mlist = p_new(list->pool, struct maildir_mailbox_list_context, 1);
	mlist->module_ctx.super = list->v;
	mlist->set = mail_namespace_get_driver_settings(list->ns, storage);

	list->v.is_internal_name = maildir_is_internal_name;
	MODULE_CONTEXT_SET(list, maildir_mailbox_list_module, mlist);
}

uint32_t maildir_get_uidvalidity_next(struct mailbox_list *list)
{
	const char *path;

	path = mailbox_list_get_root_forced(list, MAILBOX_LIST_PATH_TYPE_CONTROL);
	path = t_strconcat(path, "/"MAILDIR_UIDVALIDITY_FNAME, NULL);
	return mailbox_uidvalidity_next(list, path);
}

static enum mail_flags maildir_get_private_flags_mask(struct mailbox *box)
{
	struct maildir_mailbox *mbox = MAILDIR_MAILBOX(box);
	const char *path, *path2;
	struct stat st;

	if (mbox->private_flags_mask_set)
		return mbox->_private_flags_mask;
	mbox->private_flags_mask_set = TRUE;

	path = mailbox_list_get_root_forced(box->list, MAILBOX_LIST_PATH_TYPE_MAILBOX);
	if (box->list->set.index_pvt_dir != NULL) {
		/* private index directory is set. we'll definitely have
		   private flags. */
		mbox->_private_flags_mask = MAIL_SEEN;
	} else if (!mailbox_list_get_root_path(box->list,
					       MAILBOX_LIST_PATH_TYPE_INDEX,
					       &path2) ||
		   strcmp(path, path2) == 0) {
		/* no separate index directory. we can't have private flags,
		   so don't even bother checking if dovecot-shared exists */
	} else {
		path = t_strconcat(mailbox_get_path(box),
				   "/dovecot-shared", NULL);
		if (stat(path, &st) == 0)
			mbox->_private_flags_mask = MAIL_SEEN;
	}
	return mbox->_private_flags_mask;
}

bool maildir_is_backend_readonly(struct maildir_mailbox *mbox)
{
	if (!mbox->backend_readonly_set) {
		const char *box_path = mailbox_get_path(&mbox->box);

		mbox->backend_readonly_set = TRUE;
		if (access(t_strconcat(box_path, "/cur", NULL), W_OK) < 0 &&
		    errno == EACCES)
			mbox->backend_readonly = TRUE;
	}
	return mbox->backend_readonly;
}

struct mail_storage maildir_storage = {
	.name = MAILDIR_STORAGE_NAME,
	.class_flags = MAIL_STORAGE_CLASS_FLAG_FILE_PER_MSG |
		MAIL_STORAGE_CLASS_FLAG_HAVE_MAIL_GUIDS |
		MAIL_STORAGE_CLASS_FLAG_HAVE_MAIL_SAVE_GUIDS |
		MAIL_STORAGE_CLASS_FLAG_BINARY_DATA,
	.event_category = &event_category_maildir,

	.v = {
                maildir_get_setting_parser_info,
		maildir_storage_alloc,
		maildir_storage_create,
		index_storage_destroy,
		maildir_storage_add_list,
		maildir_storage_get_list_settings,
		maildir_storage_autodetect,
		maildir_mailbox_alloc,
		NULL,
		NULL,
	}
};

struct mailbox maildir_mailbox = {
	.v = {
		maildir_storage_is_readonly,
		index_storage_mailbox_enable,
		maildir_mailbox_exists,
		maildir_mailbox_open,
		maildir_mailbox_close,
		index_storage_mailbox_free,
		maildir_mailbox_create,
		maildir_mailbox_update,
		index_storage_mailbox_delete,
		index_storage_mailbox_rename,
		index_storage_get_status,
		maildir_mailbox_get_metadata,
		index_storage_set_subscribed,
		index_storage_attribute_set,
		index_storage_attribute_get,
		index_storage_attribute_iter_init,
		index_storage_attribute_iter_next,
		index_storage_attribute_iter_deinit,
		maildir_list_index_has_changed,
		maildir_list_index_update_sync,
		maildir_storage_sync_init,
		index_mailbox_sync_next,
		index_mailbox_sync_deinit,
		NULL,
		maildir_notify_changes,
		index_transaction_begin,
		index_transaction_commit,
		index_transaction_rollback,
		maildir_get_private_flags_mask,
		index_mail_alloc,
		index_storage_search_init,
		index_storage_search_deinit,
		index_storage_search_next_nonblock,
		index_storage_search_next_update_seq,
		maildir_save_alloc,
		maildir_save_begin,
		maildir_save_continue,
		maildir_save_finish,
		maildir_save_cancel,
		maildir_copy,
		maildir_transaction_save_commit_pre,
		maildir_transaction_save_commit_post,
		maildir_transaction_save_rollback,
		index_storage_is_inconsistent
	}
};
