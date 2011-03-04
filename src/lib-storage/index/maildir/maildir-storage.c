/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

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

struct maildir_mailbox_list_context {
	union mailbox_list_module_context module_ctx;
	const struct maildir_settings *set;
};

extern struct mail_storage maildir_storage;
extern struct mailbox maildir_mailbox;

static MODULE_CONTEXT_DEFINE_INIT(maildir_mailbox_list_module,
				  &mailbox_list_module_register);
static const char *maildir_subdirs[] = { "cur", "new", "tmp" };

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
	struct maildir_storage *storage = (struct maildir_storage *)_storage;
	struct mailbox_list *list = ns->list;
	const char *dir;

	storage->set = mail_storage_get_driver_settings(_storage);

	storage->maildir_list_ext_id = (uint32_t)-1;
	storage->temp_prefix = p_strdup(_storage->pool,
					mailbox_list_get_temp_prefix(list));

	if (list->set.control_dir == NULL && list->set.inbox_path == NULL &&
	    (ns->flags & NAMESPACE_FLAG_INBOX_ANY) != 0) {
		/* put the temp files into tmp/ directory preferrably */
		storage->temp_prefix = p_strconcat(_storage->pool, "tmp/",
						   storage->temp_prefix, NULL);
		dir = mailbox_list_get_path(list, NULL,
					    MAILBOX_LIST_PATH_TYPE_DIR);
	} else {
		/* control dir should also be writable */
		dir = mailbox_list_get_path(list, NULL,
					    MAILBOX_LIST_PATH_TYPE_CONTROL);
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

	if (set->inbox_path == NULL && set->maildir_name == NULL &&
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
	if (mail_user_get_home(ns->user, &home) > 0) {
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
mkdir_verify(struct mail_storage *storage, struct mail_namespace *ns,
	     const char *dir, mode_t mode, gid_t gid, const char *gid_origin,
	     bool verify)
{
	struct stat st;

	if (verify) {
		if (stat(dir, &st) == 0)
			return 0;

		if (errno != ENOENT) {
			mail_storage_set_critical(storage,
						  "stat(%s) failed: %m", dir);
			return -1;
		}
	}

	if (mkdir_parents_chgrp(dir, mode, gid, gid_origin) == 0)
		return 0;

	if (errno == EEXIST) {
		if (verify)
			return 0;
		mail_storage_set_error(storage, MAIL_ERROR_EXISTS,
				       "Mailbox already exists");
	} else if (errno == ENOENT) {
		mail_storage_set_error(storage, MAIL_ERROR_NOTFOUND,
			"Mailbox was deleted while it was being created");
	} else if (errno == EACCES) {
		if (ns->type == NAMESPACE_SHARED) {
			/* shared namespace, don't log permission errors */
			mail_storage_set_error(storage, MAIL_ERROR_PERM,
					       MAIL_ERRSTR_NO_PERMISSION);
			return -1;
		}
		mail_storage_set_critical(storage, "%s",
			mail_error_create_eacces_msg("mkdir", dir));
	} else {
		mail_storage_set_critical(storage,
					  "mkdir(%s) failed: %m", dir);
	}
	return -1;
}

static int maildir_check_tmp(struct mail_storage *storage, const char *dir)
{
	const char *path;
	struct stat st;

	/* if tmp/ directory exists, we need to clean it up once in a while */
	path = t_strconcat(dir, "/tmp", NULL);
	if (stat(path, &st) < 0) {
		if (errno == ENOENT)
			return 0;
		if (errno == EACCES) {
			mail_storage_set_critical(storage, "%s",
				mail_error_eacces_msg("stat", path));
			return -1;
		}
		mail_storage_set_critical(storage, "stat(%s) failed: %m", path);
		return -1;
	}

	if (st.st_atime > st.st_ctime + MAILDIR_TMP_DELETE_SECS) {
		/* the directory should be empty. we won't do anything
		   until ctime changes. */
	} else if (st.st_atime < ioloop_time - MAILDIR_TMP_SCAN_SECS) {
		/* time to scan */
		(void)unlink_old_files(path, "",
				       ioloop_time - MAILDIR_TMP_DELETE_SECS);
	}
	return 1;
}

/* create or fix maildir, ignore if it already exists */
static int create_maildir(struct mailbox *box, bool verify)
{
	const char *path;
	unsigned int i;
	enum mail_error error;
	int ret = 0;

	for (i = 0; i < N_ELEMENTS(maildir_subdirs); i++) {
		path = t_strconcat(box->path, "/", maildir_subdirs[i], NULL);
		if (mkdir_verify(box->storage, box->list->ns, path,
				 box->dir_create_mode, box->file_create_gid,
				 box->file_create_gid_origin, verify) < 0) {
			(void)mail_storage_get_last_error(box->storage, &error);
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
		      const char *name, enum mailbox_flags flags)
{
	struct maildir_mailbox *mbox;
	struct index_mailbox_context *ibox;
	pool_t pool;

	pool = pool_alloconly_create("maildir mailbox", 1024*3);
	mbox = p_new(pool, struct maildir_mailbox, 1);
	mbox->box = maildir_mailbox;
	mbox->box.pool = pool;
	mbox->box.storage = storage;
	mbox->box.list = list;
	mbox->box.mail_vfuncs = &maildir_mail_vfuncs;

	index_storage_mailbox_alloc(&mbox->box, name, flags,
				    MAILDIR_INDEX_PREFIX);

	ibox = INDEX_STORAGE_CONTEXT(&mbox->box);
	ibox->save_commit_pre = maildir_transaction_save_commit_pre;
	ibox->save_commit_post = maildir_transaction_save_commit_post;
	ibox->save_rollback = maildir_transaction_save_rollback;

	mbox->storage = (struct maildir_storage *)storage;
	mbox->maildir_ext_id =
		mail_index_ext_register(mbox->box.index, "maildir",
					sizeof(mbox->maildir_hdr), 0, 0);
	return &mbox->box;
}

static int maildir_mailbox_open_existing(struct mailbox *box)
{
	struct maildir_mailbox *mbox = (struct maildir_mailbox *)box;
	struct stat st;
	const char *shared_path;

	mbox->uidlist = maildir_uidlist_init(mbox);
	mbox->keywords = maildir_keywords_init(mbox);

	shared_path = t_strconcat(box->path, "/dovecot-shared", NULL);
	if (stat(shared_path, &st) == 0)
		box->private_flags_mask = MAIL_SEEN;

	if ((box->flags & MAILBOX_FLAG_KEEP_LOCKED) != 0) {
		if (maildir_uidlist_lock(mbox->uidlist) <= 0)
			return -1;
		mbox->keep_lock_to = timeout_add(MAILDIR_LOCK_TOUCH_SECS * 1000,
						 maildir_lock_touch_timeout,
						 mbox);
	}

	if (access(t_strconcat(box->path, "/cur", NULL), W_OK) < 0 &&
	    errno == EACCES)
		mbox->box.backend_readonly = TRUE;
	return index_storage_mailbox_open(box, FALSE);
}

static int maildir_mailbox_open(struct mailbox *box)
{
	const char *root_dir;
	struct stat st;
	int ret;

	/* begin by checking if tmp/ directory exists and if it should be
	   cleaned up. */
	ret = maildir_check_tmp(box->storage, box->path);
	if (ret > 0) {
		/* exists */
		return maildir_mailbox_open_existing(box);
	}
	if (ret < 0)
		return -1;

	/* tmp/ directory doesn't exist. does the maildir? */
	root_dir = mailbox_list_get_path(box->list, NULL,
					 MAILBOX_LIST_PATH_TYPE_MAILBOX);
	if (strcmp(box->path, root_dir) == 0) {
		/* root directory. either INBOX or some other namespace root */
		errno = ENOENT;
	} else if (stat(box->path, &st) == 0) {
		/* yes, we'll need to create the missing dirs */
		if (create_maildir(box, TRUE) < 0)
			return -1;

		return maildir_mailbox_open_existing(box);
	}

	if (errno == ENOENT) {
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTFOUND,
			T_MAIL_ERR_MAILBOX_NOT_FOUND(box->name));
		return -1;
	} else {
		mail_storage_set_critical(box->storage,
					  "stat(%s) failed: %m", box->path);
		return -1;
	}
}

static int maildir_create_shared(struct mailbox *box)
{
	const char *path;
	mode_t old_mask;
	int fd;

	old_mask = umask(0);
	path = t_strconcat(box->path, "/dovecot-shared", NULL);
	fd = open(path, O_WRONLY | O_CREAT, box->file_create_mode);
	umask(old_mask);

	if (fd == -1) {
		mail_storage_set_critical(box->storage, "open(%s) failed: %m",
					  path);
		return -1;
	}

	if (fchown(fd, (uid_t)-1, box->file_create_gid) < 0) {
		if (errno == EPERM) {
			mail_storage_set_critical(box->storage, "%s",
				eperm_error_get_chgrp("fchown", path,
					box->file_create_gid,
					box->file_create_gid_origin));
		} else {
			mail_storage_set_critical(box->storage,
				"fchown(%s) failed: %m", path);
		}
	}
	(void)close(fd);
	return 0;
}

static int
maildir_mailbox_update(struct mailbox *box, const struct mailbox_update *update)
{
	struct maildir_mailbox *mbox = (struct maildir_mailbox *)box;
	struct maildir_uidlist *uidlist;
	int ret;

	if (!box->opened) {
		if (mailbox_open(box) < 0)
			return -1;
	}
	uidlist = mbox->uidlist;

	if (maildir_uidlist_lock(uidlist) <= 0)
		return -1;

	if (!mail_guid_128_is_empty(update->mailbox_guid))
		maildir_uidlist_set_mailbox_guid(uidlist, update->mailbox_guid);
	if (update->uid_validity != 0)
		maildir_uidlist_set_uid_validity(uidlist, update->uid_validity);
	if (update->min_next_uid != 0) {
		maildir_uidlist_set_next_uid(uidlist, update->min_next_uid,
					     FALSE);
	}
	ret = maildir_uidlist_update(uidlist);
	if (ret == 0)
		ret = index_storage_mailbox_update(box, update);
	maildir_uidlist_unlock(uidlist);
	return ret;
}

static int
maildir_mailbox_create(struct mailbox *box, const struct mailbox_update *update,
		       bool directory)
{
	const char *root_dir, *shared_path;
	struct stat st;
	int ret;

	if (directory &&
	    (box->list->props & MAILBOX_LIST_PROP_NO_NOSELECT) == 0)
		return 0;

	ret = maildir_check_tmp(box->storage, box->path);
	if (ret > 0) {
		mail_storage_set_error(box->storage, MAIL_ERROR_EXISTS,
				       "Mailbox already exists");
		return -1;
	}
	if (ret < 0)
		return -1;

	if (create_maildir(box, FALSE) < 0)
		return -1;

	/* if dovecot-shared exists in the root dir, copy it to newly
	   created mailboxes */
	root_dir = mailbox_list_get_path(box->list, NULL,
					 MAILBOX_LIST_PATH_TYPE_MAILBOX);
	shared_path = t_strconcat(root_dir, "/dovecot-shared", NULL);
	if (stat(shared_path, &st) == 0) {
		if (maildir_create_shared(box) < 0)
			return -1;
	}

	return update == NULL ? 0 : maildir_mailbox_update(box, update);
}

static int
maildir_mailbox_get_guid(struct mailbox *box, uint8_t guid[MAIL_GUID_128_SIZE])
{
	struct maildir_mailbox *mbox = (struct maildir_mailbox *)box;

	return maildir_uidlist_get_mailbox_guid(mbox->uidlist, guid);
}

static void maildir_mailbox_close(struct mailbox *box)
{
	struct maildir_mailbox *mbox = (struct maildir_mailbox *)box;

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
	struct maildir_mailbox *mbox = (struct maildir_mailbox *)box;

	if (box->notify_callback == NULL)
		index_mailbox_check_remove_all(&mbox->box);
	else {
		index_mailbox_check_add(&mbox->box,
			t_strconcat(mbox->box.path, "/new", NULL));
		index_mailbox_check_add(&mbox->box,
			t_strconcat(mbox->box.path, "/cur", NULL));
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

static int
maildir_list_get_mailbox_flags(struct mailbox_list *list,
			       const char *dir, const char *fname,
			       enum mailbox_list_file_type type,
			       struct stat *st_r,
			       enum mailbox_info_flags *flags)
{
	struct maildir_mailbox_list_context *mlist = MAILDIR_LIST_CONTEXT(list);
	struct stat st2;
	const char *cur_path;
	int ret;

	ret = mlist->module_ctx.super.
		get_mailbox_flags(list, dir, fname, type, st_r, flags);
	if (ret <= 0 || MAILBOX_INFO_FLAGS_FINISHED(*flags))
		return ret;

	/* see if it's a selectable mailbox. after that we can figure out based
	   on the link count if we have child mailboxes or not. for a
	   selectable mailbox we have 3 more links (cur/, new/ and tmp/)
	   than non-selectable. */
	cur_path = t_strconcat(dir, "/", fname, "/cur", NULL);
	if ((ret = stat(cur_path, &st2)) < 0 || !S_ISDIR(st2.st_mode)) {
		if (ret < 0 && errno == ENOENT)
			*flags |= MAILBOX_NONEXISTENT;
		else
			*flags |= MAILBOX_NOSELECT;
		if (st_r->st_nlink > 2)
			*flags |= MAILBOX_CHILDREN;
		else
			*flags |= MAILBOX_NOCHILDREN;
	} else {
		if (st_r->st_nlink > 5)
			*flags |= MAILBOX_CHILDREN;
		else
			*flags |= MAILBOX_NOCHILDREN;
	}
	return 1;
}

static void maildir_storage_add_list(struct mail_storage *storage,
				     struct mailbox_list *list)
{
	struct maildir_mailbox_list_context *mlist;

	mlist = p_new(list->pool, struct maildir_mailbox_list_context, 1);
	mlist->module_ctx.super = list->v;
	mlist->set = mail_storage_get_driver_settings(storage);

	list->v.is_internal_name = maildir_is_internal_name;
	list->v.get_mailbox_flags = maildir_list_get_mailbox_flags;
	MODULE_CONTEXT_SET(list, maildir_mailbox_list_module, mlist);
}

uint32_t maildir_get_uidvalidity_next(struct mailbox_list *list)
{
	const char *path;

	path = mailbox_list_get_path(list, NULL,
				     MAILBOX_LIST_PATH_TYPE_CONTROL);
	path = t_strconcat(path, "/"MAILDIR_UIDVALIDITY_FNAME, NULL);
	return mailbox_uidvalidity_next(list, path);
}

struct mail_storage maildir_storage = {
	.name = MAILDIR_STORAGE_NAME,
	.class_flags = 0,

	.v = {
                maildir_get_setting_parser_info,
		maildir_storage_alloc,
		maildir_storage_create,
		NULL,
		maildir_storage_add_list,
		maildir_storage_get_list_settings,
		maildir_storage_autodetect,
		maildir_mailbox_alloc,
		NULL
	}
};

struct mailbox maildir_mailbox = {
	.v = {
		index_storage_is_readonly,
		index_storage_allow_new_keywords,
		index_storage_mailbox_enable,
		maildir_mailbox_open,
		maildir_mailbox_close,
		index_storage_mailbox_free,
		maildir_mailbox_create,
		maildir_mailbox_update,
		index_storage_mailbox_delete,
		index_storage_mailbox_rename,
		index_storage_get_status,
		maildir_mailbox_get_guid,
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
		index_transaction_set_max_modseq,
		index_keywords_create,
		index_keywords_create_from_indexes,
		index_keywords_ref,
		index_keywords_unref,
		index_keyword_is_valid,
		index_storage_get_seq_range,
		index_storage_get_uid_range,
		index_storage_get_expunges,
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
		maildir_save_alloc,
		maildir_save_begin,
		maildir_save_continue,
		maildir_save_finish,
		maildir_save_cancel,
		maildir_copy,
		NULL,
		index_storage_is_inconsistent
	}
};
