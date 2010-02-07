/* Copyright (c) 2002-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "hostpid.h"
#include "str.h"
#include "mkdir-parents.h"
#include "eacces-error.h"
#include "unlink-directory.h"
#include "unlink-old-files.h"
#include "mailbox-log.h"
#include "mailbox-uidvalidity.h"
#include "maildir-storage.h"
#include "maildir-uidlist.h"
#include "maildir-keywords.h"
#include "maildir-sync.h"
#include "index-mail.h"

#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>

#define MAILDIR_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, maildir_mailbox_list_module)

struct maildir_mailbox_list {
	union mailbox_list_module_context module_ctx;
	const struct maildir_settings *set;
};

struct rename_context {
	bool found;
	size_t oldnamelen;
	const char *newname;
};

extern struct mail_storage maildir_storage;
extern struct mailbox maildir_mailbox;

static MODULE_CONTEXT_DEFINE_INIT(maildir_mailbox_list_module,
				  &mailbox_list_module_register);
static const char *maildir_subdirs[] = { "cur", "new", "tmp" };

static bool maildir_is_internal_name(const char *name)
{
	return strcmp(name, "cur") == 0 ||
		strcmp(name, "new") == 0 ||
		strcmp(name, "tmp") == 0;
}

static bool maildir_storage_is_valid_existing_name(struct mailbox_list *list,
						   const char *name)
{
	struct maildir_mailbox_list *mlist = MAILDIR_LIST_CONTEXT(list);
	const char *p;

	if (!mlist->module_ctx.super.is_valid_existing_name(list, name))
		return FALSE;

	/* Don't allow the mailbox name to end in cur/new/tmp */
	p = strrchr(name, '/');
	if (p != NULL)
		name = p + 1;
	return !maildir_is_internal_name(name);
}

static bool maildir_storage_is_valid_create_name(struct mailbox_list *list,
						 const char *name)
{
	struct maildir_mailbox_list *mlist = MAILDIR_LIST_CONTEXT(list);
	bool ret = TRUE;

	if (!mlist->module_ctx.super.is_valid_create_name(list, name))
		return FALSE;

	/* Don't allow creating mailboxes under cur/new/tmp */
	T_BEGIN {
		const char *const *tmp;

		for (tmp = t_strsplit(name, "/"); *tmp != NULL; tmp++) {
			if (maildir_is_internal_name(*tmp)) {
				ret = FALSE;
				break;
			}
		}
	} T_END;
	return ret;
}

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
	    (ns->flags & NAMESPACE_FLAG_INBOX) != 0) {
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

	if (set->inbox_path == NULL &&
	    (strcmp(set->layout, MAILBOX_LIST_NAME_MAILDIRPLUSPLUS) == 0 ||
	     strcmp(set->layout, MAILBOX_LIST_NAME_FS) == 0) &&
	    (ns->flags & NAMESPACE_FLAG_INBOX) != 0) {
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
	int ret;

	if (!verify) {
		ret = maildir_check_tmp(box->storage, box->path);
		if (ret > 0) {
			mail_storage_set_error(box->storage,
				MAIL_ERROR_EXISTS, "Mailbox already exists");
			return -1;
		}
		if (ret < 0)
			return -1;
	}

	for (i = 0; i < N_ELEMENTS(maildir_subdirs); i++) {
		path = t_strconcat(box->path, "/", maildir_subdirs[i], NULL);
		if (mkdir_verify(box->storage, box->list->ns, path,
				 box->dir_create_mode, box->file_create_gid,
				 box->file_create_gid_origin, verify) < 0)
			return -1;
	}
	return 0;
}

static void maildir_lock_touch_timeout(struct maildir_mailbox *mbox)
{
	(void)maildir_uidlist_lock_touch(mbox->uidlist);
}

static struct mailbox *
maildir_mailbox_alloc(struct mail_storage *storage, struct mailbox_list *list,
		      const char *name, struct istream *input,
		      enum mailbox_flags flags)
{
	struct maildir_mailbox *mbox;
	struct index_mailbox_context *ibox;
	pool_t pool;

	pool = pool_alloconly_create("maildir mailbox", 1024+512);
	mbox = p_new(pool, struct maildir_mailbox, 1);
	mbox->box = maildir_mailbox;
	mbox->box.pool = pool;
	mbox->box.storage = storage;
	mbox->box.list = list;
	mbox->box.mail_vfuncs = &maildir_mail_vfuncs;

	index_storage_mailbox_alloc(&mbox->box, name, input, flags,
				    MAILDIR_INDEX_PREFIX);

	ibox = INDEX_STORAGE_CONTEXT(&mbox->box);
	ibox->save_commit_pre = maildir_transaction_save_commit_pre;
	ibox->save_commit_post = maildir_transaction_save_commit_post;
	ibox->save_rollback = maildir_transaction_save_rollback;

	mbox->storage = (struct maildir_storage *)storage;
	mbox->maildir_ext_id =
		mail_index_ext_register(mbox->box.index, "maildir",
					sizeof(mbox->maildir_hdr), 0, 0);
	mbox->uidlist = maildir_uidlist_init(mbox);
	mbox->keywords = maildir_keywords_init(mbox);
	return &mbox->box;
}

static int maildir_mailbox_open_existing(struct mailbox *box)
{
	struct maildir_mailbox *mbox = (struct maildir_mailbox *)box;
	struct stat st;
	const char *shared_path;

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
	struct stat st;
	int ret;
	bool inbox;

	if (box->input != NULL) {
		mail_storage_set_critical(box->storage,
			"Maildir doesn't support streamed mailboxes");
		return -1;
	}

	inbox = strcmp(box->name, "INBOX") == 0 &&
		(box->list->ns->flags & NAMESPACE_FLAG_INBOX) != 0;

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
	if (inbox || (*box->name != '\0' && stat(box->path, &st) == 0)) {
		/* yes, we'll need to create the missing dirs */
		if (create_maildir(box, TRUE) < 0)
			return -1;

		return maildir_mailbox_open_existing(box);
	} else if (*box->name == '\0' || errno == ENOENT) {
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
	struct maildir_uidlist *uidlist = mbox->uidlist;
	int ret;

	if (!box->opened) {
		if (mailbox_open(box) < 0)
			return -1;
	}

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

	if (directory &&
	    (box->list->props & MAILBOX_LIST_PROP_NO_NOSELECT) == 0)
		return 0;

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

static void
maildir_storage_get_status(struct mailbox *box, enum mailbox_status_items items,
			   struct mailbox_status *status_r)
{
	struct maildir_mailbox *mbox = (struct maildir_mailbox *)box;

	index_storage_get_status(box, items, status_r);
	if ((items & STATUS_GUID) != 0) {
		(void)maildir_uidlist_get_mailbox_guid(mbox->uidlist,
						       status_r->mailbox_guid);
	}
}

static const char *
maildir_get_unlink_dest(struct mailbox_list *list, const char *name)
{
	const char *root_dir;
	char sep;

	if (list->mail_set->mail_full_filesystem_access &&
	    (*name == '/' || *name == '~'))
		return NULL;

	if (strcmp(mailbox_list_get_driver_name(list),
		   MAILBOX_LIST_NAME_MAILDIRPLUSPLUS) != 0) {
		/* Not maildir++ driver. Don't use this trick. */
		return NULL;
	}

	root_dir = mailbox_list_get_path(list, NULL,
					 MAILBOX_LIST_PATH_TYPE_DIR);
	sep = mailbox_list_get_hierarchy_sep(list);
	return t_strdup_printf("%s/%c%c"MAILDIR_UNLINK_DIRNAME, root_dir,
			       sep, sep);
}

static int
maildir_delete_nonrecursive(struct mailbox_list *list, const char *path,
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
			mailbox_list_set_error(list, MAIL_ERROR_NOTFOUND,
				T_MAIL_ERR_MAILBOX_NOT_FOUND(name));
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

		if (maildir_is_internal_name(d->d_name)) {
			if (unlink_directory(str_c(full_path), TRUE) < 0) {
				mailbox_list_set_critical(list,
					"unlink_directory(%s) failed: %m",
					str_c(full_path));
			} else {
				unlinked_something = TRUE;
			}
			continue;
		}

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
		mailbox_list_set_error(list, MAIL_ERROR_NOTFOUND,
			t_strdup_printf("Directory %s isn't empty, "
					"can't delete it.", name));
		return -1;
	}
	return 0;
}

static int
maildir_delete_with_trash(struct mailbox_list *list, const char *src,
			  const char *dest, const char *name)
{
	unsigned int count;

	/* rename the .maildir into ..DOVECOT-TRASH which atomically
	   marks it as being deleted. If we die before deleting the
	   ..DOVECOT-TRASH directory, it gets deleted the next time
	   mailbox listing sees it. */
	count = 0;
	while (rename(src, dest) < 0) {
		if (errno == ENOENT) {
			/* it was just deleted under us by
			   another process */
			mailbox_list_set_error(list, MAIL_ERROR_NOTFOUND,
				T_MAIL_ERR_MAILBOX_NOT_FOUND(name));
			return -1;
		}
		if (!EDESTDIREXISTS(errno)) {
			mailbox_list_set_critical(list,
				"rename(%s, %s) failed: %m", src, dest);
			return -1;
		}

		/* already existed, delete it and try again */
		if (unlink_directory(dest, TRUE) < 0 &&
		    (errno != ENOTEMPTY || count >= 5)) {
			mailbox_list_set_critical(list,
				"unlink_directory(%s) failed: %m", dest);
			return -1;
		}
		count++;
	}

	if (unlink_directory(dest, TRUE) < 0 && errno != ENOTEMPTY) {
		mailbox_list_set_critical(list,
			"unlink_directory(%s) failed: %m", dest);

		/* it's already renamed to ..dir, which means it's
		   deleted as far as the client is concerned. Report
		   success. */
	}
	return 0;
}

static void mailbox_get_guid(struct mailbox_list *list, const char *name,
			     uint8_t mailbox_guid[MAIL_GUID_128_SIZE])
{
	struct mailbox *box;
	struct mailbox_status status;

	box = mailbox_alloc(list, name, NULL, MAILBOX_FLAG_KEEP_RECENT);
	if (mailbox_open(box) < 0)
		memset(mailbox_guid, 0, MAIL_GUID_128_SIZE);
	else {
		mailbox_get_status(box, STATUS_GUID, &status);
		memcpy(mailbox_guid, status.mailbox_guid, MAIL_GUID_128_SIZE);
	}
	mailbox_close(&box);
}

static int
maildir_list_delete_mailbox(struct mailbox_list *list, const char *name)
{
	union mailbox_list_module_context *mlist = MAILDIR_LIST_CONTEXT(list);
	uint8_t mailbox_guid[MAIL_GUID_128_SIZE];
	uint8_t dir_sha128[MAIL_GUID_128_SIZE];
	struct stat st;
	const char *src, *dest, *base;
	int ret;

	mailbox_get_guid(list, name, mailbox_guid);

	/* delete the index and control directories */
	if (mlist->super.delete_mailbox(list, name) < 0)
		return -1;

	/* check if the mailbox actually exists */
	src = mailbox_list_get_path(list, name, MAILBOX_LIST_PATH_TYPE_MAILBOX);
	if (lstat(src, &st) != 0 && errno == ENOENT) {
		mailbox_list_set_error(list, MAIL_ERROR_NOTFOUND,
			T_MAIL_ERR_MAILBOX_NOT_FOUND(name));
		return -1;
	}

	if (!S_ISDIR(st.st_mode)) {
		/* a symlink most likely */
		if (unlink(src) < 0 && errno != ENOENT) {
			mailbox_list_set_critical(list,
				"unlink(%s) failed: %m", src);
			return -1;
		}
		return 0;
	}

	if (strcmp(name, "INBOX") == 0) {
		/* we shouldn't get this far if this is the actual INBOX.
		   more likely we're just deleting a namespace/INBOX.
		   be anyway sure that we don't accidentally delete the entire
		   maildir (INBOX explicitly configured to maildir root). */
		base = mailbox_list_get_path(list, NULL,
					     MAILBOX_LIST_PATH_TYPE_MAILBOX);
		if (strcmp(base, src) == 0) {
			mailbox_list_set_error(list, MAIL_ERROR_NOTPOSSIBLE,
					       "INBOX can't be deleted.");
			return -1;
		}
	}

	dest = maildir_get_unlink_dest(list, name);
	if (dest == NULL) {
		/* delete the directory directly without any renaming */
		ret = maildir_delete_nonrecursive(list, src, name);
	} else {
		ret = maildir_delete_with_trash(list, src, dest, name);
	}

	if (ret == 0) {
		mailbox_list_add_change(list, MAILBOX_LOG_RECORD_DELETE_MAILBOX,
					mailbox_guid);
		mailbox_name_get_sha128(name, dir_sha128);
		mailbox_list_add_change(list, MAILBOX_LOG_RECORD_DELETE_DIR,
					dir_sha128);
	}
	return 0;
}

static int
maildir_list_rename_mailbox(struct mailbox_list *oldlist, const char *oldname,
			    struct mailbox_list *newlist, const char *newname,
			    bool rename_children)
{
	struct maildir_mailbox_list *oldmlist = MAILDIR_LIST_CONTEXT(oldlist);
	const char *path1, *path2;

	if (strcmp(oldname, "INBOX") == 0) {
		/* INBOX often exists as the root ~/Maildir.
		   We can't rename it then. */
		path1 = mailbox_list_get_path(oldlist, oldname,
					      MAILBOX_LIST_PATH_TYPE_MAILBOX);
		path2 = mailbox_list_get_path(oldlist, NULL,
					      MAILBOX_LIST_PATH_TYPE_MAILBOX);
		if (strcmp(path1, path2) == 0) {
			mailbox_list_set_error(oldlist, MAIL_ERROR_NOTPOSSIBLE,
				"Renaming INBOX isn't supported.");
			return -1;
		}
	}

	return oldmlist->module_ctx.super.
		rename_mailbox(oldlist, oldname, newlist, newname,
			       rename_children);
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

static int
maildir_list_iter_is_mailbox(struct mailbox_list_iterate_context *ctx
			     	ATTR_UNUSED,
			     const char *dir, const char *fname,
			     const char *mailbox_name ATTR_UNUSED,
			     enum mailbox_list_file_type type,
			     enum mailbox_info_flags *flags)
{
	struct stat st, st2;
	const char *path, *cur_path;
	int ret;

	if (maildir_is_internal_name(fname)) {
		*flags |= MAILBOX_NONEXISTENT;
		return 0;
	}

	switch (type) {
	case MAILBOX_LIST_FILE_TYPE_FILE:
	case MAILBOX_LIST_FILE_TYPE_OTHER:
		/* non-directories are not */
		*flags |= MAILBOX_NOSELECT;
		return 0;

	case MAILBOX_LIST_FILE_TYPE_DIR:
	case MAILBOX_LIST_FILE_TYPE_UNKNOWN:
	case MAILBOX_LIST_FILE_TYPE_SYMLINK:
		break;
	}

	path = t_strdup_printf("%s/%s", dir, fname);
	if (stat(path, &st) == 0) {
		if (!S_ISDIR(st.st_mode)) {
			if (strncmp(fname, ".nfs", 4) == 0) {
				/* temporary NFS file */
				*flags |= MAILBOX_NONEXISTENT;
			} else {
				*flags |= MAILBOX_NOSELECT |
					MAILBOX_NOINFERIORS;
			}
			return 0;
		}
		ret = 1;
	} else if (errno == ENOENT) {
		/* doesn't exist - probably a non-existing subscribed mailbox */
		*flags |= MAILBOX_NONEXISTENT;
		ret = 0;
	} else {
		/* non-selectable. probably either access denied, or symlink
		   destination not found. don't bother logging errors. */
		*flags |= MAILBOX_NOSELECT;
		ret = 1;
	}
	if ((*flags & (MAILBOX_NOSELECT | MAILBOX_NONEXISTENT)) == 0) {
		/* make sure it's a selectable mailbox */
		cur_path = t_strconcat(path, "/cur", NULL);
		if (stat(cur_path, &st2) < 0 || !S_ISDIR(st2.st_mode))
			*flags |= MAILBOX_NOSELECT;

		if (*ctx->list->set.maildir_name == '\0') {
			/* now we can figure out based on the link count if we
			   have child mailboxes or not. for a selectable
			   mailbox we have 3 more links (cur/, new/ and tmp/)
			   than non-selectable. */
			if ((*flags & MAILBOX_NOSELECT) == 0) {
				if (st.st_nlink > 5)
					*flags |= MAILBOX_CHILDREN;
				else
					*flags |= MAILBOX_NOCHILDREN;
			} else {
				if (st.st_nlink > 2)
					*flags |= MAILBOX_CHILDREN;
				else
					*flags |= MAILBOX_NOCHILDREN;
			}
		} else {
			/* link count 3 may mean either a selectable mailbox
			   or a non-selectable mailbox with 1 child. */
			if (st.st_nlink > 3)
				*flags |= MAILBOX_CHILDREN;
			else if (st.st_nlink == 3) {
				if ((*flags & MAILBOX_NOSELECT) != 0)
					*flags |= MAILBOX_CHILDREN;
				else
					*flags |= MAILBOX_NOCHILDREN;
			}
		}
	}
	return ret;
}

static int
maildirplusplus_iter_is_mailbox(struct mailbox_list_iterate_context *ctx,
				const char *dir, const char *fname,
				const char *mailbox_name ATTR_UNUSED,
				enum mailbox_list_file_type type,
				enum mailbox_info_flags *flags)
{
	struct maildir_mailbox_list *mlist = MAILDIR_LIST_CONTEXT(ctx->list);
	int ret;

	if (fname[1] == mailbox_list_get_hierarchy_sep(ctx->list) &&
	    strcmp(fname+2, MAILDIR_UNLINK_DIRNAME) == 0) {
		const char *path;
		struct stat st;

		/* this directory is in the middle of being deleted,
		   or the process trying to delete it had died.
		   delete it ourself if it's been there longer than
		   one hour. */
		path = t_strdup_printf("%s/%s", dir, fname);
		if (stat(path, &st) == 0 &&
		    st.st_mtime < ioloop_time - 3600)
			(void)unlink_directory(path, TRUE);

		*flags |= MAILBOX_NONEXISTENT;
		return 0;
	}

	switch (type) {
	case MAILBOX_LIST_FILE_TYPE_DIR:
		/* all directories are valid maildirs */
		return 1;

	case MAILBOX_LIST_FILE_TYPE_FILE:
	case MAILBOX_LIST_FILE_TYPE_OTHER:
		/* non-directories are not */
		*flags |= MAILBOX_NOSELECT;
		return 0;

	case MAILBOX_LIST_FILE_TYPE_UNKNOWN:
	case MAILBOX_LIST_FILE_TYPE_SYMLINK:
		/* need to check with stat() to be sure */
		break;
	}

	/* Check files beginning with .nfs always because they may be
	   temporary files created by the kernel */
	if (mlist->set->maildir_stat_dirs || *fname == '\0' ||
	    strncmp(fname, ".nfs", 4) == 0) {
		const char *path;
		struct stat st;

		/* if fname="", we're checking if a base maildir has INBOX */
		path = *fname == '\0' ? t_strdup_printf("%s/cur", dir) :
			t_strdup_printf("%s/%s", dir, fname);
		if (stat(path, &st) == 0) {
			if (S_ISDIR(st.st_mode))
				ret = 1;
			else {
				if (strncmp(fname, ".nfs", 4) == 0)
					*flags |= MAILBOX_NONEXISTENT;
				else
					*flags |= MAILBOX_NOSELECT;
				ret = 0;
			}
		} else if (errno == ENOENT) {
			/* just deleted? */
			*flags |= MAILBOX_NONEXISTENT;
			ret = 0;
		} else {
			*flags |= MAILBOX_NOSELECT;
			ret = 0;
		}
	} else {
		ret = 1;
	}
	return ret;
}

uint32_t maildir_get_uidvalidity_next(struct mailbox_list *list)
{
	const char *path;

	path = mailbox_list_get_path(list, NULL,
				     MAILBOX_LIST_PATH_TYPE_CONTROL);
	path = t_strconcat(path, "/"MAILDIR_UIDVALIDITY_FNAME, NULL);
	return mailbox_uidvalidity_next(list, path);
}

static void maildir_storage_add_list(struct mail_storage *storage,
				     struct mailbox_list *list)
{
	struct maildir_mailbox_list *mlist;

	mlist = p_new(list->pool, struct maildir_mailbox_list, 1);
	mlist->module_ctx.super = list->v;
	mlist->set = mail_storage_get_driver_settings(storage);

	if (strcmp(list->name, MAILBOX_LIST_NAME_MAILDIRPLUSPLUS) == 0) {
		list->v.iter_is_mailbox = maildirplusplus_iter_is_mailbox;
	} else {
		list->v.is_valid_existing_name =
			maildir_storage_is_valid_existing_name;
		list->v.is_valid_create_name =
			maildir_storage_is_valid_create_name;
		list->v.iter_is_mailbox = maildir_list_iter_is_mailbox;
	}
	list->v.delete_mailbox = maildir_list_delete_mailbox;
	list->v.rename_mailbox = maildir_list_rename_mailbox;
	MODULE_CONTEXT_SET(list, maildir_mailbox_list_module, mlist);
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
		maildir_mailbox_create,
		maildir_mailbox_update,
		maildir_storage_get_status,
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
		index_storage_is_inconsistent
	}
};
