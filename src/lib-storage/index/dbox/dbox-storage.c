/* Copyright (c) 2007-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "str.h"
#include "hex-binary.h"
#include "randgen.h"
#include "mkdir-parents.h"
#include "unlink-directory.h"
#include "unlink-old-files.h"
#include "index-mail.h"
#include "mail-copy.h"
#include "mailbox-uidvalidity.h"
#include "maildir/maildir-uidlist.h"
#include "dbox-map.h"
#include "dbox-file.h"
#include "dbox-sync.h"
#include "dbox-storage-rebuild.h"
#include "dbox-storage.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#define DBOX_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, dbox_mailbox_list_module)

struct dbox_mailbox_list {
	union mailbox_list_module_context module_ctx;
	const struct dbox_settings *set;
};

extern struct mail_storage dbox_storage;
extern struct mailbox dbox_mailbox;

static MODULE_CONTEXT_DEFINE_INIT(dbox_mailbox_list_module,
				  &mailbox_list_module_register);

static struct mail_storage *dbox_storage_alloc(void)
{
	struct dbox_storage *storage;
	pool_t pool;

	pool = pool_alloconly_create("dbox storage", 512+256);
	storage = p_new(pool, struct dbox_storage, 1);
	storage->storage = dbox_storage;
	storage->storage.pool = pool;
	return &storage->storage;
}

static int
dbox_storage_create(struct mail_storage *_storage, struct mail_namespace *ns,
		    const char **error_r)
{
	struct dbox_storage *storage = (struct dbox_storage *)_storage;
	const char *dir;

	storage->set = mail_storage_get_driver_settings(_storage);
	i_assert(storage->set->dbox_max_open_files >= 2);

	if (*ns->list->set.mailbox_dir_name == '\0') {
		*error_r = "dbox: MAILBOXDIR must not be empty";
		return -1;
	}

	_storage->unique_root_dir =
		p_strdup(_storage->pool, ns->list->set.root_dir);

	dir = mailbox_list_get_path(ns->list, NULL, MAILBOX_LIST_PATH_TYPE_DIR);
	storage->storage_dir = p_strconcat(_storage->pool, dir,
					   "/"DBOX_GLOBAL_DIR_NAME, NULL);
	storage->alt_storage_dir = p_strconcat(_storage->pool,
					       ns->list->set.alt_dir,
					       "/"DBOX_GLOBAL_DIR_NAME, NULL);
	i_array_init(&storage->open_files,
		     I_MIN(storage->set->dbox_max_open_files, 128));

	storage->map = dbox_map_init(storage);
	mailbox_list_get_dir_permissions(ns->list, NULL, &storage->create_mode,
					 &storage->create_gid);
	return 0;
}

static void dbox_storage_destroy(struct mail_storage *_storage)
{
	struct dbox_storage *storage = (struct dbox_storage *)_storage;

	if (storage->sync_rebuild) {
		if (dbox_storage_rebuild(storage) < 0)
			return;
	}

	dbox_files_free(storage);
	dbox_map_deinit(&storage->map);
	array_free(&storage->open_files);
	index_storage_destroy(_storage);
}

static void
dbox_storage_get_list_settings(const struct mail_namespace *ns ATTR_UNUSED,
			       struct mailbox_list_settings *set)
{
	if (set->layout == NULL)
		set->layout = MAILBOX_LIST_NAME_FS;
	if (set->subscription_fname == NULL)
		set->subscription_fname = DBOX_SUBSCRIPTION_FILE_NAME;
	if (set->maildir_name == NULL)
		set->maildir_name = DBOX_MAILDIR_NAME;
	if (set->mailbox_dir_name == NULL)
		set->mailbox_dir_name = DBOX_MAILBOX_DIR_NAME;
}

static const char *
dbox_get_alt_path(struct mailbox_list *list, const char *path)
{
#if 0 // FIXME
	const char *root;
	unsigned int len;

	if (storage->alt_dir == NULL)
		return NULL;

	root = mailbox_list_get_path(storage->storage.list, NULL,
				     MAILBOX_LIST_PATH_TYPE_DIR);

	len = strlen(root);
	if (strncmp(path, root, len) != 0 && path[len] == '/') {
		/* can't determine the alt path - shouldn't happen */
		return NULL;
	}
	return t_strconcat(storage->alt_dir, path + len, NULL);
#endif
	return NULL;
}

static struct mailbox *
dbox_open(struct dbox_storage *storage, struct mailbox_list *list,
	  const char *name, enum mailbox_open_flags flags)
{
	struct mail_storage *_storage = &storage->storage;
	struct dbox_mailbox *mbox;
	struct mailbox *box;
	struct mail_index *index;
	const char *path;
	pool_t pool;
	int ret;

	/* dbox can't work without index files */
	flags &= ~MAILBOX_OPEN_NO_INDEX_FILES;

	path = mailbox_list_get_path(list, name,
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);

	index = index_storage_alloc(list, name, flags, DBOX_INDEX_PREFIX);
	mail_index_set_fsync_types(index, MAIL_INDEX_SYNC_TYPE_APPEND |
				   MAIL_INDEX_SYNC_TYPE_EXPUNGE);

	pool = pool_alloconly_create("dbox mailbox", 1024+512);
	mbox = p_new(pool, struct dbox_mailbox, 1);
	mbox->ibox.box = dbox_mailbox;
	mbox->ibox.box.pool = pool;
	mbox->ibox.box.storage = _storage;
	mbox->ibox.box.list = list;
	mbox->ibox.mail_vfuncs = &dbox_mail_vfuncs;
	mbox->ibox.index = index;
	mbox->ibox.keep_index_backups = TRUE;
	mbox->ibox.index_never_in_memory = TRUE;
	mbox->path = p_strdup(pool, path);
	mbox->alt_path = p_strdup(pool, dbox_get_alt_path(list, path));
	mbox->storage = storage;

	mbox->dbox_ext_id =
		mail_index_ext_register(index, "dbox", 0,
					sizeof(struct dbox_mail_index_record),
					sizeof(uint32_t));
	mbox->dbox_hdr_ext_id =
		mail_index_ext_register(index, "dbox-hdr",
					sizeof(struct dbox_index_header), 0, 0);
	mbox->guid_ext_id =
		mail_index_ext_register(index, "guid", 0, DBOX_GUID_BIN_LEN, 1);

	ret = index_storage_mailbox_init(&mbox->ibox, name, flags, FALSE);
	mbox->maildir_uidlist = maildir_uidlist_init_readonly(&mbox->ibox);

	box = &mbox->ibox.box;
	if (ret < 0)
		mailbox_close(&box);
	return box;
}

uint32_t dbox_get_uidvalidity_next(struct mailbox_list *list)
{
	const char *path;

	path = mailbox_list_get_path(list, NULL,
				     MAILBOX_LIST_PATH_TYPE_CONTROL);
	path = t_strconcat(path, "/"DBOX_UIDVALIDITY_FILE_NAME, NULL);
	return mailbox_uidvalidity_next(path);
}

static void dbox_write_index_header(struct mailbox *box)
{
	struct dbox_mailbox *mbox = (struct dbox_mailbox *)box;
	struct mail_index_transaction *trans;
	struct dbox_index_header hdr;
	uint32_t uid_validity;

	if (dbox_map_open(mbox->storage->map, TRUE) < 0)
		return;

	trans = mail_index_transaction_begin(mbox->ibox.view, 0);

	/* set dbox header */
	memset(&hdr, 0, sizeof(hdr));
	hdr.map_uid_validity = dbox_map_get_uid_validity(mbox->storage->map);
	mail_index_update_header_ext(trans, mbox->dbox_hdr_ext_id, 0,
				     &hdr, sizeof(hdr));

	/* set uidvalidity */
	uid_validity = dbox_get_uidvalidity_next(box->list);
	mail_index_update_header(trans,
		offsetof(struct mail_index_header, uid_validity),
		&uid_validity, sizeof(uid_validity), TRUE);

	(void)mail_index_transaction_commit(&trans);
}

static int create_dbox(struct mail_storage *_storage, struct mailbox_list *list,
		       const char *path, const char *name, bool directory)
{
	struct dbox_storage *storage = (struct dbox_storage *)_storage;
	struct mailbox *box;
	mode_t mode;
	gid_t gid;

	mailbox_list_get_dir_permissions(list, NULL, &mode, &gid);
	if (mkdir_parents_chown(path, mode, (uid_t)-1, gid) == 0) {
		if (!directory) {
			/* create indexes immediately with the dbox header */
			box = dbox_open(storage, list, name,
					MAILBOX_OPEN_KEEP_RECENT);
			if (box == NULL)
				return -1;
			dbox_write_index_header(box);
			mailbox_close(&box);
			return 0;
		}
	} else if (errno != EEXIST) {
		if (!mail_storage_set_error_from_errno(_storage)) {
			mail_storage_set_critical(_storage,
				"mkdir(%s) failed: %m", path);
		}
		return -1;
	}
	return 0;
}

static bool
dbox_cleanup_if_exists(struct mailbox_list *list, const char *path)
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
			mailbox_list_get_global_temp_prefix(list);

		(void)unlink_old_files(path, prefix,
				       ioloop_time - DBOX_TMP_DELETE_SECS);
	}
	return TRUE;
}

struct mailbox *
dbox_mailbox_open(struct mail_storage *_storage, struct mailbox_list *list,
		  const char *name, struct istream *input,
		  enum mailbox_open_flags flags)
{
	struct dbox_storage *storage = (struct dbox_storage *)_storage;
	const char *path;

	if (input != NULL) {
		mailbox_list_set_critical(list,
			"dbox doesn't support streamed mailboxes");
		return NULL;
	}

	path = mailbox_list_get_path(list, name,
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);
	if (dbox_cleanup_if_exists(list, path)) {
		return dbox_open(storage, list, name, flags);
	} else if (errno == ENOENT) {
		if (strcmp(name, "INBOX") == 0 &&
		    (list->ns->flags & NAMESPACE_FLAG_INBOX) != 0) {
			/* INBOX always exists, create it */
			if (create_dbox(_storage, list, path, name, FALSE) < 0) {
				mailbox_list_set_error_from_storage(list,
								    _storage);
				return NULL;
			}
			return dbox_open(storage, list, name, flags);
		}

		mailbox_list_set_error(list, MAIL_ERROR_NOTFOUND,
			T_MAIL_ERR_MAILBOX_NOT_FOUND(name));
	} else if (errno == EACCES) {
		mailbox_list_set_critical(list, "%s",
			mail_error_eacces_msg("stat", path));
	} else {
		mailbox_list_set_critical(list, "stat(%s) failed: %m", path);
	}
	return NULL;
}

static int dbox_storage_mailbox_close(struct mailbox *box)
{
	struct dbox_mailbox *mbox = (struct dbox_mailbox *)box;

	maildir_uidlist_deinit(&mbox->maildir_uidlist);
	return index_storage_mailbox_close(box);
}

static int
dbox_mailbox_create(struct mail_storage *storage, struct mailbox_list *list,
		    const char *name, bool directory)
{
	const char *path, *alt_path;
	struct stat st;

	path = mailbox_list_get_path(list, name,
				     directory ? MAILBOX_LIST_PATH_TYPE_DIR :
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);
	if (stat(path, &st) == 0) {
		mail_storage_set_error(storage, MAIL_ERROR_EXISTS,
				       "Mailbox already exists");
		return -1;
	}

	/* make sure the alt path doesn't exist yet. it shouldn't (except with
	   race conditions with RENAME/DELETE), but if something crashed and
	   left it lying around we don't want to start overwriting files in
	   it. */
	alt_path = directory ? NULL : dbox_get_alt_path(list, path);
	if (alt_path != NULL && stat(alt_path, &st) == 0) {
		mail_storage_set_error(storage, MAIL_ERROR_EXISTS,
				       "Mailbox already exists");
		return -1;
	}

	return create_dbox(storage, list, path, name, directory);
}

static int
dbox_mailbox_unref_mails(struct mailbox_list *list, const char *path)
{
	struct dbox_storage *storage = (struct dbox_storage *)list->ns->storage;
	const struct mail_storage_settings *old_set;
	struct mail_storage_settings tmp_set;
	struct mailbox *box;
	struct dbox_mailbox *mbox;
	const struct mail_index_header *hdr;
	const struct dbox_mail_index_record *dbox_rec;
	struct dbox_map_transaction_context *map_trans;
	ARRAY_TYPE(uint32_t) map_uids;
	const void *data;
	bool expunged;
	uint32_t seq;
	int ret;

	old_set = list->mail_set;
	tmp_set = *list->mail_set;
	tmp_set.mail_full_filesystem_access = TRUE;
	list->mail_set = &tmp_set;
	box = dbox_open(storage, list, path, MAILBOX_OPEN_IGNORE_ACLS |
			MAILBOX_OPEN_KEEP_RECENT);
	list->mail_set = old_set;
	if (box == NULL)
		return -1;
	mbox = (struct dbox_mailbox *)box;

	/* get a list of all map_uids in this mailbox */
	i_array_init(&map_uids, 128);
	hdr = mail_index_get_header(mbox->ibox.view);
	for (seq = 1; seq <= hdr->messages_count; seq++) {
		mail_index_lookup_ext(mbox->ibox.view, seq, mbox->dbox_ext_id,
				      &data, &expunged);
		dbox_rec = data;
		if (dbox_rec == NULL) {
			/* no multi-mails */
			break;
		}
		if (dbox_rec->map_uid != 0)
			array_append(&map_uids, &dbox_rec->map_uid, 1);
	}

	/* unreference the map_uids */
	map_trans = dbox_map_transaction_begin(storage->map, FALSE);
	ret = dbox_map_update_refcounts(map_trans, &map_uids, -1);
	if (ret == 0)
		ret = dbox_map_transaction_commit(map_trans);
	dbox_map_transaction_free(&map_trans);
	array_free(&map_uids);
	mailbox_close(&box);
	return ret;
}

static const char *dbox_get_trash_dest(const char *trash_dir)
{
	const char *path;
	unsigned char randbuf[16];
	struct stat st;

	do {
		random_fill_weak(randbuf, sizeof(randbuf));
		path = t_strconcat(trash_dir, "/",
			binary_to_hex(randbuf, sizeof(randbuf)), NULL);
	} while (lstat(path, &st) == 0);
	return path;
}

static int
dbox_list_delete_mailbox(struct mailbox_list *list, const char *name)
{
	struct dbox_mailbox_list *mlist = DBOX_LIST_CONTEXT(list);
	struct stat st;
	const char *path, *alt_path, *trash_dir, *trash_dest;
	bool deleted = FALSE;
	int ret;

	/* Make sure the indexes are closed before trying to delete the
	   directory that contains them. It can still fail with some NFS
	   implementations if indexes are opened by another session, but
	   that can't really be helped. */
	index_storage_destroy_unrefed();

	/* delete the index and control directories */
	if (mlist->module_ctx.super.delete_mailbox(list, name) < 0)
		return -1;

	path = mailbox_list_get_path(list, name,
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);
	trash_dir = mailbox_list_get_path(list, NULL,
					  MAILBOX_LIST_PATH_TYPE_DIR);
	trash_dir = t_strconcat(trash_dir, "/"DBOX_TRASH_DIR_NAME, NULL);
	trash_dest = dbox_get_trash_dest(trash_dir);

	/* first try renaming the actual mailbox to trash directory */
	ret = rename(path, trash_dest);
	if (ret < 0 && errno == ENOENT) {
		/* either source mailbox doesn't exist or trash directory
		   doesn't exist. try creating the trash and retrying. */
		mode_t mode;
		gid_t gid;

		mailbox_list_get_dir_permissions(list, NULL, &mode, &gid);
		if (mkdir_parents_chown(trash_dir, mode, (uid_t)-1, gid) < 0 &&
		    errno != EEXIST) {
			mailbox_list_set_critical(list,
				"mkdir(%s) failed: %m", trash_dir);
			return -1;
		}
		ret = rename(path, trash_dest);
	}
	if (ret == 0) {
		if (dbox_mailbox_unref_mails(list, trash_dest) < 0) {
			/* we've already renamed it. there's no going back. */
			mailbox_list_set_internal_error(list);
			ret = -1;
		}
		if (unlink_directory(trash_dest, TRUE) < 0) {
			mailbox_list_set_critical(list,
				"unlink_directory(%s) failed: %m", trash_dest);
			ret = -1;
		}
		/* if there's an alt path, delete it too */
		alt_path = dbox_get_alt_path(list, path);
		if (alt_path != NULL) {
			if (unlink_directory(alt_path, TRUE) < 0) {
				mailbox_list_set_critical(list,
					"unlink_directory(%s) failed: %m", alt_path);
				ret = -1;
			}
		}
		/* try to delete the parent directory also */
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
		ret = 0;
	}

	alt_path = dbox_get_alt_path(list, path);
	if (alt_path != NULL)
		(void)rmdir(alt_path);

	if (rmdir(path) == 0)
		return ret;
	else if (errno == ENOTEMPTY) {
		if (deleted)
			return ret;
		mailbox_list_set_error(list, MAIL_ERROR_NOTFOUND,
			t_strdup_printf("Directory %s isn't empty, "
					"can't delete it.", name));
	} else if (!mailbox_list_set_error_from_errno(list)) {
		mailbox_list_set_critical(list, "rmdir() failed for %s: %m",
					  path);
	}
	return -1;
}

static int
dbox_list_rename_get_alt_paths(struct mailbox_list *oldlist,
			       const char *oldname,
			       struct mailbox_list *newlist,
			       const char *newname,
			       enum mailbox_list_path_type path_type,
			       const char **oldpath_r, const char **newpath_r)
{
	const char *path;

	path = mailbox_list_get_path(oldlist, oldname, path_type);
	*oldpath_r = dbox_get_alt_path(oldlist, path);
	if (*oldpath_r == NULL)
		return 0;

	path = mailbox_list_get_path(newlist, newname, path_type);
	*newpath_r = dbox_get_alt_path(newlist, path);
	if (*newpath_r == NULL) {
		/* destination dbox storage doesn't have alt-path defined.
		   we can't do the rename easily. */
		mailbox_list_set_error(oldlist, MAIL_ERROR_NOTPOSSIBLE,
			"Can't rename mailboxes across specified storages.");
		return -1;
	}
	return 1;
}

static int
dbox_list_rename_mailbox_pre(struct mailbox_list *oldlist,
			     const char *oldname,
			     struct mailbox_list *newlist,
			     const char *newname)
{
	const char *alt_oldpath, *alt_newpath;
	struct stat st;
	int ret;

	ret = dbox_list_rename_get_alt_paths(oldlist, oldname, newlist, newname,
					     MAILBOX_LIST_PATH_TYPE_DIR,
					     &alt_oldpath, &alt_newpath);
	if (ret <= 0)
		return ret;

	if (stat(alt_newpath, &st) == 0) {
		/* race condition or a directory left there lying around?
		   safest to just report error. */
		mailbox_list_set_error(oldlist, MAIL_ERROR_EXISTS,
				       "Target mailbox already exists");
		return -1;
	} else if (errno != ENOENT) {
		mailbox_list_set_critical(oldlist, "stat(%s) failed: %m",
					  alt_newpath);
		return -1;
	}
	return 0;
}

static int
dbox_list_rename_mailbox(struct mailbox_list *oldlist, const char *oldname,
			 struct mailbox_list *newlist, const char *newname,
			 bool rename_children)
{
	struct dbox_mailbox_list *oldmlist = DBOX_LIST_CONTEXT(oldlist);
	enum mailbox_list_path_type path_type;
	const char *alt_oldpath, *alt_newpath, *path;
	int ret;

	ret = oldmlist->module_ctx.super.
		rename_mailbox(oldlist, oldname, newlist, newname,
			       rename_children);
	if (ret < 0)
		return -1;

	path_type = rename_children ? MAILBOX_LIST_PATH_TYPE_DIR :
		MAILBOX_LIST_PATH_TYPE_MAILBOX;
	ret = dbox_list_rename_get_alt_paths(oldlist, oldname, newlist, newname,
					     path_type, &alt_oldpath,
					     &alt_newpath);
	if (ret <= 0)
		return ret;

	if (rename(alt_oldpath, alt_newpath) == 0) {
		/* ok */
		if (!rename_children) {
			path = mailbox_list_get_path(oldlist, oldname,
						     MAILBOX_LIST_PATH_TYPE_DIR);
			if (rmdir(path) < 0 &&
			    errno != ENOENT && errno != ENOTEMPTY) {
				mailbox_list_set_critical(oldlist,
					"rmdir(%s) failed: %m", path);
			}
		}
	} else if (errno != ENOENT) {
		/* renaming is done already, so just log the error */
		mailbox_list_set_critical(oldlist, "rename(%s, %s) failed: %m",
					  alt_oldpath, alt_newpath);
	}
	return 0;
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
				     const char *mailbox_name ATTR_UNUSED,
				     enum mailbox_list_file_type type,
				     enum mailbox_info_flags *flags)
{
	const char *path, *maildir_path;
	struct stat st, st2;
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
	path = t_strconcat(dir, "/", fname, NULL);
	if (stat(path, &st) == 0) {
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
	} else if (errno == ENOENT) {
		/* doesn't exist - probably a non-existing subscribed mailbox */
		*flags |= MAILBOX_NONEXISTENT;
	} else {
		/* non-selectable. probably either access denied, or symlink
		   destination not found. don't bother logging errors. */
		*flags |= MAILBOX_NOSELECT;
	}
	if ((*flags & (MAILBOX_NOSELECT | MAILBOX_NONEXISTENT)) == 0) {
		/* make sure it's a selectable mailbox */
		maildir_path = t_strconcat(path, "/"DBOX_MAILDIR_NAME, NULL);
		if (stat(maildir_path, &st2) < 0 || !S_ISDIR(st2.st_mode))
			*flags |= MAILBOX_NOSELECT;
		if (st.st_nlink == 3 && *ctx->list->set.maildir_name != '\0') {
			/* now we know what link count 3 means. */
			if ((*flags & MAILBOX_NOSELECT) != 0)
				*flags |= MAILBOX_CHILDREN;
			else
				*flags |= MAILBOX_NOCHILDREN;
		}
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

static void dbox_storage_add_list(struct mail_storage *storage,
				  struct mailbox_list *list)
{
	struct dbox_mailbox_list *mlist;

	mlist = p_new(list->pool, struct dbox_mailbox_list, 1);
	mlist->module_ctx.super = list->v;
	mlist->set = mail_storage_get_driver_settings(storage);

	list->v.iter_is_mailbox = dbox_list_iter_is_mailbox;
	list->v.delete_mailbox = dbox_list_delete_mailbox;
	list->v.rename_mailbox = dbox_list_rename_mailbox;
	list->v.rename_mailbox_pre = dbox_list_rename_mailbox_pre;

	MODULE_CONTEXT_SET(list, dbox_mailbox_list_module, mlist);
}

struct mail_storage dbox_storage = {
	MEMBER(name) DBOX_STORAGE_NAME,
	MEMBER(class_flags) MAIL_STORAGE_CLASS_FLAG_UNIQUE_ROOT, /* FIXME: for multi-dbox only.. */

	{
                dbox_get_setting_parser_info,
		dbox_class_init,
		dbox_class_deinit,
		dbox_storage_alloc,
		dbox_storage_create,
		dbox_storage_destroy,
		dbox_storage_add_list,
		dbox_storage_get_list_settings,
		NULL,
		dbox_mailbox_open,
		dbox_mailbox_create,
		dbox_sync_purge
	}
};

struct mailbox dbox_mailbox = {
	MEMBER(name) NULL, 
	MEMBER(storage) NULL, 
	MEMBER(list) NULL,

	{
		index_storage_is_readonly,
		index_storage_allow_new_keywords,
		index_storage_mailbox_enable,
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
		index_transaction_set_max_modseq,
		index_keywords_create,
		index_keywords_free,
		index_keyword_is_valid,
		index_storage_get_seq_range,
		index_storage_get_uid_range,
		index_storage_get_expunged_uids,
		NULL,
		NULL,
		NULL,
		dbox_mail_alloc,
		index_header_lookup_init,
		index_header_lookup_ref,
		index_header_lookup_unref,
		index_storage_search_init,
		index_storage_search_deinit,
		index_storage_search_next_nonblock,
		index_storage_search_next_update_seq,
		dbox_save_alloc,
		dbox_save_begin,
		dbox_save_continue,
		dbox_save_finish,
		dbox_save_cancel,
		dbox_copy,
		index_storage_is_inconsistent
	}
};
