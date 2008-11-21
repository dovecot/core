/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "hostpid.h"
#include "str.h"
#include "mkdir-parents.h"
#include "unlink-directory.h"
#include "unlink-old-files.h"
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

#define MAILDIR_PLUSPLUS_DRIVER_NAME "maildir++"
#define MAILDIR_SUBFOLDER_FILENAME "maildirfolder"

#define MAILDIR_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, maildir_mailbox_list_module)

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

static int
maildir_list_delete_mailbox(struct mailbox_list *list, const char *name);
static int
maildir_list_rename_mailbox(struct mailbox_list *list,
			    const char *oldname, const char *newname);
static int
maildir_list_iter_is_mailbox(struct mailbox_list_iterate_context *ctx,
			     const char *dir, const char *fname,
			     const char *mailbox_name,
			     enum mailbox_list_file_type type,
			     enum mailbox_info_flags *flags_r);
static int
maildirplusplus_iter_is_mailbox(struct mailbox_list_iterate_context *ctx,
				const char *dir, const char *fname,
				const char *mailbox_name,
				enum mailbox_list_file_type type,
				enum mailbox_info_flags *flags_r);

static int
maildir_get_list_settings(struct mailbox_list_settings *list_set,
			  const char *data, struct mail_storage *storage,
			  const char **layout_r, const char **error_r)
{
	enum mail_storage_flags flags = storage->flags;
	struct mail_user *user = storage->ns->user;
	bool debug = (flags & MAIL_STORAGE_FLAG_DEBUG) != 0;
	const char *path, *home;

	*layout_r = MAILDIR_PLUSPLUS_DRIVER_NAME;

	memset(list_set, 0, sizeof(*list_set));
	list_set->subscription_fname = MAILDIR_SUBSCRIPTION_FILE_NAME;
	list_set->maildir_name = "";

	if (data == NULL || *data == '\0') {
		if ((flags & MAIL_STORAGE_FLAG_NO_AUTODETECTION) != 0) {
			*error_r = "Root mail directory not given";
			return -1;
		}

		/* we'll need to figure out the maildir location ourself.
		   It's ~/Maildir unless we are chrooted. */
		if (mail_user_get_home(user, &home) > 0) {
			path = t_strconcat(home, "/Maildir", NULL);
			if (access(path, R_OK|W_OK|X_OK) == 0) {
				if (debug) {
					i_info("maildir: root exists (%s)",
					       path);
				}
				list_set->root_dir = path;
			} else {
				if (debug) {
					i_info("maildir: access(%s, rwx): "
					       "failed: %m", path);
				}
			}
		} else {
			if (debug)
				i_info("maildir: Home directory not set");
		}

		if (access("/cur", R_OK|W_OK|X_OK) == 0) {
			if (debug)
				i_info("maildir: /cur exists, assuming chroot");
			list_set->root_dir = "/";
		}
	} else {
		if (debug)
			i_info("maildir: data=%s", data);
		if (mailbox_list_settings_parse(data, list_set, storage->ns,
						layout_r, NULL, error_r) < 0)
			return -1;
	}

	if (list_set->root_dir == NULL || *list_set->root_dir == '\0') {
		if (debug)
			i_info("maildir: couldn't find root dir");
		*error_r = "Root mail directory not given";
		return -1;
	}
	return 0;
}

static bool maildir_is_internal_name(const char *name)
{
	return strcmp(name, "cur") == 0 ||
		strcmp(name, "new") == 0 ||
		strcmp(name, "tmp") == 0;
}

static bool maildir_storage_is_valid_existing_name(struct mailbox_list *list,
						   const char *name)
{
	struct maildir_storage *storage = MAILDIR_LIST_CONTEXT(list);
	const char *p;

	if (!storage->list_module_ctx.super.is_valid_existing_name(list, name))
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
	struct maildir_storage *storage = MAILDIR_LIST_CONTEXT(list);
	bool ret = TRUE;

	if (!storage->list_module_ctx.super.is_valid_create_name(list, name))
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

static struct mail_storage *maildir_alloc(void)
{
	struct maildir_storage *storage;
	pool_t pool;

	pool = pool_alloconly_create("maildir storage", 512+256);
	storage = p_new(pool, struct maildir_storage, 1);
	storage->storage = maildir_storage;
	storage->storage.pool = pool;
	storage->storage.storage_class = &maildir_storage;

	return &storage->storage;
}

static int
maildir_create(struct mail_storage *_storage, const char *data,
	       const char **error_r)
{
	struct maildir_storage *storage = (struct maildir_storage *)_storage;
	enum mail_storage_flags flags = _storage->flags;
	struct mailbox_list_settings list_set;
	struct mailbox_list *list;
	const char *layout;
	struct stat st;

	if (maildir_get_list_settings(&list_set, data, _storage, &layout,
				      error_r) < 0)
		return -1;
	list_set.mail_storage_flags = &_storage->flags;
	list_set.lock_method = &_storage->lock_method;

	if (list_set.inbox_path == NULL &&
	    strcmp(layout, MAILDIR_PLUSPLUS_DRIVER_NAME) == 0 &&
	    (_storage->ns->flags & NAMESPACE_FLAG_INBOX) != 0) {
		/* Maildir++ INBOX is the Maildir base itself */
		list_set.inbox_path = list_set.root_dir;
	}

	if ((flags & MAIL_STORAGE_FLAG_NO_AUTOCREATE) != 0) {
		if (stat(list_set.root_dir, &st) == 0) {
			/* ok */
		} else if (errno == EACCES) {
			*error_r = mail_storage_eacces_msg("stat",
							   list_set.root_dir);
			return -1;
		} else if (errno == ENOENT) {
			*error_r = t_strdup_printf(
					"Root mail directory doesn't exist: %s",
					list_set.root_dir);
			return -1;
		} else {
			*error_r = t_strdup_printf("stat(%s) failed: %m",
						   list_set.root_dir);
			return -1;
		}
	}

	if (mailbox_list_alloc(layout, &list, error_r) < 0)
		return -1;

	_storage->list = list;
	storage->list_module_ctx.super = list->v;
	if (strcmp(layout, MAILDIR_PLUSPLUS_DRIVER_NAME) == 0) {
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
	storage->maildir_list_ext_id = (uint32_t)-1;

	MODULE_CONTEXT_SET_FULL(list, maildir_mailbox_list_module,
				storage, &storage->list_module_ctx);

	/* finish list init after we've overridden vfuncs */
	mailbox_list_init(list, _storage->ns, &list_set,
			  mail_storage_get_list_flags(flags));

	storage->copy_with_hardlinks =
		getenv("MAILDIR_COPY_WITH_HARDLINKS") != NULL;
	storage->copy_preserve_filename =
		getenv("MAILDIR_COPY_PRESERVE_FILENAME") != NULL;
	storage->stat_dirs = getenv("MAILDIR_STAT_DIRS") != NULL;

	storage->temp_prefix = mailbox_list_get_temp_prefix(list);
	if (list_set.control_dir == NULL) {
		/* put the temp files into tmp/ directory preferrably */
		storage->temp_prefix =
			p_strconcat(_storage->pool,
				    "tmp/", storage->temp_prefix, NULL);
	}
	return 0;
}

static bool maildir_autodetect(const char *data, enum mail_storage_flags flags)
{
	bool debug = (flags & MAIL_STORAGE_FLAG_DEBUG) != 0;
	struct stat st;
	const char *path;

	data = t_strcut(data, ':');

	path = t_strconcat(data, "/cur", NULL);
	if (stat(path, &st) < 0) {
		if (debug)
			i_info("maildir autodetect: stat(%s) failed: %m", path);
		return FALSE;
	}

	if (!S_ISDIR(st.st_mode)) {
		if (debug)
			i_info("maildir autodetect: %s not a directory", path);
		return FALSE;
	}
	return TRUE;
}

static int mkdir_verify(struct mail_storage *storage,
			const char *dir, mode_t mode, gid_t gid, bool verify)
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

	if (mkdir_parents_chown(dir, mode, (uid_t)-1, gid) == 0)
		return 0;

	if (errno == EEXIST) {
		if (verify)
			return 0;
		mail_storage_set_error(storage, MAIL_ERROR_EXISTS,
				       "Mailbox already exists");
	} else if (errno == ENOENT) {
		mail_storage_set_error(storage, MAIL_ERROR_NOTFOUND,
			"Mailbox was deleted while it was being created");
	} else if (errno == EACCES && storage->ns->type == NAMESPACE_SHARED) {
		/* shared namespace, don't log permission errors */
		mail_storage_set_error(storage, MAIL_ERROR_PERM,
				       MAIL_ERRSTR_NO_PERMISSION);
		return -1;
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
				mail_storage_eacces_msg("stat", path));
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
static int create_maildir(struct mail_storage *storage,
			  const char *dir, mode_t mode, gid_t gid, bool verify)
{
	const char *path;
	unsigned int i;
	int ret;

	ret = maildir_check_tmp(storage, dir);
	if (ret > 0) {
		if (!verify) {
			mail_storage_set_error(storage, MAIL_ERROR_EXISTS,
					       "Mailbox already exists");
			return -1;
		}
		return 1;
	}
	if (ret < 0)
		return -1;

	/* doesn't exist, create */
	for (i = 0; i < N_ELEMENTS(maildir_subdirs); i++) {
		path = t_strconcat(dir, "/", maildir_subdirs[i], NULL);
		if (mkdir_verify(storage, path, mode, gid, verify) < 0)
			return -1;
	}
	return 0;
}

static void maildir_lock_touch_timeout(struct maildir_mailbox *mbox)
{
	(void)maildir_uidlist_lock_touch(mbox->uidlist);
}

static mode_t get_dir_mode(mode_t mode)
{
	/* add the execute bit if either read or write bit is set */
	if ((mode & 0600) != 0) mode |= 0100;
	if ((mode & 0060) != 0) mode |= 0010;
	if ((mode & 0006) != 0) mode |= 0001;
	return mode;
}

static struct mailbox *
maildir_open(struct maildir_storage *storage, const char *name,
	     enum mailbox_open_flags flags)
{
	struct maildir_mailbox *mbox;
	struct mail_index *index;
	const char *path, *control_dir;
	struct stat st;
	pool_t pool;

	path = mailbox_list_get_path(storage->storage.list, name,
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);
	control_dir = mailbox_list_get_path(storage->storage.list, name,
					    MAILBOX_LIST_PATH_TYPE_CONTROL);

	pool = pool_alloconly_create("maildir mailbox", 1024+512);
	mbox = p_new(pool, struct maildir_mailbox, 1);
	mbox->ibox.box = maildir_mailbox;
	mbox->ibox.box.pool = pool;
	mbox->ibox.storage = &storage->storage;
	mbox->ibox.mail_vfuncs = &maildir_mail_vfuncs;

	mbox->storage = storage;
	mbox->path = p_strdup(pool, path);

	index = index_storage_alloc(&storage->storage, name, flags,
				    MAILDIR_INDEX_PREFIX);
	mbox->ibox.index = index;

	/* for shared mailboxes get the create mode from the
	   permissions of dovecot-shared file. */
	if (stat(t_strconcat(path, "/dovecot-shared", NULL), &st) == 0) {
		if ((st.st_mode & S_ISGID) != 0 ||
		    (st.st_mode & 0060) == 0) {
			/* Ignore GID */
			st.st_gid = (gid_t)-1;
		}
		mail_index_set_permissions(index, st.st_mode & 0666, st.st_gid);

		mbox->ibox.box.file_create_mode = st.st_mode & 0666;
		mbox->ibox.box.dir_create_mode =
			get_dir_mode(st.st_mode & 0666);
		mbox->ibox.box.file_create_gid = st.st_gid;
		mbox->ibox.box.private_flags_mask = MAIL_SEEN;
	}

	mbox->maildir_ext_id =
		mail_index_ext_register(index, "maildir",
					sizeof(mbox->maildir_hdr), 0, 0);

	index_storage_mailbox_init(&mbox->ibox, name, flags, FALSE);
	mbox->uidlist = maildir_uidlist_init(mbox);
	if ((flags & MAILBOX_OPEN_KEEP_LOCKED) != 0) {
		if (maildir_uidlist_lock(mbox->uidlist) <= 0) {
			struct mailbox *box = &mbox->ibox.box;

			mailbox_close(&box);
			return NULL;
		}
		mbox->keep_lock_to = timeout_add(MAILDIR_LOCK_TOUCH_SECS * 1000,
						 maildir_lock_touch_timeout,
						 mbox);
	}

	if (access(t_strconcat(path, "/cur", NULL), W_OK) < 0 &&
	    errno == EACCES)
		mbox->ibox.readonly = TRUE;

	mbox->keywords = maildir_keywords_init(mbox);
	return &mbox->ibox.box;
}

static struct mailbox *
maildir_mailbox_open(struct mail_storage *_storage, const char *name,
		     struct istream *input, enum mailbox_open_flags flags)
{
	struct maildir_storage *storage = (struct maildir_storage *)_storage;
	const char *path;
	struct stat st;
	mode_t mode;
	gid_t gid;
	int ret;

	if (input != NULL) {
		mail_storage_set_critical(_storage,
			"Maildir doesn't support streamed mailboxes");
		return NULL;
	}

	path = mailbox_list_get_path(_storage->list, name,
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);

	if (strcmp(name, "INBOX") == 0 &&
	    (_storage->ns->flags & NAMESPACE_FLAG_INBOX) != 0) {
		/* INBOX always exists */
		mailbox_list_get_dir_permissions(_storage->list, &mode, &gid);
		if (create_maildir(_storage, path, mode, gid, TRUE) < 0)
			return NULL;
		return maildir_open(storage, "INBOX", flags);
	}

	/* begin by checking if tmp/ directory exists and if it should be
	   cleaned up. */
	ret = maildir_check_tmp(_storage, path);
	if (ret > 0) {
		/* exists */
		return maildir_open(storage, name, flags);
	}
	if (ret < 0)
		return NULL;

	/* tmp/ directory doesn't exist. does the maildir? */
	if (stat(path, &st) == 0) {
		/* yes, we'll need to create the missing dirs */
		mailbox_list_get_dir_permissions(_storage->list, &mode, &gid);
		if (create_maildir(_storage, path, mode, gid, TRUE) < 0)
			return NULL;

		return maildir_open(storage, name, flags);
	} else if (errno == ENOENT) {
		mail_storage_set_error(_storage, MAIL_ERROR_NOTFOUND,
			T_MAIL_ERR_MAILBOX_NOT_FOUND(name));
		return NULL;
	} else {
		mail_storage_set_critical(_storage, "stat(%s) failed: %m",
					  path);
		return NULL;
	}
}

static int maildir_create_shared(struct mail_storage *storage,
				 const char *dir, mode_t mode, gid_t gid)
{
	const char *path;
	mode_t old_mask;
	int fd;

	/* add the execute bit if either read or write bit is set */
	if ((mode & 0600) != 0) mode |= 0100;
	if ((mode & 0060) != 0) mode |= 0010;
	if ((mode & 0006) != 0) mode |= 0001;

	if (create_maildir(storage, dir, mode, gid, FALSE) < 0)
		return -1;

	old_mask = umask(0777 ^ mode);
	path = t_strconcat(dir, "/dovecot-shared", NULL);
	fd = open(path, O_WRONLY | O_CREAT, mode & 0666);
	umask(old_mask);

	if (fd == -1) {
		mail_storage_set_critical(storage, "open(%s) failed: %m", path);
		return -1;
	}

	if (fchown(fd, (uid_t)-1, gid) < 0) {
		mail_storage_set_critical(storage,
					  "fchown(%s) failed: %m", path);
	}
	(void)close(fd);
	return 0;
}

static int maildir_mailbox_create(struct mail_storage *_storage,
				  const char *name,
				  bool directory ATTR_UNUSED)
{
	struct stat st;
	const char *path, *root_dir, *shared_path;
	mode_t old_mask;
	int fd;

	path = mailbox_list_get_path(_storage->list, name,
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);
	root_dir = mailbox_list_get_path(_storage->list, NULL,
					 MAILBOX_LIST_PATH_TYPE_MAILBOX);

	/* if dovecot-shared exists in the root dir, create the mailbox using
	   its permissions and gid, and copy the dovecot-shared inside it. */
	shared_path = t_strconcat(root_dir, "/dovecot-shared", NULL);
	if (stat(shared_path, &st) == 0) {
		if (maildir_create_shared(_storage, path,
					  st.st_mode & 0666, st.st_gid) < 0)
			return -1;
	} else {
		mailbox_list_get_dir_permissions(_storage->list,
						 &st.st_mode, &st.st_gid);
		if (create_maildir(_storage, path, st.st_mode, st.st_gid,
				   FALSE) < 0)
			return -1;
	}

	/* Maildir++ spec want that maildirfolder named file is created for
	   all subfolders. */
	path = t_strconcat(path, "/" MAILDIR_SUBFOLDER_FILENAME, NULL);
	old_mask = umask(0777 ^ (st.st_mode & 0666));
	fd = open(path, O_CREAT | O_WRONLY, 0666);
	umask(old_mask);
	if (fd != -1) {
		/* if dovecot-shared exists, use the same group */
		if (st.st_gid != (gid_t)-1 &&
		    fchown(fd, (uid_t)-1, st.st_gid) < 0) {
			mail_storage_set_critical(_storage,
				"fchown(%s) failed: %m", path);
		}
		(void)close(fd);
	} else if (errno == ENOENT) {
		mail_storage_set_error(_storage, MAIL_ERROR_NOTFOUND,
			"Mailbox was deleted while it was being created");
		return -1;
	} else {
		mail_storage_set_critical(_storage,
			"open(%s, O_CREAT) failed: %m", path);
	}
	return 0;
}

static const char *
maildir_get_unlink_dest(struct mailbox_list *list, const char *name)
{
	const char *root_dir;
	char sep;

	if ((list->flags & MAILBOX_LIST_FLAG_FULL_FS_ACCESS) != 0 &&
	    (*name == '/' || *name == '~'))
		return NULL;

	if (strcmp(mailbox_list_get_driver_name(list),
		   MAILDIR_PLUSPLUS_DRIVER_NAME) != 0) {
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
maildir_list_delete_mailbox(struct mailbox_list *list, const char *name)
{
	struct maildir_storage *storage = MAILDIR_LIST_CONTEXT(list);
	struct stat st;
	const char *src, *dest, *base;
	int count;

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
		return maildir_delete_nonrecursive(list, src, name);
	}

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

static int maildir_list_rename_mailbox(struct mailbox_list *list,
				       const char *oldname, const char *newname)
{
	struct maildir_storage *storage = MAILDIR_LIST_CONTEXT(list);
	const char *path1, *path2;

	if (strcmp(oldname, "INBOX") == 0) {
		/* INBOX often exists as the root ~/Maildir.
		   We can't rename it then. */
		path1 = mailbox_list_get_path(list, oldname,
					      MAILBOX_LIST_PATH_TYPE_MAILBOX);
		path2 = mailbox_list_get_path(list, NULL,
					      MAILBOX_LIST_PATH_TYPE_MAILBOX);
		if (strcmp(path1, path2) == 0) {
			mailbox_list_set_error(list, MAIL_ERROR_NOTPOSSIBLE,
				"Renaming INBOX isn't supported.");
			return -1;
		}
	}

	return storage->list_module_ctx.super.
		rename_mailbox(list, oldname, newname);
}

static int maildir_storage_mailbox_close(struct mailbox *box)
{
	struct maildir_mailbox *mbox = (struct maildir_mailbox *)box;

	if (mbox->keep_lock_to != NULL) {
		maildir_uidlist_unlock(mbox->uidlist);
		timeout_remove(&mbox->keep_lock_to);
	}

	if (mbox->keywords != NULL)
		maildir_keywords_deinit(&mbox->keywords);
	maildir_uidlist_deinit(&mbox->uidlist);
	return index_storage_mailbox_close(box);
}

static void maildir_notify_changes(struct mailbox *box)
{
	struct maildir_mailbox *mbox = (struct maildir_mailbox *)box;

	if (box->notify_callback == NULL)
		index_mailbox_check_remove_all(&mbox->ibox);
	else {
		index_mailbox_check_add(&mbox->ibox,
					t_strconcat(mbox->path, "/new", NULL));
		index_mailbox_check_add(&mbox->ibox,
					t_strconcat(mbox->path, "/cur", NULL));
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
	return 1;
}

static int
maildirplusplus_iter_is_mailbox(struct mailbox_list_iterate_context *ctx,
				const char *dir, const char *fname,
				const char *mailbox_name ATTR_UNUSED,
				enum mailbox_list_file_type type,
				enum mailbox_info_flags *flags)
{
	struct maildir_storage *storage = MAILDIR_LIST_CONTEXT(ctx->list);
	struct mail_storage *_storage = &storage->storage;
	int ret;

	if (fname[1] == mailbox_list_get_hierarchy_sep(_storage->list) &&
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
	if (storage->stat_dirs || *fname == '\0' ||
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

uint32_t maildir_get_uidvalidity_next(struct mail_storage *storage)
{
	const char *path;

	path = mailbox_list_get_path(storage->list, NULL,
				     MAILBOX_LIST_PATH_TYPE_CONTROL);
	path = t_strconcat(path, "/"MAILDIR_UIDVALIDITY_FNAME, NULL);
	return mailbox_uidvalidity_next(path);
}

static void maildir_class_init(void)
{
	maildir_transaction_class_init();
}

static void maildir_class_deinit(void)
{
	maildir_transaction_class_deinit();
}

struct mail_storage maildir_storage = {
	MEMBER(name) MAILDIR_STORAGE_NAME,
	MEMBER(mailbox_is_file) FALSE,

	{
		maildir_class_init,
		maildir_class_deinit,
		maildir_alloc,
		maildir_create,
		index_storage_destroy,
		maildir_autodetect,
		maildir_mailbox_open,
		maildir_mailbox_create
	}
};

struct mailbox maildir_mailbox = {
	MEMBER(name) NULL, 
	MEMBER(storage) NULL, 

	{
		index_storage_is_readonly,
		index_storage_allow_new_keywords,
		index_storage_mailbox_enable,
		maildir_storage_mailbox_close,
		index_storage_get_status,
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
		index_keywords_free,
		index_keyword_is_valid,
		index_storage_get_seq_range,
		index_storage_get_uid_range,
		index_storage_get_expunged_uids,
		index_mail_alloc,
		index_header_lookup_init,
		index_header_lookup_ref,
		index_header_lookup_unref,
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
