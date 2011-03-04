/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hostpid.h"
#include "mkdir-parents.h"
#include "mailbox-log.h"
#include "subscription-file.h"
#include "mail-storage.h"
#include "mailbox-list-delete.h"
#include "mailbox-list-fs.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

#define GLOBAL_TEMP_PREFIX ".temp."

extern struct mailbox_list fs_mailbox_list;

static struct mailbox_list *fs_list_alloc(void)
{
	struct fs_mailbox_list *list;
	pool_t pool;

	pool = pool_alloconly_create("fs list", 2048);

	list = p_new(pool, struct fs_mailbox_list, 1);
	list->list = fs_mailbox_list;
	list->list.pool = pool;

	list->temp_prefix = p_strconcat(pool, GLOBAL_TEMP_PREFIX,
					my_hostname, ".", my_pid, ".", NULL);
	return &list->list;
}

static void fs_list_deinit(struct mailbox_list *_list)
{
	struct fs_mailbox_list *list = (struct fs_mailbox_list *)_list;

	pool_unref(&list->list.pool);
}

static bool fs_list_is_valid_common(const char *name, size_t *len_r)
{
	*len_r = strlen(name);

	if (name[0] == '\0' || name[*len_r-1] == '/')
		return FALSE;
	return TRUE;
}

static bool
fs_list_is_valid_common_nonfs(struct mailbox_list *list, const char *name)
{
	bool ret, allow_internal_dirs;

	/* make sure it's not absolute path */
	if (*name == '/' || *name == '~')
		return FALSE;

	/* make sure the mailbox name doesn't contain any foolishness:
	   "../" could give access outside the mailbox directory.
	   "./" and "//" could fool ACL checks. */
	allow_internal_dirs = list->v.is_internal_name == NULL ||
		*list->set.maildir_name != '\0';
	T_BEGIN {
		const char *const *names;

		names = t_strsplit(name, "/");
		for (; *names != NULL; names++) {
			const char *n = *names;

			if (*n == '\0')
				break; /* // */
			if (*n == '.') {
				if (n[1] == '\0')
					break; /* ./ */
				if (n[1] == '.' && n[2] == '\0')
					break; /* ../ */
			}
			if (*list->set.maildir_name != '\0' &&
			    strcmp(list->set.maildir_name, n) == 0) {
				/* don't allow maildir_name to be used as part
				   of the mailbox name */
				break;
			}
			if (!allow_internal_dirs &&
			    list->v.is_internal_name(list, n))
				break;
		}
		ret = *names == NULL;
	} T_END;

	return ret;
}

static bool
fs_is_valid_pattern(struct mailbox_list *list, const char *pattern)
{
	if (list->mail_set->mail_full_filesystem_access)
		return TRUE;

	return fs_list_is_valid_common_nonfs(list, pattern);
}

static bool
fs_is_valid_existing_name(struct mailbox_list *list, const char *name)
{
	size_t len;

	if (!fs_list_is_valid_common(name, &len))
		return FALSE;

	if (list->mail_set->mail_full_filesystem_access)
		return TRUE;

	return fs_list_is_valid_common_nonfs(list, name);
}

static bool
fs_is_valid_create_name(struct mailbox_list *list, const char *name)
{
	size_t len;

	if (!fs_list_is_valid_common(name, &len))
		return FALSE;
	if (len > FS_MAX_CREATE_MAILBOX_NAME_LENGTH)
		return FALSE;

	if (list->mail_set->mail_full_filesystem_access)
		return TRUE;

	if (mailbox_list_name_is_too_large(name, '/'))
		return FALSE;
	return fs_list_is_valid_common_nonfs(list, name);
}

static const char *
fs_list_get_path(struct mailbox_list *_list, const char *name,
		 enum mailbox_list_path_type type)
{
	const struct mailbox_list_settings *set = &_list->set;
	const char *root_dir;

	if (name == NULL) {
		/* return root directories */
		return mailbox_list_get_root_path(set, type);
	}

	i_assert(mailbox_list_is_valid_pattern(_list, name));

	if (mailbox_list_try_get_absolute_path(_list, &name))
		return name;

	root_dir = set->root_dir;
	switch (type) {
	case MAILBOX_LIST_PATH_TYPE_DIR:
		if (*set->maildir_name != '\0')
			return t_strdup_printf("%s/%s%s", set->root_dir,
					       set->mailbox_dir_name, name);
		break;
	case MAILBOX_LIST_PATH_TYPE_ALT_DIR:
		if (set->alt_dir == NULL)
			return NULL;
		if (*set->maildir_name != '\0')
			return t_strdup_printf("%s/%s%s", set->alt_dir,
					       set->mailbox_dir_name, name);
		root_dir = set->alt_dir;
		break;
	case MAILBOX_LIST_PATH_TYPE_MAILBOX:
		break;
	case MAILBOX_LIST_PATH_TYPE_ALT_MAILBOX:
		if (set->alt_dir == NULL)
			return NULL;
		root_dir = set->alt_dir;
		break;
	case MAILBOX_LIST_PATH_TYPE_CONTROL:
		if (set->control_dir != NULL)
			return t_strdup_printf("%s/%s%s", set->control_dir,
					       set->mailbox_dir_name, name);
		break;
	case MAILBOX_LIST_PATH_TYPE_INDEX:
		if (set->index_dir != NULL) {
			if (*set->index_dir == '\0')
				return "";
			return t_strdup_printf("%s/%s%s", set->index_dir,
					       set->mailbox_dir_name, name);
		}
		break;
	}

	if (type == MAILBOX_LIST_PATH_TYPE_ALT_DIR ||
	    type == MAILBOX_LIST_PATH_TYPE_ALT_MAILBOX) {
		/* don't use inbox_path */
	} else if (strcmp(name, "INBOX") == 0 && set->inbox_path != NULL) {
		/* If INBOX is a file, index and control directories are
		   located in root directory. */
		if ((_list->flags & MAILBOX_LIST_FLAG_MAILBOX_FILES) == 0 ||
		    type == MAILBOX_LIST_PATH_TYPE_MAILBOX ||
		    type == MAILBOX_LIST_PATH_TYPE_DIR)
			return set->inbox_path;
	}

	if (*set->maildir_name == '\0') {
		return t_strdup_printf("%s/%s%s", root_dir,
				       set->mailbox_dir_name, name);
	} else {
		return t_strdup_printf("%s/%s%s/%s", root_dir,
				       set->mailbox_dir_name, name,
				       set->maildir_name);
	}
}

static int
fs_list_get_mailbox_name_status(struct mailbox_list *_list, const char *name,
				enum mailbox_name_status *status)
{
	struct stat st;
	const char *path, *dir_path;
	enum mailbox_info_flags flags;

	if (strcmp(name, "INBOX") == 0 &&
	    (_list->ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0) {
		*status = MAILBOX_NAME_EXISTS_MAILBOX;
		return 0;
	}

	path = mailbox_list_get_path(_list, name,
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);
	if (stat(path, &st) == 0) {
		if (*_list->set.maildir_name != '\0' ||
		    _list->v.is_internal_name == NULL || !S_ISDIR(st.st_mode)) {
			*status = MAILBOX_NAME_EXISTS_MAILBOX;
			return 0;
		}

		/* check if mailbox is selectable */
		if (mailbox_list_mailbox(_list, name, &flags) < 0)
			return -1;
		if ((flags & (MAILBOX_NOSELECT | MAILBOX_NONEXISTENT)) == 0)
			*status = MAILBOX_NAME_EXISTS_MAILBOX;
		else
			*status = MAILBOX_NAME_EXISTS_DIR;
		return 0;
	}
	if (errno == ENOENT) {
		/* see if the directory exists */
		dir_path = mailbox_list_get_path(_list, name,
						 MAILBOX_LIST_PATH_TYPE_DIR);
		if (strcmp(path, dir_path) != 0 && stat(dir_path, &st) == 0) {
			*status = MAILBOX_NAME_EXISTS_DIR;
			return 0;
		}
		errno = ENOENT;
	}

	if (!mailbox_list_is_valid_create_name(_list, name)) {
		*status = MAILBOX_NAME_INVALID;
		return 0;
	}

	if (ENOTFOUND(errno) || errno == EACCES) {
		*status = MAILBOX_NAME_VALID;
		return 0;
	} else if (errno == ENOTDIR) {
		*status = MAILBOX_NAME_NOINFERIORS;
		return 0;
	} else {
		mailbox_list_set_critical(_list, "stat(%s) failed: %m", path);
		return -1;
	}
}

static const char *
fs_list_get_temp_prefix(struct mailbox_list *_list, bool global)
{
	struct fs_mailbox_list *list = (struct fs_mailbox_list *)_list;

	return global ? GLOBAL_TEMP_PREFIX : list->temp_prefix;
}

static const char *
fs_list_join_refpattern(struct mailbox_list *_list ATTR_UNUSED,
			const char *ref, const char *pattern)
{
	if (*pattern == '/' || *pattern == '~') {
		/* pattern overrides reference */
	} else if (*ref != '\0') {
		/* merge reference and pattern */
		pattern = t_strconcat(ref, pattern, NULL);
	}
	return pattern;
}

static int fs_list_set_subscribed(struct mailbox_list *_list,
				  const char *name, bool set)
{
	struct fs_mailbox_list *list = (struct fs_mailbox_list *)_list;
	const char *path;

	path = t_strconcat(_list->set.control_dir != NULL ?
			   _list->set.control_dir : _list->set.root_dir,
			   "/", _list->set.subscription_fname, NULL);
	return subsfile_set_subscribed(_list, path, list->temp_prefix,
				       name, set);
}

static int mailbox_is_selectable(struct mailbox_list *list, const char *name)
{
	enum mailbox_info_flags flags;

	if (mailbox_list_mailbox(list, name, &flags) < 0)
		return -1;

	return (flags & (MAILBOX_NOSELECT | MAILBOX_NONEXISTENT)) == 0 ? 1 : 0;
}

static int
fs_list_create_mailbox_dir(struct mailbox_list *list, const char *name,
			   enum mailbox_dir_create_type type)
{
	const char *path, *gid_origin, *p;
	mode_t mode;
	gid_t gid;
	bool directory, create_parent_dir;
	int ret;

	directory = type != MAILBOX_DIR_CREATE_TYPE_MAILBOX;
	path = mailbox_list_get_path(list, name,
				     directory ? MAILBOX_LIST_PATH_TYPE_DIR :
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);
	create_parent_dir = !directory &&
		(list->flags & MAILBOX_LIST_FLAG_MAILBOX_FILES) != 0;
	if (create_parent_dir) {
		/* we only need to make sure that the parent directory exists */
		p = strrchr(path, '/');
		if (p == NULL)
			return 0;
		path = t_strdup_until(path, p);
	}

	mailbox_list_get_dir_permissions(list, NULL, &mode,
					 &gid, &gid_origin);
	if (mkdir_parents_chgrp(path, mode, gid, gid_origin) == 0)
		return 0;
	else if (errno == EEXIST) {
		if (create_parent_dir)
			return 0;
		if (!directory && *list->set.mailbox_dir_name == '\0') {
			if ((ret = mailbox_is_selectable(list, name)) <= 0)
				return ret;
		}
		mailbox_list_set_error(list, MAIL_ERROR_EXISTS,
				       "Mailbox already exists");
	} else if (errno == ENOTDIR) {
		mailbox_list_set_error(list, MAIL_ERROR_NOTPOSSIBLE,
			"Mailbox doesn't allow inferior mailboxes");
	} else if (!mailbox_list_set_error_from_errno(list)) {
		mailbox_list_set_critical(list, "mkdir(%s) failed: %m", path);
	}
	return -1;
}

static const char *mailbox_list_fs_get_trash_dir(struct mailbox_list *list)
{
	const char *root_dir;

	root_dir = mailbox_list_get_path(list, NULL,
					 MAILBOX_LIST_PATH_TYPE_DIR);
	return t_strdup_printf("%s/"MAILBOX_LIST_FS_TRASH_DIR_NAME, root_dir);
}

static int fs_list_delete_mailbox(struct mailbox_list *list, const char *name)
{
	const char *path, *trash_dir;
	int ret = 0;

	if ((list->flags & MAILBOX_LIST_FLAG_MAILBOX_FILES) != 0) {
		if (mailbox_list_delete_mailbox_file(list, name) < 0)
			return -1;
		ret = 1;
	}

	if (*list->set.maildir_name != '\0' &&
	    *list->set.mailbox_dir_name != '\0' && ret == 0) {
		trash_dir = mailbox_list_fs_get_trash_dir(list);
		ret = mailbox_list_delete_maildir_via_trash(list, name,
							    trash_dir);
		if (ret < 0)
			return -1;

		/* try to delete the parent directory */
		path = mailbox_list_get_path(list, name,
					     MAILBOX_LIST_PATH_TYPE_DIR);
		if (rmdir(path) < 0 && errno != ENOENT &&
		    errno != ENOTEMPTY && errno != EEXIST) {
			mailbox_list_set_critical(list, "rmdir(%s) failed: %m",
						  path);
		}
	}

	if (ret == 0) {
		bool rmdir_path = *list->set.maildir_name != '\0';

		path = mailbox_list_get_path(list, name,
					     MAILBOX_LIST_PATH_TYPE_MAILBOX);
		if (mailbox_list_delete_mailbox_nonrecursive(list, name, path,
							     rmdir_path) < 0)
			return -1;
	}
	mailbox_list_delete_finish(list, name);
	return 0;
}

static int fs_list_rmdir(struct mailbox_list *list, const char *name,
			 const char *path)
{
	uint8_t dir_sha128[MAIL_GUID_128_SIZE];

	if (rmdir(path) < 0)
		return -1;

	mailbox_name_get_sha128(name, dir_sha128);
	mailbox_list_add_change(list, MAILBOX_LOG_RECORD_DELETE_DIR,
				dir_sha128);
	return 0;
}

static int fs_list_delete_dir(struct mailbox_list *list, const char *name)
{
	const char *path, *child_name, *child_path, *p;

	path = mailbox_list_get_path(list, name, MAILBOX_LIST_PATH_TYPE_DIR);
	if (fs_list_rmdir(list, name, path) == 0)
		return 0;

	if (errno == ENOENT) {
		mailbox_list_set_error(list, MAIL_ERROR_NOTFOUND,
			T_MAIL_ERR_MAILBOX_NOT_FOUND(name));
	} else if (errno == ENOTEMPTY || errno == EEXIST) {
		/* mbox workaround: if only .imap/ directory is preventing the
		   deletion, remove it */
		child_name = t_strdup_printf("%s%cchild", name,
					     list->ns->real_sep);
		child_path = mailbox_list_get_path(list, child_name,
						   MAILBOX_LIST_PATH_TYPE_INDEX);
		if (strncmp(path, child_path, strlen(path)) == 0) {
			/* drop the "/child" part out. */
			p = strrchr(child_path, '/');
			if (rmdir(t_strdup_until(child_path, p)) == 0) {
				/* try again */
				if (fs_list_rmdir(list, name, path) == 0)
					return 0;
			}
		}

		mailbox_list_set_error(list, MAIL_ERROR_EXISTS,
			"Mailbox has children, delete them first");
	} else {
		mailbox_list_set_critical(list, "rmdir(%s) failed: %m", path);
	}
	return -1;
}

static int rename_dir(struct mailbox_list *oldlist, const char *oldname,
		      struct mailbox_list *newlist, const char *newname,
		      enum mailbox_list_path_type type, bool rmdir_parent)
{
	const char *oldpath, *newpath, *p;

	oldpath = mailbox_list_get_path(oldlist, oldname, type);
	newpath = mailbox_list_get_path(newlist, newname, type);

	if (strcmp(oldpath, newpath) == 0)
		return 0;

	if (rename(oldpath, newpath) < 0 && errno != ENOENT) {
		mailbox_list_set_critical(oldlist, "rename(%s, %s) failed: %m",
					  oldpath, newpath);
		return -1;
	}
	if (rmdir_parent && (p = strrchr(oldpath, '/')) != NULL) {
		oldpath = t_strdup_until(oldpath, p);
		if (rmdir(oldpath) < 0 && errno != ENOENT &&
		    errno != ENOTEMPTY && errno != EEXIST) {
			mailbox_list_set_critical(oldlist,
				"rmdir(%s) failed: %m", oldpath);
		}
	}

	/* avoid leaving empty directories lying around */
	mailbox_list_delete_until_root(oldlist, oldpath, type);
	return 0;
}

static int fs_list_rename_mailbox(struct mailbox_list *oldlist,
				  const char *oldname,
				  struct mailbox_list *newlist,
				  const char *newname, bool rename_children)
{
	struct mail_storage *oldstorage;
	const char *oldpath, *newpath, *alt_newpath, *root_path;
	const char *p, *origin;
	enum mailbox_list_path_type path_type, alt_path_type;
	struct stat st;
	mode_t mode;
	gid_t gid;
	bool rmdir_parent = FALSE;

	if (mailbox_list_get_storage(&oldlist, &oldname, &oldstorage) < 0)
		return -1;

	if (rename_children) {
		path_type = MAILBOX_LIST_PATH_TYPE_DIR;
		alt_path_type = MAILBOX_LIST_PATH_TYPE_ALT_DIR;
	} else if (mail_storage_is_mailbox_file(oldstorage) ||
		   *oldlist->set.maildir_name != '\0') {
		path_type = MAILBOX_LIST_PATH_TYPE_MAILBOX;
		alt_path_type = MAILBOX_LIST_PATH_TYPE_ALT_MAILBOX;
	} else {
		/* we can't do this, our children would get renamed with us */
		mailbox_list_set_error(oldlist, MAIL_ERROR_NOTPOSSIBLE,
			"Can't rename mailbox without its children.");
		return -1;
	}

	oldpath = mailbox_list_get_path(oldlist, oldname, path_type);
	newpath = mailbox_list_get_path(newlist, newname, path_type);
	alt_newpath = mailbox_list_get_path(newlist, newname, alt_path_type);

	root_path = mailbox_list_get_path(oldlist, NULL,
					  MAILBOX_LIST_PATH_TYPE_MAILBOX);
	if (strcmp(oldpath, root_path) == 0) {
		/* most likely INBOX */
		mailbox_list_set_error(oldlist, MAIL_ERROR_NOTPOSSIBLE,
			t_strdup_printf("Renaming %s isn't supported.",
					oldname));
		return -1;
	}

	/* create the hierarchy */
	p = strrchr(newpath, '/');
	if (p != NULL) {
		mailbox_list_get_dir_permissions(newlist, NULL, &mode,
						 &gid, &origin);
		p = t_strdup_until(newpath, p);
		if (mkdir_parents_chgrp(p, mode, gid, origin) < 0 &&
		    errno != EEXIST) {
			if (mailbox_list_set_error_from_errno(oldlist))
				return -1;

			mailbox_list_set_critical(oldlist,
				"mkdir_parents(%s) failed: %m", p);
			return -1;
		}
	}

	/* first check that the destination mailbox doesn't exist.
	   this is racy, but we need to be atomic and there's hardly any
	   possibility that someone actually tries to rename two mailboxes
	   to same new one */
	if (lstat(newpath, &st) == 0) {
		mailbox_list_set_error(oldlist, MAIL_ERROR_EXISTS,
				       "Target mailbox already exists");
		return -1;
	} else if (errno == ENOTDIR) {
		mailbox_list_set_error(oldlist, MAIL_ERROR_NOTPOSSIBLE,
			"Target mailbox doesn't allow inferior mailboxes");
		return -1;
	} else if (errno != ENOENT && errno != EACCES) {
		mailbox_list_set_critical(oldlist, "lstat(%s) failed: %m",
					  newpath);
		return -1;
	}

	if (alt_newpath != NULL) {
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
	}

	if (rename(oldpath, newpath) < 0) {
		if (ENOTFOUND(errno)) {
			mailbox_list_set_error(oldlist, MAIL_ERROR_NOTFOUND,
				T_MAIL_ERR_MAILBOX_NOT_FOUND(oldname));
		} else if (!mailbox_list_set_error_from_errno(oldlist)) {
			mailbox_list_set_critical(oldlist,
				"rename(%s, %s) failed: %m", oldpath, newpath);
		}
		return -1;
	}

	if (!rename_children) {
		/* if there are no child mailboxes, get rid of the mailbox
		   directory entirely. */
		oldpath = mailbox_list_get_path(oldlist, oldname,
						MAILBOX_LIST_PATH_TYPE_DIR);
		if (rmdir(oldpath) == 0)
			rmdir_parent = TRUE;
		else if (errno != ENOENT &&
			 errno != ENOTEMPTY && errno != EEXIST) {
			mailbox_list_set_critical(oldlist,
				"rmdir(%s) failed: %m", oldpath);
		}
	}

	if (alt_newpath != NULL) {
		(void)rename_dir(oldlist, oldname, newlist, newname,
				 alt_path_type, rmdir_parent);
	}
	(void)rename_dir(oldlist, oldname, newlist, newname,
			 MAILBOX_LIST_PATH_TYPE_CONTROL, rmdir_parent);
	(void)rename_dir(oldlist, oldname, newlist, newname,
			 MAILBOX_LIST_PATH_TYPE_INDEX, rmdir_parent);
	return 0;
}

struct mailbox_list fs_mailbox_list = {
	.name = MAILBOX_LIST_NAME_FS,
	.hierarchy_sep = '/',
	.props = 0,
	.mailbox_name_max_length = MAILBOX_LIST_NAME_MAX_LENGTH,

	{
		fs_list_alloc,
		fs_list_deinit,
		NULL,
		fs_is_valid_pattern,
		fs_is_valid_existing_name,
		fs_is_valid_create_name,
		fs_list_get_path,
		fs_list_get_mailbox_name_status,
		fs_list_get_temp_prefix,
		fs_list_join_refpattern,
		fs_list_iter_init,
		fs_list_iter_next,
		fs_list_iter_deinit,
		fs_list_get_mailbox_flags,
		NULL,
		fs_list_set_subscribed,
		fs_list_create_mailbox_dir,
		fs_list_delete_mailbox,
		fs_list_delete_dir,
		fs_list_rename_mailbox
	}
};
