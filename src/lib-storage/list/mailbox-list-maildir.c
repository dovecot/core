/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hostpid.h"
#include "eacces-error.h"
#include "mkdir-parents.h"
#include "str.h"
#include "subscription-file.h"
#include "mailbox-list-delete.h"
#include "mailbox-list-maildir.h"

#include <stdio.h>
#include <sys/stat.h>

#define MAILDIR_SUBFOLDER_FILENAME "maildirfolder"
#define MAILDIR_GLOBAL_TEMP_PREFIX "temp."
#define IMAPDIR_GLOBAL_TEMP_PREFIX ".temp."

extern struct mailbox_list maildir_mailbox_list;
extern struct mailbox_list imapdir_mailbox_list;

static struct mailbox_list *maildir_list_alloc(void)
{
	struct maildir_mailbox_list *list;
	pool_t pool;

	pool = pool_alloconly_create("maildir++ list", 2048);
	list = p_new(pool, struct maildir_mailbox_list, 1);
	list->list = maildir_mailbox_list;
	list->list.pool = pool;

	list->global_temp_prefix = MAILDIR_GLOBAL_TEMP_PREFIX;
	list->temp_prefix = p_strconcat(pool, list->global_temp_prefix,
					my_hostname, ".", my_pid, ".", NULL);
	return &list->list;
}

static struct mailbox_list *imapdir_list_alloc(void)
{
	struct maildir_mailbox_list *list;
	pool_t pool;

	pool = pool_alloconly_create("imapdir list", 1024);
	list = p_new(pool, struct maildir_mailbox_list, 1);
	list->list = imapdir_mailbox_list;
	list->list.pool = pool;

	list->global_temp_prefix = IMAPDIR_GLOBAL_TEMP_PREFIX;
	list->temp_prefix = p_strconcat(pool, list->global_temp_prefix,
					my_hostname, ".", my_pid, ".", NULL);
	return &list->list;
}

static void maildir_list_deinit(struct mailbox_list *_list)
{
	struct maildir_mailbox_list *list =
		(struct maildir_mailbox_list *)_list;

	pool_unref(&list->list.pool);
}

static const char *
maildir_list_get_dirname_path(struct mailbox_list *list, const char *dir,
			      const char *name)
{
	if (*name == '\0')
		return dir;
	else if (list->name == imapdir_mailbox_list.name)
		return t_strdup_printf("%s/%s", dir, name);

	return t_strdup_printf("%s/%c%s", dir, list->hierarchy_sep, name);
}

static const char *
maildir_list_get_absolute_path(struct mailbox_list *list, const char *name)
{
	const char *p;

	if (!mailbox_list_try_get_absolute_path(list, &name)) {
		/* fallback to using as ~name */
		return name;
	}

	p = strrchr(name, '/');
	if (p == NULL)
		return name;
	return maildir_list_get_dirname_path(list, t_strdup_until(name, p),
					     p+1);
}

static bool
maildir_list_is_valid_common(struct mailbox_list *list, const char *name,
			     size_t *len_r)
{
	size_t len;

	/* check that there are no adjacent hierarchy separators */
	for (len = 0; name[len] != '\0'; len++) {
		if (name[len] == list->hierarchy_sep &&
		    name[len+1] == list->hierarchy_sep)
			return FALSE;
	}

	if (len == 0 || name[len-1] == '/')
		return FALSE;

	if (name[0] == list->hierarchy_sep ||
	    name[len-1] == list->hierarchy_sep)
		return FALSE;

	*len_r = len;
	return TRUE;
}

static bool maildir_list_is_valid_common_nonfs(const char *name)
{
	if (*name == '~' || strchr(name, '/') != NULL)
		return FALSE;

	if (name[0] == '.' && (name[1] == '\0' ||
			       (name[1] == '.' && name[2] == '\0'))) {
		/* "." and ".." aren't allowed. */
		return FALSE;
	}
	return TRUE;
}

static bool
maildir_is_valid_existing_name(struct mailbox_list *list, const char *name)
{
	size_t len;

	if (!maildir_list_is_valid_common(list, name, &len))
		return FALSE;

	if (list->mail_set->mail_full_filesystem_access)
		return TRUE;

	return maildir_list_is_valid_common_nonfs(name);
}

static bool
maildir_is_valid_pattern(struct mailbox_list *list, const char *pattern)
{
	/* maildir code itself doesn't care about this, but we may get here
	   from listing subscriptions to LAYOUT=fs namespace containing
	   entries for a subscriptions=no LAYOUT=maildir++ namespace */
	return maildir_is_valid_existing_name(list, pattern);
}

static bool
maildir_is_valid_create_name(struct mailbox_list *list, const char *name)
{
	size_t len;

	if (!maildir_list_is_valid_common(list, name, &len))
		return FALSE;
	if (len > MAILDIR_MAX_CREATE_MAILBOX_NAME_LENGTH)
		return FALSE;

	if (list->mail_set->mail_full_filesystem_access)
		return TRUE;

	if (!maildir_list_is_valid_common_nonfs(name))
		return FALSE;
	if (mailbox_list_name_is_too_large(name, list->hierarchy_sep))
		return FALSE;

	return TRUE;
}

static const char *
maildir_list_get_path(struct mailbox_list *_list, const char *name,
		      enum mailbox_list_path_type type)
{
	const char *root_dir;

	if (name == NULL) {
		/* return root directories */
		return mailbox_list_get_root_path(&_list->set, type);
	}

	if (_list->mail_set->mail_full_filesystem_access &&
	    (*name == '/' || *name == '~'))
		return maildir_list_get_absolute_path(_list, name);

	root_dir = _list->set.root_dir;
	switch (type) {
	case MAILBOX_LIST_PATH_TYPE_DIR:
	case MAILBOX_LIST_PATH_TYPE_MAILBOX:
		break;
	case MAILBOX_LIST_PATH_TYPE_ALT_DIR:
	case MAILBOX_LIST_PATH_TYPE_ALT_MAILBOX:
		if (_list->set.alt_dir == NULL)
			return NULL;
		root_dir = _list->set.alt_dir;
		break;
	case MAILBOX_LIST_PATH_TYPE_CONTROL:
		if (_list->set.control_dir != NULL) {
			return maildir_list_get_dirname_path(_list,
					       _list->set.control_dir, name);
		}
		break;
	case MAILBOX_LIST_PATH_TYPE_INDEX:
		if (_list->set.index_dir != NULL) {
			if (*_list->set.index_dir == '\0')
				return "";
			return maildir_list_get_dirname_path(_list,
						_list->set.index_dir, name);
		}
		break;
	}

	if (type == MAILBOX_LIST_PATH_TYPE_ALT_DIR ||
	    type == MAILBOX_LIST_PATH_TYPE_ALT_MAILBOX) {
		/* don't use inbox_path */
	} else if (strcmp(name, "INBOX") == 0 && _list->set.inbox_path != NULL)
		return _list->set.inbox_path;

	return maildir_list_get_dirname_path(_list, root_dir, name);
}

static int
maildir_list_get_mailbox_name_status(struct mailbox_list *_list,
				     const char *name,
				     enum mailbox_name_status *status)
{
	struct stat st;
	const char *path;

	path = mailbox_list_get_path(_list, name,
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);

	if ((strcmp(name, "INBOX") == 0 &&
	     (_list->ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0) ||
	    stat(path, &st) == 0) {
		*status = MAILBOX_NAME_EXISTS_MAILBOX;
		return 0;
	}

	if (!mailbox_list_is_valid_create_name(_list, name)) {
		*status = MAILBOX_NAME_INVALID;
		return 0;
	}

	if (ENOTFOUND(errno) || errno == EACCES) {
		*status = MAILBOX_NAME_VALID;
		return 0;
	} else {
		mailbox_list_set_critical(_list, "stat(%s) failed: %m", path);
		return -1;
	}
}

static const char *
maildir_list_get_temp_prefix(struct mailbox_list *_list, bool global)
{
	struct maildir_mailbox_list *list =
		(struct maildir_mailbox_list *)_list;

	return global ? list->global_temp_prefix : list->temp_prefix;
}

static int maildir_list_set_subscribed(struct mailbox_list *_list,
				       const char *name, bool set)
{
	struct maildir_mailbox_list *list =
		(struct maildir_mailbox_list *)_list;
	const char *path;

	path = t_strconcat(_list->set.control_dir != NULL ?
			   _list->set.control_dir : _list->set.root_dir,
			   "/", _list->set.subscription_fname, NULL);

	return subsfile_set_subscribed(_list, path, list->temp_prefix,
				       name, set);
}

static int
maildir_list_create_maildirfolder_file(struct mailbox_list *list,
				       const char *dir)
{
	const char *path, *gid_origin;
	mode_t mode, old_mask;
	gid_t gid;
	int fd;

	/* Maildir++ spec wants that maildirfolder named file is created for
	   all subfolders. */
	mailbox_list_get_permissions(list, NULL, &mode, &gid, &gid_origin);

	path = t_strconcat(dir, "/" MAILDIR_SUBFOLDER_FILENAME, NULL);
	old_mask = umask(0);
	fd = open(path, O_CREAT | O_WRONLY, mode);
	umask(old_mask);
	if (fd != -1) {
		/* ok */
	} else if (errno == ENOENT) {
		mailbox_list_set_error(list, MAIL_ERROR_NOTFOUND,
			"Mailbox was deleted while it was being created");
		return -1;
	} else {
		mailbox_list_set_critical(list,
			"open(%s, O_CREAT) failed: %m", path);
		return -1;
	}

	if (gid != (gid_t)-1) {
		if (fchown(fd, (uid_t)-1, gid) == 0) {
			/* ok */
		} else if (errno == EPERM) {
			mailbox_list_set_critical(list, "%s",
				eperm_error_get_chgrp("fchown", path,
						      gid, gid_origin));
		} else {
			mailbox_list_set_critical(list,
				"fchown(%s) failed: %m", path);
		}
	}
	(void)close(fd);
	return 0;
}

static int
maildir_list_create_mailbox_dir(struct mailbox_list *list, const char *name,
				enum mailbox_dir_create_type type)
{
	const char *path, *root_dir, *gid_origin, *p;
	mode_t mode;
	gid_t gid;
	bool create_parent_dir;

	if (type == MAILBOX_DIR_CREATE_TYPE_ONLY_NOSELECT) {
		mailbox_list_set_error(list, MAIL_ERROR_NOTPOSSIBLE,
				       "Can't create non-selectable mailbox");
		return -1;
	}

	path = mailbox_list_get_path(list, name,
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);
	create_parent_dir = type == MAILBOX_DIR_CREATE_TYPE_MAILBOX &&
		(list->flags & MAILBOX_LIST_FLAG_MAILBOX_FILES) != 0;
	if (create_parent_dir) {
		/* we only need to make sure that the parent directory exists */
		p = strrchr(path, '/');
		if (p == NULL)
			return 0;
		path = t_strdup_until(path, p);
	}

	root_dir = mailbox_list_get_path(list, NULL,
					 MAILBOX_LIST_PATH_TYPE_MAILBOX);
	mailbox_list_get_dir_permissions(list, NULL, &mode,
					 &gid, &gid_origin);
	if (mkdir_parents_chgrp(path, mode, gid, gid_origin) == 0) {
		/* ok */
	} else if (errno == EEXIST) {
		if (create_parent_dir)
			return 0;
		if (type == MAILBOX_DIR_CREATE_TYPE_MAILBOX) {
			if (strcmp(path, root_dir) == 0) {
				/* even though the root directory exists,
				   the mailbox might not */
				return 0;
			}
		}

		mailbox_list_set_error(list, MAIL_ERROR_EXISTS,
				       "Mailbox already exists");
		return -1;
	} else if (mailbox_list_set_error_from_errno(list)) {
		return -1;
	} else {
		mailbox_list_set_critical(list, "mkdir(%s) failed: %m", path);
		return -1;
	}
	return create_parent_dir || strcmp(path, root_dir) == 0 ? 0 :
		maildir_list_create_maildirfolder_file(list, path);
}

static const char *mailbox_list_maildir_get_trash_dir(struct mailbox_list *list)
{
	const char *root_dir;

	root_dir = mailbox_list_get_path(list, NULL,
					 MAILBOX_LIST_PATH_TYPE_DIR);
	return t_strdup_printf("%s/%c%c"MAILBOX_LIST_MAILDIR_TRASH_DIR_NAME,
			       root_dir, list->hierarchy_sep,
			       list->hierarchy_sep);
}

static int
maildir_list_delete_maildir(struct mailbox_list *list, const char *name)
{
	const char *path, *trash_dir;
	int ret = 0;

	trash_dir = mailbox_list_maildir_get_trash_dir(list);
	ret = mailbox_list_delete_maildir_via_trash(list, name, trash_dir);
	if (ret < 0)
		return -1;

	if (ret == 0) {
		/* we could actually use just unlink_directory()
		   but error handling is easier this way :) */
		path = mailbox_list_get_path(list, name,
					     MAILBOX_LIST_PATH_TYPE_MAILBOX);
		if (mailbox_list_delete_mailbox_nonrecursive(list, name,
							     path, TRUE) < 0)
			return -1;
	}
	return 0;
}

static int
maildir_list_delete_mailbox(struct mailbox_list *list, const char *name)
{
	if ((list->flags & MAILBOX_LIST_FLAG_MAILBOX_FILES) != 0) {
		if (mailbox_list_delete_mailbox_file(list, name) < 0)
			return -1;
	} else {
		if (maildir_list_delete_maildir(list, name) < 0)
			return -1;
	}

	mailbox_list_delete_finish(list, name);
	return 0;
}

static int maildir_list_delete_dir(struct mailbox_list *list, const char *name)
{
	const char *path;
	struct stat st;

	/* with maildir++ there aren't any non-selectable mailboxes.
	   we'll always fail. */
	path = mailbox_list_get_path(list, name, MAILBOX_LIST_PATH_TYPE_DIR);
	if (stat(path, &st) == 0) {
		mailbox_list_set_error(list, MAIL_ERROR_EXISTS,
				       "Mailbox exists");
	} else if (errno == ENOENT) {
		mailbox_list_set_error(list, MAIL_ERROR_NOTFOUND,
			T_MAIL_ERR_MAILBOX_NOT_FOUND(name));
	} else {
		mailbox_list_set_critical(list, "stat(%s) failed: %m", path);
	}
	return -1;
}

static int rename_dir(struct mailbox_list *oldlist, const char *oldname,
		      struct mailbox_list *newlist, const char *newname,
		      enum mailbox_list_path_type type)
{
	const char *oldpath, *newpath;

	oldpath = mailbox_list_get_path(oldlist, oldname, type);
	newpath = mailbox_list_get_path(newlist, newname, type);

	if (strcmp(oldpath, newpath) == 0)
		return 0;

	if (rename(oldpath, newpath) < 0 && errno != ENOENT) {
		mailbox_list_set_critical(oldlist, "rename(%s, %s) failed: %m",
					  oldpath, newpath);
		return -1;
	}
	return 0;
}

static int
maildir_rename_children(struct mailbox_list *oldlist, const char *oldname,
			struct mailbox_list *newlist, const char *newname)
{
	struct mailbox_list_iterate_context *iter;
        const struct mailbox_info *info;
	ARRAY_DEFINE(names_arr, const char *);
	const char *pattern, *oldpath, *newpath, *old_childname, *new_childname;
	const char *const *names, *old_vname, *new_vname;
	unsigned int i, count, old_vnamelen;
	pool_t pool;
	string_t *str;
	int ret;

	ret = 0;

	/* first get the list of the children and save them to memory, because
	   we can't rely on readdir() not skipping files while the directory
	   is being modified. this doesn't protect against modifications by
	   other processes though. */
	pool = pool_alloconly_create("Maildir++ children list", 1024);
	i_array_init(&names_arr, 64);

	str = t_str_new(256);
	old_vname = t_strdup(mail_namespace_get_vname(oldlist->ns, str, oldname));
	old_vnamelen = strlen(old_vname);

	str_truncate(str, 0);
	new_vname = t_strdup(mail_namespace_get_vname(newlist->ns, str, newname));

	pattern = t_strdup_printf("%s%c*", old_vname, oldlist->ns->sep);
	iter = mailbox_list_iter_init(oldlist, pattern,
				      MAILBOX_LIST_ITER_RETURN_NO_FLAGS |
				      MAILBOX_LIST_ITER_RAW_LIST);
	while ((info = mailbox_list_iter_next(iter)) != NULL) {
		const char *name;

		/* verify that the prefix matches, otherwise we could have
		   problems with mailbox names containing '%' and '*' chars */
		if (strncmp(info->name, old_vname, old_vnamelen) == 0 &&
		    info->name[old_vnamelen] == oldlist->ns->sep) {
			name = p_strdup(pool, info->name + old_vnamelen);
			array_append(&names_arr, &name, 1);
		}
	}
	if (mailbox_list_iter_deinit(&iter) < 0) {
		ret = -1;
		names = NULL; count = 0;
	} else {
		names = array_get(&names_arr, &count);
	}

	for (i = 0; i < count; i++) {
		old_childname = mail_namespace_get_storage_name(oldlist->ns,
					t_strconcat(old_vname, names[i], NULL));
		if (strcmp(old_childname, new_vname) == 0) {
			/* When doing RENAME "a" "a.b" we see "a.b" here.
			   We don't want to rename it anymore to "a.b.b". */
			continue;
		}

		new_childname = mail_namespace_get_storage_name(newlist->ns,
					t_strconcat(new_vname, names[i], NULL));
		oldpath = mailbox_list_get_path(oldlist, old_childname,
						MAILBOX_LIST_PATH_TYPE_MAILBOX);
		newpath = mailbox_list_get_path(newlist, new_childname,
						MAILBOX_LIST_PATH_TYPE_MAILBOX);

		/* FIXME: it's possible to merge two mailboxes if either one of
		   them doesn't have existing root mailbox. We could check this
		   but I'm not sure if it's worth it. It could be even
		   considered as a feature.

		   Anyway, the bug with merging is that if both mailboxes have
		   identically named child mailbox they conflict. Just ignore
		   those and leave them under the old mailbox. */
		if (rename(oldpath, newpath) == 0 || EDESTDIREXISTS(errno))
			ret = 1;
		else {
			mailbox_list_set_critical(oldlist,
				"rename(%s, %s) failed: %m", oldpath, newpath);
			ret = -1;
			break;
		}

		(void)rename_dir(oldlist, old_childname, newlist, new_childname,
				 MAILBOX_LIST_PATH_TYPE_CONTROL);
		(void)rename_dir(oldlist, old_childname, newlist, new_childname,
				 MAILBOX_LIST_PATH_TYPE_INDEX);
	}
	array_free(&names_arr);
	pool_unref(&pool);

	return ret;
}

static int
maildir_list_rename_mailbox(struct mailbox_list *oldlist, const char *oldname,
			    struct mailbox_list *newlist, const char *newname,
			    bool rename_children)
{
	const char *oldpath, *newpath, *root_path;
	int ret;
        bool found;

	/* NOTE: it's possible to rename a nonexistent mailbox which has
	   children. In that case we should ignore the rename() error. */
	oldpath = mailbox_list_get_path(oldlist, oldname,
					MAILBOX_LIST_PATH_TYPE_MAILBOX);
	newpath = mailbox_list_get_path(newlist, newname,
					MAILBOX_LIST_PATH_TYPE_MAILBOX);

	root_path = mailbox_list_get_path(oldlist, NULL,
					  MAILBOX_LIST_PATH_TYPE_MAILBOX);
	if (strcmp(oldpath, root_path) == 0) {
		/* most likely INBOX */
		mailbox_list_set_error(oldlist, MAIL_ERROR_NOTPOSSIBLE,
			t_strdup_printf("Renaming %s isn't supported.",
					oldname));
		return -1;
	}

	ret = rename(oldpath, newpath);
	if (ret == 0 || errno == ENOENT) {
		(void)rename_dir(oldlist, oldname, newlist, newname,
				 MAILBOX_LIST_PATH_TYPE_CONTROL);
		(void)rename_dir(oldlist, oldname, newlist, newname,
				 MAILBOX_LIST_PATH_TYPE_INDEX);

		found = ret == 0;
		if (!rename_children)
			ret = 0;
		else T_BEGIN {
			ret = maildir_rename_children(oldlist, oldname,
						      newlist, newname);
		} T_END;
		if (ret < 0)
			return -1;
		if (!found && ret == 0) {
			mailbox_list_set_error(oldlist, MAIL_ERROR_NOTFOUND,
				T_MAIL_ERR_MAILBOX_NOT_FOUND(oldname));
			return -1;
		}

		return 0;
	}

	if (EDESTDIREXISTS(errno)) {
		mailbox_list_set_error(oldlist, MAIL_ERROR_EXISTS,
				       "Target mailbox already exists");
	} else {
		mailbox_list_set_critical(oldlist, "rename(%s, %s) failed: %m",
					  oldpath, newpath);
	}
	return -1;
}

struct mailbox_list maildir_mailbox_list = {
	.name = MAILBOX_LIST_NAME_MAILDIRPLUSPLUS,
	.hierarchy_sep = '.',
	.props = MAILBOX_LIST_PROP_NO_MAILDIR_NAME |
		MAILBOX_LIST_PROP_NO_ALT_DIR |
		MAILBOX_LIST_PROP_NO_NOSELECT,
	.mailbox_name_max_length = MAILBOX_LIST_NAME_MAX_LENGTH,

	{
		maildir_list_alloc,
		maildir_list_deinit,
		NULL,
		maildir_is_valid_pattern,
		maildir_is_valid_existing_name,
		maildir_is_valid_create_name,
		maildir_list_get_path,
		maildir_list_get_mailbox_name_status,
		maildir_list_get_temp_prefix,
		NULL,
		maildir_list_iter_init,
		maildir_list_iter_next,
		maildir_list_iter_deinit,
		maildir_list_get_mailbox_flags,
		NULL,
		maildir_list_set_subscribed,
		maildir_list_create_mailbox_dir,
		maildir_list_delete_mailbox,
		maildir_list_delete_dir,
		maildir_list_rename_mailbox
	}
};

struct mailbox_list imapdir_mailbox_list = {
	.name = MAILBOX_LIST_NAME_IMAPDIR,
	.hierarchy_sep = '.',
	.props = MAILBOX_LIST_PROP_NO_MAILDIR_NAME |
		MAILBOX_LIST_PROP_NO_ALT_DIR |
		MAILBOX_LIST_PROP_NO_NOSELECT,
	.mailbox_name_max_length = MAILBOX_LIST_NAME_MAX_LENGTH,

	{
		imapdir_list_alloc,
		maildir_list_deinit,
		NULL,
		maildir_is_valid_pattern,
		maildir_is_valid_existing_name,
		maildir_is_valid_create_name,
		maildir_list_get_path,
		maildir_list_get_mailbox_name_status,
		maildir_list_get_temp_prefix,
		NULL,
		maildir_list_iter_init,
		maildir_list_iter_next,
		maildir_list_iter_deinit,
		maildir_list_get_mailbox_flags,
		NULL,
		maildir_list_set_subscribed,
		maildir_list_create_mailbox_dir,
		maildir_list_delete_mailbox,
		maildir_list_delete_dir,
		maildir_list_rename_mailbox
	}
};
