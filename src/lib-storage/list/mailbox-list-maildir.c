/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hostpid.h"
#include "eacces-error.h"
#include "mkdir-parents.h"
#include "str.h"
#include "subscription-file.h"
#include "mailbox-list-subscriptions.h"
#include "mailbox-list-delete.h"
#include "mailbox-list-maildir.h"

#include <stdio.h>
#include <sys/stat.h>

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
	list->sep = '.';

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
	list->sep = '.';

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
	else if (strcmp(list->name, imapdir_mailbox_list.name) == 0)
		return t_strdup_printf("%s/%s", dir, name);

	return t_strdup_printf("%s/%c%s", dir,
			       mailbox_list_get_hierarchy_sep(list), name);
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

static char maildir_list_get_hierarchy_sep(struct mailbox_list *_list)
{
	struct maildir_mailbox_list *list =
		(struct maildir_mailbox_list *)_list;

	return list->sep;
}

static int
maildir_list_get_path(struct mailbox_list *_list, const char *name,
		      enum mailbox_list_path_type type, const char **path_r)
{
	const char *root_dir;

	if (name == NULL) {
		/* return root directories */
		return mailbox_list_set_get_root_path(&_list->set, type,
						      path_r) ? 1 : 0;
	}

	if (_list->mail_set->mail_full_filesystem_access &&
	    (*name == '/' || *name == '~')) {
		*path_r = maildir_list_get_absolute_path(_list, name);
		return 1;
	}

	root_dir = _list->set.root_dir;
	switch (type) {
	case MAILBOX_LIST_PATH_TYPE_DIR:
	case MAILBOX_LIST_PATH_TYPE_MAILBOX:
		break;
	case MAILBOX_LIST_PATH_TYPE_ALT_DIR:
	case MAILBOX_LIST_PATH_TYPE_ALT_MAILBOX:
		if (_list->set.alt_dir == NULL)
			return 0;
		root_dir = _list->set.alt_dir;
		break;
	case MAILBOX_LIST_PATH_TYPE_CONTROL:
		if (_list->set.control_dir != NULL) {
			*path_r = maildir_list_get_dirname_path(_list,
					       _list->set.control_dir, name);
			return 1;
		}
		break;
	case MAILBOX_LIST_PATH_TYPE_INDEX_CACHE:
		if (_list->set.index_cache_dir != NULL) {
			*path_r = maildir_list_get_dirname_path(_list,
						_list->set.index_cache_dir, name);
			return 1;
		}
		/* fall through */
	case MAILBOX_LIST_PATH_TYPE_INDEX:
		if (_list->set.index_dir != NULL) {
			if (*_list->set.index_dir == '\0')
				return 0;
			*path_r = maildir_list_get_dirname_path(_list,
						_list->set.index_dir, name);
			return 1;
		}
		break;
	case MAILBOX_LIST_PATH_TYPE_INDEX_PRIVATE:
		if (_list->set.index_pvt_dir == NULL)
			return 0;
		*path_r = maildir_list_get_dirname_path(_list,
					_list->set.index_pvt_dir, name);
		return 1;
	case MAILBOX_LIST_PATH_TYPE_LIST_INDEX:
		i_unreached();
	}

	if (type == MAILBOX_LIST_PATH_TYPE_ALT_DIR ||
	    type == MAILBOX_LIST_PATH_TYPE_ALT_MAILBOX) {
		/* don't use inbox_path */
	} else if (strcmp(name, "INBOX") == 0 && _list->set.inbox_path != NULL) {
		*path_r = _list->set.inbox_path;
		return 1;
	}

	*path_r = maildir_list_get_dirname_path(_list, root_dir, name);
	return 1;
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

	if (_list->set.subscription_fname == NULL) {
		mailbox_list_set_error(_list, MAIL_ERROR_NOTPOSSIBLE,
				       "Subscriptions not supported");
		return -1;
	}

	path = t_strconcat(_list->set.control_dir != NULL ?
			   _list->set.control_dir : _list->set.root_dir,
			   "/", _list->set.subscription_fname, NULL);

	return subsfile_set_subscribed(_list, path, list->temp_prefix,
				       name, set);
}

static const char *
mailbox_list_maildir_get_trash_dir(struct mailbox_list *_list)
{
	struct maildir_mailbox_list *list =
		(struct maildir_mailbox_list *)_list;
	const char *root_dir;

	root_dir = mailbox_list_get_root_forced(_list, MAILBOX_LIST_PATH_TYPE_DIR);
	return t_strdup_printf("%s/%c%c"MAILBOX_LIST_MAILDIR_TRASH_DIR_NAME,
			       root_dir, list->sep, list->sep);
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
		if (mailbox_list_get_path(list, name,
					  MAILBOX_LIST_PATH_TYPE_MAILBOX,
					  &path) <= 0)
			i_unreached();
		if (mailbox_list_delete_mailbox_nonrecursive(list, name,
							     path, TRUE) < 0)
			return -1;
	}
	return 0;
}

static int
maildir_list_delete_mailbox(struct mailbox_list *list, const char *name)
{
	const char *path;
	int ret;

	if ((list->flags & MAILBOX_LIST_FLAG_MAILBOX_FILES) != 0) {
		ret = mailbox_list_get_path(list, name,
					    MAILBOX_LIST_PATH_TYPE_MAILBOX,
					    &path);
		if (ret < 0)
			return -1;
		i_assert(ret > 0);
		ret = mailbox_list_delete_mailbox_file(list, name, path);
	} else {
		ret = maildir_list_delete_maildir(list, name);
	}

	i_assert(ret <= 0);
	return mailbox_list_delete_finish_ret(list, name, ret == 0);
}

static int maildir_list_delete_dir(struct mailbox_list *list, const char *name)
{
	const char *path;
	struct stat st;

	/* with maildir++ there aren't any non-selectable mailboxes.
	   we'll always fail. */
	if (mailbox_list_get_path(list, name, MAILBOX_LIST_PATH_TYPE_DIR,
				  &path) <= 0)
		i_unreached();
	if (stat(path, &st) == 0) {
		mailbox_list_set_error(list, MAIL_ERROR_EXISTS,
				       "Mailbox exists");
	} else if (errno == ENOENT || errno == ENOTDIR) {
		mailbox_list_set_error(list, MAIL_ERROR_NOTFOUND,
			T_MAILBOX_LIST_ERR_NOT_FOUND(list, name));
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

	if (mailbox_list_get_path(oldlist, oldname, type, &oldpath) <= 0 ||
	    mailbox_list_get_path(newlist, newname, type, &newpath) <= 0)
		return 0;

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
	ARRAY(const char *) names_arr;
	const char *pattern, *oldpath, *newpath, *old_childname, *new_childname;
	const char *const *names, *old_vname, *new_vname;
	unsigned int i, count;
	size_t old_vnamelen;
	pool_t pool;
	char old_ns_sep;
	int ret;

	ret = 0;

	/* first get the list of the children and save them to memory, because
	   we can't rely on readdir() not skipping files while the directory
	   is being modified. this doesn't protect against modifications by
	   other processes though. */
	pool = pool_alloconly_create("Maildir++ children list", 1024);
	i_array_init(&names_arr, 64);

	old_vname = mailbox_list_get_vname(oldlist, oldname);
	old_vnamelen = strlen(old_vname);

	new_vname = mailbox_list_get_vname(newlist, newname);

	old_ns_sep = mail_namespace_get_sep(oldlist->ns);
	pattern = t_strdup_printf("%s%c*", old_vname, old_ns_sep);
	iter = mailbox_list_iter_init(oldlist, pattern,
				      MAILBOX_LIST_ITER_RETURN_NO_FLAGS |
				      MAILBOX_LIST_ITER_RAW_LIST);
	while ((info = mailbox_list_iter_next(iter)) != NULL) {
		const char *name;

		/* verify that the prefix matches, otherwise we could have
		   problems with mailbox names containing '%' and '*' chars */
		if (strncmp(info->vname, old_vname, old_vnamelen) == 0 &&
		    info->vname[old_vnamelen] == old_ns_sep) {
			name = p_strdup(pool, info->vname + old_vnamelen);
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
		old_childname = mailbox_list_get_storage_name(oldlist,
					t_strconcat(old_vname, names[i], NULL));
		if (strcmp(old_childname, new_vname) == 0) {
			/* When doing RENAME "a" "a.b" we see "a.b" here.
			   We don't want to rename it anymore to "a.b.b". */
			continue;
		}

		new_childname = mailbox_list_get_storage_name(newlist,
					t_strconcat(new_vname, names[i], NULL));
		if (mailbox_list_get_path(oldlist, old_childname,
					  MAILBOX_LIST_PATH_TYPE_MAILBOX,
					  &oldpath) <= 0 ||
		    mailbox_list_get_path(newlist, new_childname,
					  MAILBOX_LIST_PATH_TYPE_MAILBOX,
					  &newpath) <= 0)
			i_unreached();

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
		(void)rename_dir(oldlist, old_childname, newlist, new_childname,
				 MAILBOX_LIST_PATH_TYPE_INDEX_CACHE);
	}
	array_free(&names_arr);
	pool_unref(&pool);

	return ret;
}

static int
maildir_list_rename_mailbox(struct mailbox_list *oldlist, const char *oldname,
			    struct mailbox_list *newlist, const char *newname)
{
	const char *oldpath, *newpath, *root_path;
	int ret;
        bool found;

	/* NOTE: it's possible to rename a nonexistent mailbox which has
	   children. In that case we should ignore the rename() error. */
	if (mailbox_list_get_path(oldlist, oldname,
				  MAILBOX_LIST_PATH_TYPE_MAILBOX, &oldpath) <= 0 ||
	    mailbox_list_get_path(newlist, newname,
				  MAILBOX_LIST_PATH_TYPE_MAILBOX, &newpath) <= 0)
		i_unreached();

	root_path = mailbox_list_get_root_forced(oldlist,
						 MAILBOX_LIST_PATH_TYPE_MAILBOX);
	if (strcmp(oldpath, root_path) == 0) {
		/* most likely INBOX */
		mailbox_list_set_error(oldlist, MAIL_ERROR_NOTPOSSIBLE,
			t_strdup_printf("Renaming %s isn't supported.",
					oldname));
		return -1;
	}

	/* if we're renaming under another mailbox, require its permissions
	   to be same as ours. */
	if (strchr(newname, mailbox_list_get_hierarchy_sep(newlist)) != NULL) {
		struct mailbox_permissions old_perm, new_perm;

		mailbox_list_get_permissions(oldlist, oldname, &old_perm);
		mailbox_list_get_permissions(newlist, newname, &new_perm);

		if ((new_perm.file_create_mode != old_perm.file_create_mode ||
		     new_perm.dir_create_mode != old_perm.dir_create_mode ||
		     new_perm.file_create_gid != old_perm.file_create_gid)) {
			mailbox_list_set_error(oldlist, MAIL_ERROR_NOTPOSSIBLE,
				"Renaming not supported across conflicting "
				"directory permissions");
			return -1;
		}
	}


	ret = rename(oldpath, newpath);
	if (ret == 0 || errno == ENOENT) {
		(void)rename_dir(oldlist, oldname, newlist, newname,
				 MAILBOX_LIST_PATH_TYPE_CONTROL);
		(void)rename_dir(oldlist, oldname, newlist, newname,
				 MAILBOX_LIST_PATH_TYPE_INDEX);
		(void)rename_dir(oldlist, oldname, newlist, newname,
				 MAILBOX_LIST_PATH_TYPE_INDEX_CACHE);

		found = ret == 0;
		T_BEGIN {
			ret = maildir_rename_children(oldlist, oldname,
						      newlist, newname);
		} T_END;
		if (ret < 0)
			return -1;
		if (!found && ret == 0) {
			mailbox_list_set_error(oldlist, MAIL_ERROR_NOTFOUND,
				T_MAILBOX_LIST_ERR_NOT_FOUND(oldlist, oldname));
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
	.props = MAILBOX_LIST_PROP_NO_MAILDIR_NAME |
		MAILBOX_LIST_PROP_NO_ALT_DIR |
		MAILBOX_LIST_PROP_NO_NOSELECT,
	.mailbox_name_max_length = MAILBOX_LIST_NAME_MAX_LENGTH,

	.v = {
		.alloc = maildir_list_alloc,
		.deinit = maildir_list_deinit,
		.get_hierarchy_sep = maildir_list_get_hierarchy_sep,
		.get_vname = mailbox_list_default_get_vname,
		.get_storage_name = mailbox_list_default_get_storage_name,
		.get_path = maildir_list_get_path,
		.get_temp_prefix = maildir_list_get_temp_prefix,
		.iter_init = maildir_list_iter_init,
		.iter_next = maildir_list_iter_next,
		.iter_deinit = maildir_list_iter_deinit,
		.get_mailbox_flags = maildir_list_get_mailbox_flags,
		.subscriptions_refresh = mailbox_list_subscriptions_refresh,
		.set_subscribed = maildir_list_set_subscribed,
		.delete_mailbox = maildir_list_delete_mailbox,
		.delete_dir = maildir_list_delete_dir,
		.delete_symlink = mailbox_list_delete_symlink_default,
		.rename_mailbox = maildir_list_rename_mailbox,
	}
};

struct mailbox_list imapdir_mailbox_list = {
	.name = MAILBOX_LIST_NAME_IMAPDIR,
	.props = MAILBOX_LIST_PROP_NO_MAILDIR_NAME |
		MAILBOX_LIST_PROP_NO_ALT_DIR |
		MAILBOX_LIST_PROP_NO_NOSELECT,
	.mailbox_name_max_length = MAILBOX_LIST_NAME_MAX_LENGTH,

	.v = {
		.alloc = imapdir_list_alloc,
		.deinit = maildir_list_deinit,
		.get_hierarchy_sep = maildir_list_get_hierarchy_sep,
		.get_vname = mailbox_list_default_get_vname,
		.get_storage_name = mailbox_list_default_get_storage_name,
		.get_path = maildir_list_get_path,
		.get_temp_prefix = maildir_list_get_temp_prefix,
		.iter_init = maildir_list_iter_init,
		.iter_next = maildir_list_iter_next,
		.iter_deinit = maildir_list_iter_deinit,
		.get_mailbox_flags = maildir_list_get_mailbox_flags,
		.subscriptions_refresh = mailbox_list_subscriptions_refresh,
		.set_subscribed = maildir_list_set_subscribed,
		.delete_mailbox = maildir_list_delete_mailbox,
		.delete_dir = maildir_list_delete_dir,
		.delete_symlink = mailbox_list_delete_symlink_default,
		.rename_mailbox = maildir_list_rename_mailbox,
	}
};
