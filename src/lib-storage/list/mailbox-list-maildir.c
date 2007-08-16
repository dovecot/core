/* Copyright (C) 2006-2007 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "hostpid.h"
#include "home-expand.h"
#include "subscription-file.h"
#include "mailbox-list-maildir.h"

#include <stdio.h>
#include <sys/stat.h>

extern struct mailbox_list maildir_mailbox_list;
extern struct mailbox_list imapdir_mailbox_list;

static struct mailbox_list *maildir_list_alloc(void)
{
	struct maildir_mailbox_list *list;
	pool_t pool;

	pool = pool_alloconly_create("maildir++ list", 1024);
	list = p_new(pool, struct maildir_mailbox_list, 1);
	list->list = maildir_mailbox_list;
	list->list.pool = pool;

	list->temp_prefix =
		p_strconcat(pool, "temp.", my_hostname, ".", my_pid, ".", NULL);
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

	list->temp_prefix = p_strconcat(pool, ".temp.", my_hostname, ".",
					my_pid, ".", NULL);
	return &list->list;
}

static void maildir_list_deinit(struct mailbox_list *_list)
{
	struct maildir_mailbox_list *list =
		(struct maildir_mailbox_list *)_list;

	pool_unref(list->list.pool);
}

static const char *
maildir_list_get_dirname_path(struct mailbox_list *list, const char *dir,
			      const char *name)
{
	if (strcmp(list->name, MAILBOX_LIST_NAME_IMAPDIR) == 0)
		return t_strdup_printf("%s/%s", dir, name);
	
	return t_strdup_printf("%s/%c%s", dir, list->hierarchy_sep, name);
}

static const char *
maildir_list_get_absolute_path(struct mailbox_list *list, const char *name)
{
	const char *p;

	if (home_try_expand(&name) < 0) {
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

static bool __attr_noreturn__
maildir_is_valid_pattern(struct mailbox_list *list __attr_unused__,
			 const char *pattern __attr_unused__)
{
	i_unreached();
#ifndef __attrs_used__
	return FALSE;
#endif
}

static bool
maildir_is_valid_existing_name(struct mailbox_list *list, const char *name)
{
	size_t len;

	if (!maildir_list_is_valid_common(list, name, &len))
		return FALSE;

	if ((list->flags & MAILBOX_LIST_FLAG_FULL_FS_ACCESS) != 0)
		return TRUE;

	return maildir_list_is_valid_common_nonfs(name);
}

static bool
maildir_is_valid_create_name(struct mailbox_list *list, const char *name)
{
	size_t len;

	if (!maildir_list_is_valid_common(list, name, &len))
		return FALSE;
	if (len > MAILDIR_MAX_CREATE_MAILBOX_NAME_LENGTH)
		return FALSE;

	if ((list->flags & MAILBOX_LIST_FLAG_FULL_FS_ACCESS) != 0)
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
	struct maildir_mailbox_list *list =
		(struct maildir_mailbox_list *)_list;

	if (name == NULL) {
		/* return root directories */
		switch (type) {
		case MAILBOX_LIST_PATH_TYPE_DIR:
		case MAILBOX_LIST_PATH_TYPE_MAILBOX:
			return _list->set.root_dir;
		case MAILBOX_LIST_PATH_TYPE_CONTROL:
			return _list->set.control_dir != NULL ?
				_list->set.control_dir : _list->set.root_dir;
		case MAILBOX_LIST_PATH_TYPE_INDEX:
			return _list->set.index_dir != NULL ?
				_list->set.index_dir : _list->set.root_dir;
		}
		i_unreached();
	}

	i_assert(mailbox_list_is_valid_existing_name(_list, name));

	if ((list->list.flags & MAILBOX_LIST_FLAG_FULL_FS_ACCESS) != 0 &&
	    (*name == '/' || *name == '~'))
		return maildir_list_get_absolute_path(_list, name);

	switch (type) {
	case MAILBOX_LIST_PATH_TYPE_DIR:
	case MAILBOX_LIST_PATH_TYPE_MAILBOX:
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

	if (strcmp(name, "INBOX") == 0) {
		return _list->set.inbox_path != NULL ?
			_list->set.inbox_path : _list->set.root_dir;
	}

	return maildir_list_get_dirname_path(_list, _list->set.root_dir, name);
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

	if (strcmp(name, "INBOX") == 0 || stat(path, &st) == 0) {
		*status = MAILBOX_NAME_EXISTS;
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
maildir_list_get_temp_prefix(struct mailbox_list *_list)
{
	struct maildir_mailbox_list *list =
		(struct maildir_mailbox_list *)_list;

	return list->temp_prefix;
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

static int rename_dir(struct mailbox_list *list,
		      enum mailbox_list_path_type type,
		      const char *oldname, const char *newname)
{
	const char *oldpath, *newpath;

	oldpath = mailbox_list_get_path(list, oldname, type);
	newpath = mailbox_list_get_path(list, newname, type);

	if (strcmp(oldpath, newpath) == 0)
		return 0;

	if (rename(oldpath, newpath) < 0 && errno != ENOENT) {
		mailbox_list_set_critical(list, "rename(%s, %s) failed: %m",
					  oldpath, newpath);
		return -1;
	}

	return 0;
}

static int rename_children(struct mailbox_list *list,
			   const char *oldname, const char *newname)
{
	struct mailbox_list_iterate_context *iter;
        const struct mailbox_info *info;
	ARRAY_DEFINE(names_arr, const char *);
	const char *pattern, *oldpath, *newpath, *old_listname, *new_listname;
	const char *const *names;
	unsigned int i, count;
	size_t oldnamelen;
	pool_t pool;
	int ret;

	ret = 0;
	oldnamelen = strlen(oldname);

	/* first get the list of the children and save them to memory, because
	   we can't rely on readdir() not skipping files while the directory
	   is being modified. this doesn't protect against modifications by
	   other processes though. */
	pool = pool_alloconly_create("Maildir++ children list", 1024);
	i_array_init(&names_arr, 64);

	pattern = t_strdup_printf("%s%c*", oldname,
				  mailbox_list_get_hierarchy_sep(list));
	iter = mailbox_list_iter_init(list, pattern,
				      MAILBOX_LIST_ITER_RETURN_NO_FLAGS);
	while ((info = mailbox_list_iter_next(iter)) != NULL) {
		const char *name;

		i_assert(oldnamelen <= strlen(info->name));

		name = p_strdup(pool, info->name + oldnamelen);
		array_append(&names_arr, &name, 1);
	}
	if (mailbox_list_iter_deinit(&iter) < 0) {
		ret = -1;
		names = NULL; count = 0;
	} else {
		names = array_get(&names_arr, &count);
	}

	for (i = 0; i < count; i++) {
		t_push();

		old_listname = t_strconcat(oldname, names[i], NULL);
		new_listname = t_strconcat(newname, names[i], NULL);
		oldpath = mailbox_list_get_path(list, old_listname,
						MAILBOX_LIST_PATH_TYPE_MAILBOX);
		newpath = mailbox_list_get_path(list, new_listname,
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
			mailbox_list_set_critical(list,
				"rename(%s, %s) failed: %m", oldpath, newpath);
			ret = -1;
			t_pop();
			break;
		}

		(void)rename_dir(list, MAILBOX_LIST_PATH_TYPE_CONTROL,
				 old_listname, new_listname);
		(void)rename_dir(list, MAILBOX_LIST_PATH_TYPE_INDEX,
				 old_listname, new_listname);
		t_pop();
	}
	array_free(&names_arr);
	pool_unref(pool);

	return ret;
}

static int
maildir_list_delete_mailbox(struct mailbox_list *list, const char *name)
{
	/* let the backend handle the rest */
	return mailbox_list_delete_index_control(list, name);
}

static int maildir_list_rename_mailbox(struct mailbox_list *list,
				       const char *oldname, const char *newname)
{
	const char *oldpath, *newpath;
	int ret;
        bool found;

	/* NOTE: it's possible to rename a nonexisting mailbox which has
	   children. In that case we should ignore the rename() error. */
	oldpath = mailbox_list_get_path(list, oldname,
					MAILBOX_LIST_PATH_TYPE_MAILBOX);
	newpath = mailbox_list_get_path(list, newname,
					MAILBOX_LIST_PATH_TYPE_MAILBOX);

	ret = rename(oldpath, newpath);
	if (ret == 0 || errno == ENOENT) {
		(void)rename_dir(list, MAILBOX_LIST_PATH_TYPE_CONTROL,
				 oldname, newname);
		(void)rename_dir(list, MAILBOX_LIST_PATH_TYPE_INDEX,
				 oldname, newname);

		found = ret == 0;
		ret = rename_children(list, oldname, newname);
		if (ret < 0)
			return -1;
		if (!found && ret == 0) {
			mailbox_list_set_error(list, MAIL_ERROR_NOTFOUND,
				T_MAIL_ERR_MAILBOX_NOT_FOUND(oldname));
			return -1;
		}

		return 0;
	}

	if (EDESTDIREXISTS(errno)) {
		mailbox_list_set_error(list, MAIL_ERROR_NOTPOSSIBLE,
				       "Target mailbox already exists");
	} else {
		mailbox_list_set_critical(list, "rename(%s, %s) failed: %m",
					  oldpath, newpath);
	}
	return -1;
}

struct mailbox_list maildir_mailbox_list = {
	MEMBER(name) MAILBOX_LIST_NAME_MAILDIRPLUSPLUS,
	MEMBER(hierarchy_sep) '.',
	MEMBER(mailbox_name_max_length) PATH_MAX,

	{
		maildir_list_alloc,
		maildir_list_deinit,
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
		NULL,
		maildir_list_set_subscribed,
		maildir_list_delete_mailbox,
		maildir_list_rename_mailbox
	}
};

struct mailbox_list imapdir_mailbox_list = {
	MEMBER(name) MAILBOX_LIST_NAME_IMAPDIR,
	MEMBER(hierarchy_sep) '.',
	MEMBER(mailbox_name_max_length) PATH_MAX,

	{
		imapdir_list_alloc,
		maildir_list_deinit,
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
		NULL,
		maildir_list_set_subscribed,
		maildir_list_delete_mailbox,
		maildir_list_rename_mailbox
	}
};
