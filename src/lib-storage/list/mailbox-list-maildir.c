/* Copyright (C) 2006 Timo Sirainen */

#include "lib.h"
#include "hostpid.h"
#include "home-expand.h"
#include "subscription-file.h"
#include "mailbox-list-maildir.h"

#include <sys/stat.h>

extern struct mailbox_list maildir_mailbox_list;

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

static void maildir_list_deinit(struct mailbox_list *_list)
{
	struct maildir_mailbox_list *list =
		(struct maildir_mailbox_list *)_list;

	pool_unref(list->list.pool);
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
	return t_strdup_printf("%s/%c%s", t_strdup_until(name, p),
			       list->hierarchy_sep, p+1);
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
maildir_is_valid_mask(struct mailbox_list *list __attr_unused__,
		      const char *mask __attr_unused__)
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

	mailbox_list_clear_error(&list->list);

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
			return t_strdup_printf("%s/%c%s",
					       _list->set.control_dir,
					       _list->hierarchy_sep, name);
		}
		break;
	case MAILBOX_LIST_PATH_TYPE_INDEX:
		if (_list->set.index_dir != NULL) {
			if (*_list->set.index_dir == '\0')
				return "";
			return t_strdup_printf("%s/%c%s", _list->set.index_dir,
					       _list->hierarchy_sep, name);
		}
		break;
	}

	if (strcmp(name, "INBOX") == 0) {
		return _list->set.inbox_path != NULL ?
			_list->set.inbox_path : _list->set.root_dir;
	}

	return t_strdup_printf("%s/%c%s", _list->set.root_dir,
			       _list->hierarchy_sep, name);
}

static int
maildir_list_get_mailbox_name_status(struct mailbox_list *_list,
				     const char *name,
				     enum mailbox_name_status *status)
{
	struct maildir_mailbox_list *list =
		(struct maildir_mailbox_list *)_list;
	struct stat st;
	const char *path;

	mailbox_list_clear_error(&list->list);

	if (!mailbox_list_is_valid_existing_name(_list, name)) {
		*status = MAILBOX_NAME_INVALID;
		return 0;
	}

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

static const char *
maildir_list_join_refmask(struct mailbox_list *_list __attr_unused__,
			  const char *ref, const char *mask)
{
	if (*ref != '\0') {
		/* merge reference and mask */
		mask = t_strconcat(ref, mask, NULL);
	}
	return mask;
}

static int maildir_list_set_subscribed(struct mailbox_list *_list,
				       const char *name, bool set)
{
	struct maildir_mailbox_list *list =
		(struct maildir_mailbox_list *)_list;
	const char *path;

	mailbox_list_clear_error(&list->list);

	path = t_strconcat(_list->set.control_dir != NULL ?
			   _list->set.control_dir : _list->set.root_dir,
			   "/", _list->set.subscription_fname, NULL);

	return subsfile_set_subscribed(_list, path, list->temp_prefix,
				       name, set);
}

struct mailbox_list maildir_mailbox_list = {
	MEMBER(name) "maildir++",
	MEMBER(hierarchy_sep) '.',
	MEMBER(mailbox_name_max_length) PATH_MAX,

	{
		maildir_list_alloc,
		maildir_list_deinit,
		maildir_is_valid_mask,
		maildir_is_valid_existing_name,
		maildir_is_valid_create_name,
		maildir_list_get_path,
		maildir_list_get_mailbox_name_status,
		maildir_list_get_temp_prefix,
		maildir_list_join_refmask,
		maildir_list_iter_init,
		maildir_list_iter_next,
		maildir_list_iter_deinit,
		maildir_list_set_subscribed
	}
};
