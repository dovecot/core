/* Copyright (C) 2006-2007 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "mkdir-parents.h"
#include "unlink-directory.h"
#include "mailbox-list-private.h"

#include <time.h>
#include <dirent.h>

/* 20 * (200+1) < 4096 which is the standard PATH_MAX. Having these settings
   prevents malicious user from creating eg. "a/a/a/.../a" mailbox name and
   then start renaming them to larger names from end to beginning, which
   eventually would start causing the failures when trying to use too
   long mailbox names. */
#define MAILBOX_MAX_HIERARCHY_LEVELS 20
#define MAILBOX_MAX_HIERARCHY_NAME_LENGTH 200

/* Message to show to users when critical error occurs */
#define CRITICAL_MSG \
	"Internal error occurred. Refer to server log for more information."
#define CRITICAL_MSG_STAMP CRITICAL_MSG " [%Y-%m-%d %H:%M:%S]"

struct mailbox_list_module_register mailbox_list_module_register = { 0 };

void (*hook_mailbox_list_created)(struct mailbox_list *list);

static ARRAY_DEFINE(mailbox_list_drivers, const struct mailbox_list *);

static bool mailbox_list_driver_find(const char *name, unsigned int *idx_r)
{
	const struct mailbox_list *const *drivers;
	unsigned int i, count;

	drivers = array_get(&mailbox_list_drivers, &count);
	for (i = 0; i < count; i++) {
		if (strcasecmp(drivers[i]->name, name) == 0) {
			*idx_r = i;
			return TRUE;
		}
	}
	return FALSE;
}

void mailbox_list_register(const struct mailbox_list *list)
{
	if (!array_is_created(&mailbox_list_drivers))
		i_array_init(&mailbox_list_drivers, 4);
	else {
		unsigned int idx;

		if (mailbox_list_driver_find(list->name, &idx)) {
			i_fatal("mailbox_list_register(%s): duplicate driver",
				list->name);
		}
	}

	array_append(&mailbox_list_drivers, &list, 1);
}

void mailbox_list_unregister(const struct mailbox_list *list)
{
	unsigned int idx;

	if (!mailbox_list_driver_find(list->name, &idx)) {
		i_fatal("mailbox_list_unregister(%s): unknown driver",
			list->name);
	}
	array_delete(&mailbox_list_drivers, idx, 1);

	if (array_count(&mailbox_list_drivers) == 0)
		array_free(&mailbox_list_drivers);
}

int mailbox_list_init(const char *driver,
		      const struct mailbox_list_settings *set,
		      enum mailbox_list_flags flags,
		      struct mailbox_list **list_r, const char **error_r)
{
	const struct mailbox_list *const *class_p;
	struct mailbox_list *list;
	unsigned int idx;

	if (!mailbox_list_driver_find(driver, &idx)) {
		*error_r = "Unknown mailbox list driver";
		return -1;
	}

	i_assert(*set->root_dir != '\0');
	i_assert(*set->subscription_fname != '\0');

	class_p = array_idx(&mailbox_list_drivers, idx);
	list = (*class_p)->v.alloc();

	list->flags = flags;

	/* copy settings */
	list->set.root_dir = p_strdup(list->pool, set->root_dir);
	list->set.index_dir = set->index_dir == NULL ||
		strcmp(set->index_dir, set->root_dir) == 0 ? NULL :
		p_strdup(list->pool, set->index_dir);
	list->set.control_dir = set->control_dir == NULL ||
		strcmp(set->control_dir, set->root_dir) == 0 ? NULL :
		p_strdup(list->pool, set->control_dir);

	if (list->set.index_dir != NULL) {
		if (mkdir_parents(list->set.index_dir, 0700) < 0 &&
		    errno != EEXIST)
			i_error("mkdir(%s) failed: %m", list->set.index_dir);
	}
	if (list->set.control_dir != NULL) {
		if (mkdir_parents(list->set.control_dir, 0700) < 0 &&
		    errno != EEXIST)
			i_error("mkdir(%s) failed: %m", list->set.control_dir);
	}

	list->set.inbox_path = p_strdup(list->pool, set->inbox_path);
	list->set.subscription_fname =
		p_strdup(list->pool, set->subscription_fname);
	list->set.maildir_name = p_strdup(list->pool, set->maildir_name);

	list->set.mail_storage_flags = set->mail_storage_flags;
	list->set.lock_method = set->lock_method;

	if ((flags & MAILBOX_LIST_FLAG_DEBUG) != 0) {
		i_info("%s: root=%s, index=%s, control=%s, inbox=%s",
		       driver, list->set.root_dir,
		       list->set.index_dir == NULL ? "" : list->set.index_dir,
		       list->set.control_dir == NULL ?
		       "" : list->set.control_dir,
		       list->set.inbox_path == NULL ?
		       "" : list->set.inbox_path);
	}

	array_create(&list->module_contexts, list->pool, sizeof(void *), 5);

	if (hook_mailbox_list_created != NULL)
		hook_mailbox_list_created(list);

	list->set.mail_storage_flags = NULL;
	list->set.lock_method = NULL;

	*list_r = list;
	return 0;
}

void mailbox_list_deinit(struct mailbox_list *list)
{
	i_free_and_null(list->error);

	list->v.deinit(list);
}

const char *mailbox_list_get_driver_name(struct mailbox_list *list)
{
	return list->name;
}

char mailbox_list_get_hierarchy_sep(struct mailbox_list *list)
{
	return list->hierarchy_sep;
}

bool mailbox_list_is_valid_mask(struct mailbox_list *list, const char *mask)
{
	return list->v.is_valid_mask(list, mask);
}

bool mailbox_list_is_valid_existing_name(struct mailbox_list *list,
					 const char *name)
{
	return list->v.is_valid_existing_name(list, name);
}

bool mailbox_list_is_valid_create_name(struct mailbox_list *list,
				       const char *name)
{
	return list->v.is_valid_create_name(list, name);
}

const char *mailbox_list_get_path(struct mailbox_list *list, const char *name,
				  enum mailbox_list_path_type type)
{
	mailbox_list_clear_error(list);

	return list->v.get_path(list, name, type);
}

const char *mailbox_list_get_temp_prefix(struct mailbox_list *list)
{
	return list->v.get_temp_prefix(list);
}

const char *mailbox_list_join_refmask(struct mailbox_list *list,
				      const char *ref, const char *mask)
{
	if (list->v.join_refmask != NULL)
		return list->v.join_refmask(list, ref, mask);

	/* the default implementation: */
	if (*ref != '\0') {
		/* merge reference and mask */
		mask = t_strconcat(ref, mask, NULL);
	}
	return mask;
}

int mailbox_list_get_mailbox_name_status(struct mailbox_list *list,
					 const char *name,
					 enum mailbox_name_status *status)
{
	mailbox_list_clear_error(list);

	if (!mailbox_list_is_valid_existing_name(list, name)) {
		*status = MAILBOX_NAME_INVALID;
		return 0;
	}

	return list->v.get_mailbox_name_status(list, name, status);
}

struct mailbox_list_iterate_context *
mailbox_list_iter_init(struct mailbox_list *list, const char *mask,
		       enum mailbox_list_iter_flags flags)
{
	return list->v.iter_init(list, mask, flags);
}

struct mailbox_info *
mailbox_list_iter_next(struct mailbox_list_iterate_context *ctx)
{
	return ctx->list->v.iter_next(ctx);
}

int mailbox_list_iter_deinit(struct mailbox_list_iterate_context **_ctx)
{
	struct mailbox_list_iterate_context *ctx = *_ctx;

	*_ctx = NULL;

	return ctx->list->v.iter_deinit(ctx);
}

int mailbox_list_set_subscribed(struct mailbox_list *list,
				const char *name, bool set)
{
	mailbox_list_clear_error(list);

	return list->v.set_subscribed(list, name, set);
}

int mailbox_list_delete_mailbox(struct mailbox_list *list, const char *name)
{
	if (!mailbox_list_is_valid_existing_name(list, name)) {
		mailbox_list_set_error(list, "Invalid mailbox name");
		return -1;
	}
	if (strcmp(name, "INBOX") == 0) {
		mailbox_list_set_error(list, "INBOX can't be deleted.");
		return -1;
	}
	return list->v.delete_mailbox(list, name);
}

int mailbox_list_rename_mailbox(struct mailbox_list *list,
				const char *oldname, const char *newname)
{
	if (!mailbox_list_is_valid_existing_name(list, oldname) ||
	    !mailbox_list_is_valid_create_name(list, newname)) {
		mailbox_list_set_error(list, "Invalid mailbox name");
		return -1;
	}

	return list->v.rename_mailbox(list, oldname, newname);
}

int mailbox_list_delete_index_control(struct mailbox_list *list,
				      const char *name)
{
	const char *path, *index_dir, *dir;

	path = mailbox_list_get_path(list, name,
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);

	/* delete the index directory first, so that if we crash we don't
	   leave indexes for deleted mailboxes lying around */
	index_dir = mailbox_list_get_path(list, name,
					  MAILBOX_LIST_PATH_TYPE_INDEX);
	if (*index_dir != '\0' && strcmp(index_dir, path) != 0) {
		if (unlink_directory(index_dir, TRUE) < 0 && errno != ENOENT) {
			mailbox_list_set_critical(list,
				"unlink_directory(%s) failed: %m", index_dir);
			return -1;
		}
	}

	/* control directory next */
	dir = mailbox_list_get_path(list, name, MAILBOX_LIST_PATH_TYPE_CONTROL);
	if (*dir != '\0' && strcmp(dir, path) != 0 &&
	    strcmp(dir, index_dir) != 0) {
		if (unlink_directory(dir, TRUE) < 0 && errno != ENOENT) {
			mailbox_list_set_critical(list,
				"unlink_directory(%s) failed: %m", dir);
			return -1;
		}
	}
	return 0;
}

bool mailbox_list_name_is_too_large(const char *name, char sep)
{
	unsigned int levels = 1, level_len = 0;

	for (; *name != '\0'; name++) {
		if (*name == sep) {
			if (level_len > MAILBOX_MAX_HIERARCHY_NAME_LENGTH)
				return TRUE;
			levels++;
			level_len = 0;
		} else {
			level_len++;
		}
	}

	if (level_len > MAILBOX_MAX_HIERARCHY_NAME_LENGTH)
		return TRUE;
	if (levels > MAILBOX_MAX_HIERARCHY_LEVELS)
		return TRUE;
	return FALSE;
}

enum mailbox_list_file_type mailbox_list_get_file_type(const struct dirent *d)
{
	enum mailbox_list_file_type type;

#ifdef HAVE_DIRENT_D_TYPE
	switch (d->d_type) {
	case DT_UNKNOWN:
		type = MAILBOX_LIST_FILE_TYPE_UNKNOWN;
		break;
	case DT_REG:
		type = MAILBOX_LIST_FILE_TYPE_FILE;
		break;
	case DT_DIR:
		type = MAILBOX_LIST_FILE_TYPE_DIR;
		break;
	case DT_LNK:
		type = MAILBOX_LIST_FILE_TYPE_SYMLINK;
		break;
	default:
		type = MAILBOX_LIST_FILE_TYPE_OTHER;
		break;
	}
#else
	type = MAILBOX_LIST_FILE_TYPE_UNKNOWN;
#endif
	return type;
}

const char *mailbox_list_get_last_error(struct mailbox_list *list,
					bool *temporary_error_r)
{
	*temporary_error_r = list->temporary_error;

	return list->error;
}

void mailbox_list_clear_error(struct mailbox_list *list)
{
	i_free_and_null(list->error);

	list->temporary_error = FALSE;
}

void mailbox_list_set_error(struct mailbox_list *list, const char *error)
{
	i_free(list->error);
	list->error = i_strdup(error);

	list->temporary_error = FALSE;
}

void mailbox_list_set_internal_error(struct mailbox_list *list)
{
	struct tm *tm;
	char str[256];

	tm = localtime(&ioloop_time);

	i_free(list->error);
	list->error =
		strftime(str, sizeof(str), CRITICAL_MSG_STAMP, tm) > 0 ?
		i_strdup(str) : i_strdup(CRITICAL_MSG);
	list->temporary_error = TRUE;
}

void mailbox_list_set_critical(struct mailbox_list *list, const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	i_error("%s", t_strdup_vprintf(fmt, va));
	va_end(va);

	/* critical errors may contain sensitive data, so let user
	   see only "Internal error" with a timestamp to make it
	   easier to look from log files the actual error message. */
	mailbox_list_set_internal_error(list);
}
