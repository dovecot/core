/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "mkdir-parents.h"
#include "str.h"
#include "sha1.h"
#include "home-expand.h"
#include "close-keep-errno.h"
#include "eacces-error.h"
#include "read-full.h"
#include "write-full.h"
#include "safe-mkstemp.h"
#include "unlink-directory.h"
#include "settings-parser.h"
#include "imap-match.h"
#include "imap-utf7.h"
#include "mailbox-log.h"
#include "mailbox-tree.h"
#include "mail-storage-private.h"
#include "mailbox-list-private.h"

#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

/* 20 * (200+1) < 4096 which is the standard PATH_MAX. Having these settings
   prevents malicious user from creating eg. "a/a/a/.../a" mailbox name and
   then start renaming them to larger names from end to beginning, which
   eventually would start causing the failures when trying to use too
   long mailbox names. */
#define MAILBOX_MAX_HIERARCHY_LEVELS 20
#define MAILBOX_MAX_HIERARCHY_NAME_LENGTH 200

struct ns_list_iterate_context {
	struct mailbox_list_iterate_context ctx;
	struct mailbox_list_iterate_context *backend_ctx;
	struct mail_namespace *namespaces;
	pool_t pool;
	const char **patterns, **patterns_ns_match;
	enum namespace_type type_mask;
};

struct mailbox_list_module_register mailbox_list_module_register = { 0 };

static ARRAY_DEFINE(mailbox_list_drivers, const struct mailbox_list *);

void mailbox_lists_init(void)
{
	i_array_init(&mailbox_list_drivers, 4);
}

void mailbox_lists_deinit(void)
{
	array_free(&mailbox_list_drivers);
}

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
	unsigned int idx;

	if (mailbox_list_driver_find(list->name, &idx)) {
		i_fatal("mailbox_list_register(%s): duplicate driver",
			list->name);
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
}

const struct mailbox_list *
mailbox_list_find_class(const char *driver)
{
	const struct mailbox_list *const *class_p;
	unsigned int idx;

	if (!mailbox_list_driver_find(driver, &idx))
		return NULL;

	class_p = array_idx(&mailbox_list_drivers, idx);
	return *class_p;
}

int mailbox_list_create(const char *driver, struct mail_namespace *ns,
			const struct mailbox_list_settings *set,
			enum mailbox_list_flags flags, const char **error_r)
{
	const struct mailbox_list *const *class_p;
	struct mailbox_list *list;
	unsigned int idx;

	i_assert(ns->list == NULL);

	i_assert(set->subscription_fname == NULL ||
		 *set->subscription_fname != '\0');

	if (!mailbox_list_driver_find(driver, &idx)) {
		*error_r = "Unknown driver name";
		return -1;
	}

	class_p = array_idx(&mailbox_list_drivers, idx);
	if (((*class_p)->props & MAILBOX_LIST_PROP_NO_MAILDIR_NAME) != 0 &&
	    set->maildir_name != NULL && *set->maildir_name != '\0') {
		*error_r = "maildir_name not supported by this driver";
		return -1;
	}
	if (((*class_p)->props & MAILBOX_LIST_PROP_NO_ALT_DIR) != 0 &&
	    set->alt_dir != NULL) {
		*error_r = "alt_dir not supported by this driver";
		return -1;
	}

	i_assert(set->root_dir == NULL || *set->root_dir != '\0' ||
		 ((*class_p)->props & MAILBOX_LIST_PROP_NO_ROOT) != 0);

	list = (*class_p)->v.alloc();
	array_create(&list->module_contexts, list->pool, sizeof(void *), 5);

	list->ns = ns;
	list->mail_set = ns->mail_set;
	list->flags = flags;
	list->file_create_mode = (mode_t)-1;
	list->dir_create_mode = (mode_t)-1;
	list->file_create_gid = (gid_t)-1;
	list->changelog_timestamp = (time_t)-1;

	/* copy settings */
	if (set->root_dir != NULL) {
		list->set.root_dir = p_strdup(list->pool, set->root_dir);
		list->set.index_dir = set->index_dir == NULL ||
			strcmp(set->index_dir, set->root_dir) == 0 ? NULL :
			p_strdup(list->pool, set->index_dir);
		list->set.control_dir = set->control_dir == NULL ||
			strcmp(set->control_dir, set->root_dir) == 0 ? NULL :
			p_strdup(list->pool, set->control_dir);
	}

	list->set.inbox_path = p_strdup(list->pool, set->inbox_path);
	list->set.subscription_fname =
		p_strdup(list->pool, set->subscription_fname);
	list->set.maildir_name = set->maildir_name == NULL ? "" :
		p_strdup(list->pool, set->maildir_name);
	list->set.mailbox_dir_name =
		p_strdup(list->pool, set->mailbox_dir_name);
	list->set.alt_dir = p_strdup(list->pool, set->alt_dir);

	if (set->mailbox_dir_name == NULL || *set->mailbox_dir_name == '\0')
		list->set.mailbox_dir_name = "";
	else if (set->mailbox_dir_name[strlen(set->mailbox_dir_name)-1] == '/') {
		list->set.mailbox_dir_name =
			p_strdup(list->pool, set->mailbox_dir_name);
	} else {
		list->set.mailbox_dir_name =
			p_strconcat(list->pool, set->mailbox_dir_name, "/", NULL);
	}

	if (ns->mail_set->mail_debug) {
		i_debug("%s: root=%s, index=%s, control=%s, inbox=%s, alt=%s",
			list->name,
			list->set.root_dir == NULL ? "" : list->set.root_dir,
			list->set.index_dir == NULL ? "" : list->set.index_dir,
			list->set.control_dir == NULL ?
			"" : list->set.control_dir,
			list->set.inbox_path == NULL ?
			"" : list->set.inbox_path,
			list->set.alt_dir == NULL ? "" : list->set.alt_dir);
	}
	mail_namespace_finish_list_init(ns, list);

	hook_mailbox_list_created(list);
	return 0;
}

static int fix_path(struct mail_user *user, const char *path,
		    const char **path_r, const char **error_r)
{
	size_t len = strlen(path);

	if (len > 1 && path[len-1] == '/')
		path = t_strndup(path, len-1);
	if (path[0] == '~' && path[1] != '/' && path[1] != '\0') {
		/* ~otheruser/dir */
		if (home_try_expand(&path) < 0) {
			*error_r = t_strconcat(
				"No home directory for system user. "
				"Can't expand ", t_strcut(path, '/'),
				" for ", NULL);
			return -1;
		}
	} else {
		if (mail_user_try_home_expand(user, &path) < 0) {
			*error_r = "Home directory not set for user. "
				"Can't expand ~/ for ";
			return -1;
		}
	}
	*path_r = path;
	return 0;
}

static const char *split_next_arg(const char *const **_args)
{
	const char *const *args = *_args;
	const char *str = args[0];

	args++;
	while (*args != NULL && **args == '\0') {
		args++;
		if (*args == NULL) {
			/* string ends with ":", just ignore it. */
			break;
		}
		str = t_strconcat(str, ":", *args, NULL);
		args++;
	}
	*_args = args;
	return str;
}

int mailbox_list_settings_parse(struct mail_user *user, const char *data,
				struct mailbox_list_settings *set_r,
				const char **error_r)
{
	const char *const *tmp, *key, *value, **dest, *str, *error;

	*error_r = NULL;

	memset(set_r, 0, sizeof(*set_r));

	if (*data == '\0')
		return 0;

	/* <root dir> */
	tmp = t_strsplit(data, ":");
	str = split_next_arg(&tmp);
	if (fix_path(user, str, &set_r->root_dir, &error) < 0) {
		*error_r = t_strconcat(error, "mail root dir in: ", data, NULL);
		return -1;
	}
	if (strncmp(set_r->root_dir, "INBOX=", 6) == 0) {
		/* probably mbox user trying to avoid root_dir */
		*error_r = t_strconcat("Mail root directory not given: ",
				       data, NULL);
		return -1;
	}

	while (*tmp != NULL) {
		str = split_next_arg(&tmp);
		value = strchr(str, '=');
		if (value == NULL) {
			key = str;
			value = "";
		} else {
			key = t_strdup_until(str, value);
			value++;
		}

		if (strcmp(key, "INBOX") == 0)
			dest = &set_r->inbox_path;
		else if (strcmp(key, "INDEX") == 0)
			dest = &set_r->index_dir;
		else if (strcmp(key, "CONTROL") == 0)
			dest = &set_r->control_dir;
		else if (strcmp(key, "ALT") == 0)
			dest = &set_r->alt_dir;
		else if (strcmp(key, "LAYOUT") == 0)
			dest = &set_r->layout;
		else if (strcmp(key, "SUBSCRIPTIONS") == 0)
			dest = &set_r->subscription_fname;
		else if (strcmp(key, "DIRNAME") == 0)
			dest = &set_r->maildir_name;
		else if (strcmp(key, "MAILBOXDIR") == 0)
			dest = &set_r->mailbox_dir_name;
		else {
			*error_r = t_strdup_printf("Unknown setting: %s", key);
			return -1;
		}
		if (fix_path(user, value, dest, &error) < 0) {
			*error_r = t_strconcat(error, key, " in: ", data, NULL);
			return -1;
		}
	}

	if (set_r->index_dir != NULL && strcmp(set_r->index_dir, "MEMORY") == 0)
		set_r->index_dir = "";
	return 0;
}

const char *mailbox_list_get_unexpanded_path(struct mailbox_list *list,
					     enum mailbox_list_path_type type)
{
	const struct mail_storage_settings *mail_set;
	const char *location = list->ns->unexpanded_set->location;
	struct mail_user *user = list->ns->user;
	struct mailbox_list_settings set;
	const char *p, *error;

	if (*location == SETTING_STRVAR_EXPANDED[0]) {
		/* set using -o or userdb lookup. */
		return "";
	}

	i_assert(*location == SETTING_STRVAR_UNEXPANDED[0]);
	location++;

	if (*location == '\0') {
		mail_set = mail_user_set_get_driver_settings(user->set_info,
			user->unexpanded_set, MAIL_STORAGE_SET_DRIVER_NAME);
		i_assert(mail_set != NULL);
		location = mail_set->mail_location;
		if (*location == SETTING_STRVAR_EXPANDED[0])
			return "";
		i_assert(*location == SETTING_STRVAR_UNEXPANDED[0]);
		location++;
	}

	/* type:settings */
	p = strchr(location, ':');
	if (p == NULL)
		return "";

	if (mailbox_list_settings_parse(user, p + 1, &set, &error) < 0)
		return "";
	return mailbox_list_get_root_path(&set, type);
}

void mailbox_list_destroy(struct mailbox_list **_list)
{
	struct mailbox_list *list = *_list;

	*_list = NULL;
	i_free_and_null(list->error_string);

	if (list->changelog != NULL)
		mailbox_log_free(&list->changelog);
	list->v.deinit(list);
}

const char *mailbox_list_get_driver_name(const struct mailbox_list *list)
{
	return list->name;
}

enum mailbox_list_flags mailbox_list_get_flags(const struct mailbox_list *list)
{
	return list->flags;
}

struct mail_namespace *
mailbox_list_get_namespace(const struct mailbox_list *list)
{
	return list->ns;
}

static mode_t get_dir_mode(mode_t mode)
{
	/* add the execute bit if either read or write bit is set */
	if ((mode & 0600) != 0) mode |= 0100;
	if ((mode & 0060) != 0) mode |= 0010;
	if ((mode & 0006) != 0) mode |= 0001;
	return mode;
}

struct mail_user *
mailbox_list_get_user(const struct mailbox_list *list)
{
	return list->ns->user;
}

int mailbox_list_get_storage(struct mailbox_list **list, const char **name,
			     struct mail_storage **storage_r)
{
	if ((*list)->v.get_storage != NULL)
		return (*list)->v.get_storage(list, name, storage_r);
	else {
		*storage_r = (*list)->ns->storage;
		return 0;
	}
}

void mailbox_list_get_closest_storage(struct mailbox_list *list,
				      struct mail_storage **storage)
{
	*storage = list->ns->storage;
}

static void
mailbox_list_get_permissions_full(struct mailbox_list *list, const char *name,
				  mode_t *file_mode_r, mode_t *dir_mode_r,
				  gid_t *gid_r, const char **gid_origin_r)
{
	const char *path;
	struct stat st;

	/* use safe defaults */
	*file_mode_r = 0600;
	*dir_mode_r = 0700;
	*gid_r = (gid_t)-1;
	*gid_origin_r = "defaults";

	path = mailbox_list_get_path(list, name, MAILBOX_LIST_PATH_TYPE_DIR);
	if (path == NULL) {
		/* no filesystem support in storage */
	} else if (stat(path, &st) < 0) {
		if (!ENOTFOUND(errno)) {
			mailbox_list_set_critical(list, "stat(%s) failed: %m",
						  path);
		} else if (list->mail_set->mail_debug) {
			i_debug("Namespace %s: %s doesn't exist yet, "
				"using default permissions",
				list->ns->prefix, path);
		}
		if (name != NULL) {
			/* return defaults */
			mailbox_list_get_permissions_full(list, NULL,
							  file_mode_r,
							  dir_mode_r, gid_r,
							  gid_origin_r);
			return;
		}
	} else {
		*file_mode_r = (st.st_mode & 0666) | 0600;
		*dir_mode_r = (st.st_mode & 0777) | 0700;
		*gid_origin_r = path;

		if (!S_ISDIR(st.st_mode)) {
			/* we're getting permissions from a file.
			   apply +x modes as necessary. */
			*dir_mode_r = get_dir_mode(*dir_mode_r);
		}

		if (S_ISDIR(st.st_mode) && (st.st_mode & S_ISGID) != 0) {
			/* directory's GID is used automatically for new
			   files */
			*gid_r = (gid_t)-1;
		} else if ((st.st_mode & 0070) >> 3 == (st.st_mode & 0007)) {
			/* group has same permissions as world, so don't bother
			   changing it */
			*gid_r = (gid_t)-1;
		} else if (getegid() == st.st_gid) {
			/* using our own gid, no need to change it */
			*gid_r = (gid_t)-1;
		} else {
			*gid_r = st.st_gid;
		}
	}

	if (name == NULL) {
		list->file_create_mode = *file_mode_r;
		list->dir_create_mode = *dir_mode_r;
		list->file_create_gid = *gid_r;
		list->file_create_gid_origin =
			p_strdup(list->pool, *gid_origin_r);
	}

	if (list->mail_set->mail_debug && name == NULL) {
		i_debug("Namespace %s: Using permissions from %s: "
			"mode=0%o gid=%ld", list->ns->prefix,
			path != NULL ? path : "",
			(int)list->dir_create_mode,
			list->file_create_gid == (gid_t)-1 ? -1L :
			(long)list->file_create_gid);
	}
}

void mailbox_list_get_permissions(struct mailbox_list *list,
				  const char *name,
				  mode_t *mode_r, gid_t *gid_r,
				  const char **gid_origin_r)
{
	mode_t dir_mode;

	if (list->file_create_mode != (mode_t)-1 && name == NULL) {
		*mode_r = list->file_create_mode;
		*gid_r = list->file_create_gid;
		*gid_origin_r = list->file_create_gid_origin;
		return;
	}

	mailbox_list_get_permissions_full(list, name, mode_r, &dir_mode, gid_r,
					  gid_origin_r);
}

void mailbox_list_get_dir_permissions(struct mailbox_list *list,
				      const char *name,
				      mode_t *mode_r, gid_t *gid_r,
				      const char **gid_origin_r)
{
	mode_t file_mode;

	if (list->dir_create_mode != (mode_t)-1 && name == NULL) {
		*mode_r = list->dir_create_mode;
		*gid_r = list->file_create_gid;
		*gid_origin_r = list->file_create_gid_origin;
		return;
	}

	mailbox_list_get_permissions_full(list, name, &file_mode,
					  mode_r, gid_r, gid_origin_r);
}

static int
mailbox_list_stat_parent(struct mailbox_list *list, const char *path,
			 const char **root_dir_r, struct stat *st_r)
{
	const char *p;

	while (stat(path, st_r) < 0) {
		if (errno != ENOENT || strcmp(path, "/") == 0) {
			mailbox_list_set_critical(list, "stat(%s) failed: %m",
						  path);
			return -1;
		}
		p = strrchr(path, '/');
		if (p == NULL)
			path = "/";
		else
			path = t_strdup_until(path, p);
	}
	*root_dir_r = path;
	return 0;
}

static const char *
get_expanded_path(const char *unexpanded_start, const char *unexpanded_stop,
		  const char *expanded_full)
{
	const char *ret;
	unsigned int i, slash_count = 0, slash2_count = 0;

	/* get the expanded path up to the same amount of '/' characters.
	   if there isn't the same amount of '/' characters, it means %variable
	   expansion added more of them and we can't handle this. */
	for (i = 0; unexpanded_start+i != unexpanded_stop; i++) {
		if (unexpanded_start[i] == '/')
			slash_count++;
	}
	for (; unexpanded_start[i] != '\0'; i++) {
		if (unexpanded_start[i] == '/')
			slash2_count++;
	}

	for (i = 0; expanded_full[i] != '\0'; i++) {
		if (expanded_full[i] == '/') {
			if (slash_count == 0)
				break;
			slash_count--;
		}
	}
	if (slash_count != 0)
		return "";

	ret = t_strndup(expanded_full, i);
	for (; expanded_full[i] != '\0'; i++) {
		if (expanded_full[i] == '/') {
			if (slash2_count == 0)
				return "";
			slash2_count--;
		}
	}
	if (slash2_count != 0)
		return "";
	return ret;
}

int mailbox_list_mkdir(struct mailbox_list *list, const char *path,
		       enum mailbox_list_path_type type)
{
	const char *expanded, *unexpanded, *root_dir, *p, *origin;
	struct stat st;
	mode_t mode;
	gid_t gid;

	mailbox_list_get_dir_permissions(list, NULL, &mode, &gid, &origin);

	/* get the directory path up to last %variable. for example
	   unexpanded path may be "/var/mail/%d/%2n/%n/Maildir", and we want
	   to get expanded="/var/mail/domain/nn" */
	unexpanded = mailbox_list_get_unexpanded_path(list, type);
	p = strrchr(unexpanded, '%');
	if (p == NULL)
		expanded = "";
	else {
		while (p != unexpanded && *p != '/') p--;
		if (p == unexpanded)
			expanded = "";
		else {
			expanded = mailbox_list_get_path(list, NULL, type);
			expanded = get_expanded_path(unexpanded, p, expanded);
		}
	}

	if (*expanded != '\0') {
		/* up to this directory get the permissions from the first
		   parent directory that exists, if it has setgid bit
		   enabled. */
		if (mailbox_list_stat_parent(list, expanded,
					     &root_dir, &st) < 0)
			return -1;
		if ((st.st_mode & S_ISGID) != 0 && root_dir != expanded) {
			if (mkdir_parents_chgrp(expanded, st.st_mode,
						(gid_t)-1, root_dir) < 0 &&
			    errno != EEXIST) {
				mailbox_list_set_critical(list,
					"mkdir(%s) failed: %m", expanded);
				return -1;
			}
		}
		if (gid == (gid_t)-1 && (mode & S_ISGID) == 0) {
			/* change the group for user directories */
			gid = getegid();
		}
	}

	/* the rest of the directories exist only for one user. create them
	   with default directory permissions */
	if (mkdir_parents_chgrp(path, mode, gid, origin) < 0 &&
	    errno != EEXIST) {
		mailbox_list_set_critical(list, "mkdir(%s) failed: %m", path);
		return -1;
	}
	return 0;
}

bool mailbox_list_is_valid_pattern(struct mailbox_list *list,
				   const char *pattern)
{
	bool ret;

	T_BEGIN {
		ret = list->v.is_valid_pattern(list, pattern);
	} T_END;
	return ret;
}

bool mailbox_list_is_valid_existing_name(struct mailbox_list *list,
					 const char *name)
{
	bool ret;

	if (*name == '\0' && *list->ns->prefix != '\0') {
		/* an ugly way to get to mailbox root (e.g. Maildir/ when
		   it's not the INBOX) */
		return TRUE;
	}

	T_BEGIN {
		ret = list->v.is_valid_existing_name(list, name);
	} T_END;
	return ret;
}

bool mailbox_list_is_valid_create_name(struct mailbox_list *list,
				       const char *name)
{
	const char *p;
	int ret;

	/* safer to just disallow all control characters */
	for (p = name; *p != '\0'; p++) {
		if (*p < ' ')
			return FALSE;
	}

	T_BEGIN {
		string_t *str = t_str_new(256);
		ret = imap_utf7_to_utf8(name, str);
	} T_END;
	return ret < 0 ? FALSE :
		list->v.is_valid_create_name(list, name);
}

const char *mailbox_list_get_path(struct mailbox_list *list, const char *name,
				  enum mailbox_list_path_type type)
{
	return list->v.get_path(list, name, type);
}

const char *
mailbox_list_get_root_path(const struct mailbox_list_settings *set,
			   enum mailbox_list_path_type type)
{
	const char *path;

	switch (type) {
	case MAILBOX_LIST_PATH_TYPE_DIR:
		return set->root_dir;
	case MAILBOX_LIST_PATH_TYPE_ALT_DIR:
		return set->alt_dir;
	case MAILBOX_LIST_PATH_TYPE_MAILBOX:
		if (*set->mailbox_dir_name == '\0')
			return set->root_dir;
		path = t_strconcat(set->root_dir, "/",
				   set->mailbox_dir_name, NULL);
		return t_strndup(path, strlen(path)-1);
	case MAILBOX_LIST_PATH_TYPE_ALT_MAILBOX:
		if (*set->mailbox_dir_name == '\0')
			return set->root_dir;
		path = t_strconcat(set->alt_dir, "/",
				   set->mailbox_dir_name, NULL);
		return t_strndup(path, strlen(path)-1);
	case MAILBOX_LIST_PATH_TYPE_CONTROL:
		return set->control_dir != NULL ?
			set->control_dir : set->root_dir;
	case MAILBOX_LIST_PATH_TYPE_INDEX:
		return set->index_dir != NULL ?
			set->index_dir : set->root_dir;
	}
	i_unreached();
}

const char *mailbox_list_get_temp_prefix(struct mailbox_list *list)
{
	return list->v.get_temp_prefix(list, FALSE);
}

const char *mailbox_list_get_global_temp_prefix(struct mailbox_list *list)
{
	return list->v.get_temp_prefix(list, TRUE);
}

const char *mailbox_list_join_refpattern(struct mailbox_list *list,
					 const char *ref, const char *pattern)
{
	if (list->v.join_refpattern != NULL)
		return list->v.join_refpattern(list, ref, pattern);

	/* the default implementation: */
	if (*ref != '\0') {
		/* merge reference and pattern */
		pattern = t_strconcat(ref, pattern, NULL);
	}
	return pattern;
}

int mailbox_list_get_mailbox_name_status(struct mailbox_list *list,
					 const char *name,
					 enum mailbox_name_status *status)
{
	if (!mailbox_list_is_valid_existing_name(list, name)) {
		*status = MAILBOX_NAME_INVALID;
		return 0;
	}
	return list->v.get_mailbox_name_status(list, name, status);
}

struct mailbox_list_iterate_context *
mailbox_list_iter_init(struct mailbox_list *list, const char *pattern,
		       enum mailbox_list_iter_flags flags)
{
	const char *patterns[2];

	patterns[0] = pattern;
	patterns[1] = NULL;
	return mailbox_list_iter_init_multiple(list, patterns, flags);
}

struct mailbox_list_iterate_context *
mailbox_list_iter_init_multiple(struct mailbox_list *list,
				const char *const *patterns,
				enum mailbox_list_iter_flags flags)
{
	i_assert(*patterns != NULL);

	return list->v.iter_init(list, patterns, flags);
}

static bool
ns_match_simple(struct ns_list_iterate_context *ctx, struct mail_namespace *ns)
{
	if ((ctx->type_mask & ns->type) == 0)
		return FALSE;

	if ((ctx->ctx.flags & MAILBOX_LIST_ITER_SKIP_ALIASES) != 0) {
		if (ns->alias_for != NULL)
			return FALSE;
	}
	return TRUE;
}

static bool
ns_match_inbox(struct mail_namespace *ns, const char *pattern)
{
	struct imap_match_glob *glob;

	if ((ns->flags & NAMESPACE_FLAG_INBOX_USER) == 0)
		return FALSE;

	glob = imap_match_init(pool_datastack_create(), pattern,
			       TRUE, ns->sep);
	return imap_match(glob, "INBOX") == IMAP_MATCH_YES;
}

static bool
ns_match_next(struct ns_list_iterate_context *ctx, struct mail_namespace *ns,
	      const char *pattern)
{
	struct imap_match_glob *glob;
	enum imap_match_result result;
	const char *prefix_without_sep;
	unsigned int len;

	len = ns->prefix_len;
	if (len > 0 && ns->prefix[len-1] == ns->sep)
		len--;

	if ((ns->flags & (NAMESPACE_FLAG_LIST_PREFIX |
			  NAMESPACE_FLAG_LIST_CHILDREN)) == 0) {
		/* non-listable namespace matches only with exact prefix */
		if (strncmp(ns->prefix, pattern, ns->prefix_len) != 0)
			return FALSE;
	}

	prefix_without_sep = t_strndup(ns->prefix, len);
	if (*prefix_without_sep == '\0')
		result = IMAP_MATCH_CHILDREN;
	else {
		glob = imap_match_init(pool_datastack_create(), pattern,
				       TRUE, ns->sep);
		result = imap_match(glob, prefix_without_sep);
	}

	if ((ctx->ctx.flags & MAILBOX_LIST_ITER_STAR_WITHIN_NS) == 0) {
		switch (result) {
		case IMAP_MATCH_YES:
		case IMAP_MATCH_CHILDREN:
			return TRUE;
		case IMAP_MATCH_NO:
		case IMAP_MATCH_PARENT:
			break;
		}
		return FALSE;
	}

	switch (result) {
	case IMAP_MATCH_YES:
		/* allow matching prefix only when it's done without
		   wildcards */
		if (strcmp(prefix_without_sep, pattern) == 0)
			return TRUE;
		break;
	case IMAP_MATCH_CHILDREN: {
		/* allow this only if there isn't another namespace
		   with longer prefix that matches this pattern
		   (namespaces are sorted by prefix length) */
		struct mail_namespace *tmp;

		T_BEGIN {
			for (tmp = ns->next; tmp != NULL; tmp = tmp->next) {
				if (ns_match_simple(ctx, tmp) &&
				    ns_match_next(ctx, tmp, pattern))
					break;
			}
		} T_END;
		if (tmp == NULL)
			return TRUE;
		break;
	}
	case IMAP_MATCH_NO:
	case IMAP_MATCH_PARENT:
		break;
	}
	return FALSE;
}

static bool
ns_match(struct ns_list_iterate_context *ctx, struct mail_namespace *ns)
{
	unsigned int i;

	if (!ns_match_simple(ctx, ns))
		return FALSE;

	/* filter out namespaces whose prefix doesn't match. this same code
	   handles both with and without STAR_WITHIN_NS, so the "without" case
	   is slower than necessary, but this shouldn't matter much */
	T_BEGIN {
		for (i = 0; ctx->patterns_ns_match[i] != NULL; i++) {
			if (ns_match_inbox(ns, ctx->patterns_ns_match[i]))
				break;
			if (ns_match_next(ctx, ns, ctx->patterns_ns_match[i]))
				break;
		}
	} T_END;

	return ctx->patterns_ns_match[i] != NULL;
}

static struct mail_namespace *
ns_next(struct ns_list_iterate_context *ctx, struct mail_namespace *ns)
{
	for (; ns != NULL; ns = ns->next) {
		if (ns_match(ctx, ns))
			break;
	}
	return ns;
}

static const struct mailbox_info *
mailbox_list_ns_iter_next(struct mailbox_list_iterate_context *_ctx)
{
	struct ns_list_iterate_context *ctx =
		(struct ns_list_iterate_context *)_ctx;
	const struct mailbox_info *info;

	info = ctx->backend_ctx == NULL ? NULL :
		mailbox_list_iter_next(ctx->backend_ctx);
	if (info == NULL && ctx->namespaces != NULL) {
		/* go to the next namespace */
		if (mailbox_list_iter_deinit(&ctx->backend_ctx) < 0)
			_ctx->failed = TRUE;
		ctx->ctx.list->ns = ctx->namespaces;
		ctx->backend_ctx =
			mailbox_list_iter_init_multiple(ctx->namespaces->list,
							ctx->patterns,
							_ctx->flags);
		ctx->namespaces = ns_next(ctx, ctx->namespaces->next);
		return mailbox_list_ns_iter_next(_ctx);
	}
	return info;
}

static int
mailbox_list_ns_iter_deinit(struct mailbox_list_iterate_context *_ctx)
{
	struct ns_list_iterate_context *ctx =
		(struct ns_list_iterate_context *)_ctx;
	int ret;

	if (ctx->backend_ctx != NULL) {
		if (mailbox_list_iter_deinit(&ctx->backend_ctx) < 0)
			_ctx->failed = TRUE;
	}
	ret = _ctx->failed ? -1 : 0;
	pool_unref(&ctx->pool);
	return ret;
}

static const char **
dup_patterns_without_stars(pool_t pool, const char *const *patterns,
			   unsigned int count)
{
	const char **dup;
	unsigned int i;

	dup = p_new(pool, const char *, count + 1);
	for (i = 0; i < count; i++) {
		char *p = p_strdup(pool, patterns[i]);
		dup[i] = p;

		for (; *p != '\0'; p++) {
			if (*p == '*')
				*p = '%';
		}
	}
	return dup;
}

struct mailbox_list_iterate_context *
mailbox_list_iter_init_namespaces(struct mail_namespace *namespaces,
				  const char *const *patterns,
				  enum namespace_type type_mask,
				  enum mailbox_list_iter_flags flags)
{
	struct ns_list_iterate_context *ctx;
	unsigned int i, count;
	pool_t pool;

	i_assert(namespaces != NULL);

	pool = pool_alloconly_create("mailbox list namespaces", 1024);
	ctx = p_new(pool, struct ns_list_iterate_context, 1);
	ctx->pool = pool;
	ctx->type_mask = type_mask;
	ctx->ctx.flags = flags;
	ctx->ctx.list = p_new(pool, struct mailbox_list, 1);
	ctx->ctx.list->v.iter_next = mailbox_list_ns_iter_next;
	ctx->ctx.list->v.iter_deinit = mailbox_list_ns_iter_deinit;

	count = str_array_length(patterns);
	ctx->patterns = p_new(pool, const char *, count + 1);
	for (i = 0; i < count; i++)
		ctx->patterns[i] = p_strdup(pool, patterns[i]);

	if ((flags & MAILBOX_LIST_ITER_STAR_WITHIN_NS) != 0) {
		/* create copies of patterns with '*' wildcard changed to '%' */
		ctx->patterns_ns_match =
			dup_patterns_without_stars(pool, ctx->patterns, count);
	} else {
		ctx->patterns_ns_match = ctx->patterns;
	}

	namespaces = ns_next(ctx, namespaces);
	ctx->ctx.list->ns = namespaces;
	if (namespaces != NULL) {
		ctx->backend_ctx =
			mailbox_list_iter_init_multiple(namespaces->list,
							patterns, flags);
		ctx->namespaces = ns_next(ctx, namespaces->next);
	}
	return &ctx->ctx;
}

const struct mailbox_info *
mailbox_list_iter_next(struct mailbox_list_iterate_context *ctx)
{
	const struct mailbox_info *info;

	info = ctx->list->v.iter_next(ctx);
	if (info != NULL)
		ctx->list->ns->flags |= NAMESPACE_FLAG_USABLE;
	return info;
}

int mailbox_list_iter_deinit(struct mailbox_list_iterate_context **_ctx)
{
	struct mailbox_list_iterate_context *ctx = *_ctx;

	*_ctx = NULL;

	return ctx->list->v.iter_deinit(ctx);
}

int mailbox_list_mailbox(struct mailbox_list *list, const char *name,
			 enum mailbox_info_flags *flags_r)
{
	const char *path, *fname, *rootdir, *dir, *inbox;
	struct stat st;
	unsigned int len;

	rootdir = mailbox_list_get_path(list, NULL,
					MAILBOX_LIST_PATH_TYPE_MAILBOX);
	path = mailbox_list_get_path(list, name, MAILBOX_LIST_PATH_TYPE_DIR);
	if (rootdir == NULL) {
		/* shouldn't happen with anything except shared mailboxes */
		return 0;
	}

	fname = strrchr(path, '/');
	if (fname == NULL) {
		fname = path;
		dir = "/";
	} else {
		dir = t_strdup_until(path, fname);
		fname++;
	}

	len = strlen(rootdir);
	if (strncmp(path, rootdir, len) == 0 && path[len] == '/') {
		/* looking up a regular mailbox under mail root dir */
	} else if ((list->ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0 &&
		   strcasecmp(name, "INBOX") == 0) {
		/* looking up INBOX that's elsewhere */
	} else {
		/* looking up the root dir itself */
		dir = path;
		fname = "";
	}
	if (*fname == '\0' && *name == '\0' &&
	    (list->ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0) {
		/* if INBOX is in e.g. ~/Maildir, it shouldn't be possible to
		   access it also via namespace prefix. */
		inbox = mailbox_list_get_path(list, "INBOX",
					      MAILBOX_LIST_PATH_TYPE_MAILBOX);
		if (strcmp(inbox, dir) == 0) {
			*flags_r |= MAILBOX_NONEXISTENT;
			return 0;
		}
	}
	return list->v.get_mailbox_flags(list, dir, fname,
					 MAILBOX_LIST_FILE_TYPE_UNKNOWN,
					 &st, flags_r);
}

static bool mailbox_list_init_changelog(struct mailbox_list *list)
{
	const char *path;
	mode_t mode;
	gid_t gid;
	const char *gid_origin;

	if (list->changelog != NULL)
		return TRUE;

	/* don't do this in mailbox_list_create(), because _get_path() might be
	   overridden by storage (mbox). */
	path = mailbox_list_get_path(list, NULL, MAILBOX_LIST_PATH_TYPE_INDEX);
	if (*path == '\0')
		return FALSE;

	path = t_strconcat(path, "/"MAILBOX_LOG_FILE_NAME, NULL);
	list->changelog = mailbox_log_alloc(path);

	mailbox_list_get_permissions(list, NULL, &mode, &gid, &gid_origin);
	mailbox_log_set_permissions(list->changelog, mode, gid, gid_origin);
	return TRUE;
}

void mailbox_list_add_change(struct mailbox_list *list,
			     enum mailbox_log_record_type type,
			     const uint8_t mailbox_guid[MAIL_GUID_128_SIZE])
{
	struct mailbox_log_record rec;
	time_t stamp;

	if (!mailbox_list_init_changelog(list) ||
	    mail_guid_128_is_empty(mailbox_guid))
		return;

	if (!list->index_root_dir_created) {
		if (mailbox_list_create_missing_index_dir(list, NULL) < 0)
			return;
	}

	stamp = list->changelog_timestamp != (time_t)-1 ?
		list->changelog_timestamp : ioloop_time;

	memset(&rec, 0, sizeof(rec));
	rec.type = type;
	memcpy(rec.mailbox_guid, mailbox_guid, sizeof(rec.mailbox_guid));
	mailbox_log_record_set_timestamp(&rec, stamp);
	(void)mailbox_log_append(list->changelog, &rec);
}

int mailbox_list_set_subscribed(struct mailbox_list *list,
				const char *name, bool set)
{
	uint8_t guid[MAIL_GUID_128_SIZE];
	int ret;

	if ((ret = list->v.set_subscribed(list, name, set)) <= 0)
		return ret;

	/* subscriptions are about names, not about mailboxes. it's possible
	   to have a subscription to nonexistent mailbox. renames also don't
	   change subscriptions. so instead of using actual GUIDs, we'll use
	   hash of the name. */
	mailbox_name_get_sha128(name, guid);
	mailbox_list_add_change(list, set ? MAILBOX_LOG_RECORD_SUBSCRIBE :
				MAILBOX_LOG_RECORD_UNSUBSCRIBE, guid);
	return 0;
}

int mailbox_list_create_dir(struct mailbox_list *list, const char *name)
{
	if (!mailbox_list_is_valid_create_name(list, name) || *name == '\0') {
		mailbox_list_set_error(list, MAIL_ERROR_PARAMS,
				       "Invalid mailbox name");
		return -1;
	}
	return list->v.create_mailbox_dir(list, name,
					  MAILBOX_DIR_CREATE_TYPE_ONLY_NOSELECT);
}

int mailbox_list_delete_dir(struct mailbox_list *list, const char *name)
{
	if (!mailbox_list_is_valid_existing_name(list, name) || *name == '\0') {
		mailbox_list_set_error(list, MAIL_ERROR_PARAMS,
				       "Invalid mailbox name");
		return -1;
	}
	return list->v.delete_dir(list, name);
}

void mailbox_name_get_sha128(const char *name, uint8_t guid[MAIL_GUID_128_SIZE])
{
	unsigned char sha[SHA1_RESULTLEN];

	sha1_get_digest(name, strlen(name), sha);
	memcpy(guid, sha, I_MIN(MAIL_GUID_128_SIZE, sizeof(sha)));
}

struct mailbox_log *mailbox_list_get_changelog(struct mailbox_list *list)
{
	return !mailbox_list_init_changelog(list) ? NULL : list->changelog;
}

void mailbox_list_set_changelog_timestamp(struct mailbox_list *list,
					  time_t stamp)
{
	list->changelog_timestamp = stamp;
}

static void node_fix_parents(struct mailbox_node *node)
{
	/* If we happened to create any of the parents, we need to mark them
	   nonexistent. */
	node = node->parent;
	for (; node != NULL; node = node->parent) {
		if ((node->flags & MAILBOX_MATCHED) == 0)
			node->flags |= MAILBOX_NONEXISTENT;
	}
}

static void
mailbox_list_iter_update_real(struct mailbox_list_iter_update_context *ctx,
			      const char *name)
{
	struct mail_namespace *ns = ctx->iter_ctx->list->ns;
	struct mailbox_node *node;
	enum mailbox_info_flags create_flags = 0, always_flags;
	enum imap_match_result match;
	const char *p;
	bool created, add_matched;

	if (ctx->update_only ||
	    (ctx->iter_ctx->flags & MAILBOX_LIST_ITER_RETURN_NO_FLAGS) == 0)
		create_flags = MAILBOX_NONEXISTENT | MAILBOX_NOCHILDREN;
	always_flags = ctx->leaf_flags;
	add_matched = TRUE;

	for (;;) {
		created = FALSE;
		match = imap_match(ctx->glob, name);
		if (match == IMAP_MATCH_YES) {
			node = ctx->update_only ?
				mailbox_tree_lookup(ctx->tree_ctx, name) :
				mailbox_tree_get(ctx->tree_ctx, name, &created);
			if (created) {
				node->flags = create_flags;
				if (create_flags != 0)
					node_fix_parents(node);
			}
			if (node != NULL) {
				if (!ctx->update_only && add_matched)
					node->flags |= MAILBOX_MATCHED;
				node->flags |= always_flags;
			}
			/* We don't want to show the parent mailboxes unless
			   something else matches them, but if they are matched
			   we want to show them having child subscriptions */
			add_matched = FALSE;
		} else {
			if ((match & IMAP_MATCH_PARENT) == 0)
				break;
			/* We've a (possibly) non-subscribed parent mailbox
			   which has a subscribed child mailbox. Make sure we
			   return the parent mailbox. */
		}

		if (!ctx->match_parents)
			break;

		/* see if parent matches */
		p = strrchr(name, ns->sep);
		if (p == NULL)
			break;

		name = t_strdup_until(name, p);
		create_flags &= ~MAILBOX_NOCHILDREN;
		always_flags = MAILBOX_CHILDREN | ctx->parent_flags;
	}
}

void mailbox_list_iter_update(struct mailbox_list_iter_update_context *ctx,
			      const char *name)
{
	T_BEGIN {
		mailbox_list_iter_update_real(ctx, name);
	} T_END;
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

enum mailbox_list_file_type
mailbox_list_get_file_type(const struct dirent *d ATTR_UNUSED)
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

static bool
mailbox_list_try_get_home_path(struct mailbox_list *list, const char **name)
{
	if ((*name)[1] == '/') {
		/* ~/dir - use the configured home directory */
		if (mail_user_try_home_expand(list->ns->user, name) < 0)
			return FALSE;
	} else {
		/* ~otheruser/dir - assume we're using system users */
		if (home_try_expand(name) < 0)
			return FALSE;
	}
	return TRUE;
}

bool mailbox_list_try_get_absolute_path(struct mailbox_list *list,
					const char **name)
{
	const char *root_dir, *path, *mailbox_name;
	unsigned int len;

	if (!list->mail_set->mail_full_filesystem_access)
		return FALSE;

	if (**name == '~') {
		/* try to expand home directory */
		if (!mailbox_list_try_get_home_path(list, name)) {
			/* fallback to using actual "~name" mailbox */
			return FALSE;
		}
	} else {
		if (**name != '/')
			return FALSE;
	}

	/* okay, we have an absolute path now. but check first if it points to
	   same directory as one of our regular mailboxes. */
	root_dir = mailbox_list_get_path(list, NULL,
					 MAILBOX_LIST_PATH_TYPE_MAILBOX);
	len = strlen(root_dir);
	if (strncmp(root_dir, *name, len) == 0 && (*name)[len] == '/') {
		mailbox_name = *name + len + 1;
		path = mailbox_list_get_path(list, mailbox_name,
					     MAILBOX_LIST_PATH_TYPE_MAILBOX);
		if (strcmp(path, *name) == 0) {
			/* yeah, we can replace the full path with mailbox
			   name. this way we can use indexes. */
			*name = mailbox_name;
			return FALSE;
		}
	}
	return TRUE;
}

int mailbox_list_create_parent_dir(struct mailbox_list *list,
				   const char *mailbox, const char *path)
{
	const char *p, *dir, *origin;
	gid_t gid;
	mode_t mode;

	p = strrchr(path, '/');
	if (p == NULL)
		return 0;

	dir = t_strdup_until(path, p);
	mailbox_list_get_dir_permissions(list, mailbox, &mode, &gid, &origin);
	if (mkdir_parents_chgrp(dir, mode, gid, origin) < 0 &&
	    errno != EEXIST) {
		mailbox_list_set_critical(list, "mkdir_parents(%s) failed: %m",
					  dir);
		return -1;
	}
	return 0;
}

int mailbox_list_create_missing_index_dir(struct mailbox_list *list,
					  const char *name)
{
	const char *root_dir, *index_dir, *parent_dir, *p, *origin;
	mode_t mode;
	gid_t gid;
	unsigned int n = 0;

	list->index_root_dir_created = TRUE;
	root_dir = mailbox_list_get_path(list, name,
					 MAILBOX_LIST_PATH_TYPE_MAILBOX);
	index_dir = mailbox_list_get_path(list, name,
					  MAILBOX_LIST_PATH_TYPE_INDEX);
	if (*index_dir == '\0' || strcmp(index_dir, root_dir) == 0)
		return 0;

	mailbox_list_get_dir_permissions(list, name, &mode, &gid, &origin);
	while (mkdir_chgrp(index_dir, mode, gid, origin) < 0) {
		if (errno == EEXIST)
			break;

		p = strrchr(index_dir, '/');
		if (errno != ENOENT || p == NULL || ++n == 2) {
			mailbox_list_set_critical(list,
				"mkdir(%s) failed: %m", index_dir);
			return -1;
		}
		/* create the parent directory first */
		parent_dir = t_strdup_until(index_dir, p);
		if (mailbox_list_mkdir(list, parent_dir,
				       MAILBOX_LIST_PATH_TYPE_INDEX) < 0)
			return -1;
	}
	return 0;
}

const char *mailbox_list_get_last_error(struct mailbox_list *list,
					enum mail_error *error_r)
{
	if (error_r != NULL)
		*error_r = list->error;

	return list->error_string != NULL ? list->error_string :
		"Unknown internal list error";
}

void mailbox_list_clear_error(struct mailbox_list *list)
{
	i_free_and_null(list->error_string);

	list->error = MAIL_ERROR_NONE;
}

void mailbox_list_set_error(struct mailbox_list *list,
			    enum mail_error error, const char *string)
{
	i_free(list->error_string);
	list->error_string = i_strdup(string);

	list->error = error;
}

void mailbox_list_set_internal_error(struct mailbox_list *list)
{
	struct tm *tm;
	char str[256];

	tm = localtime(&ioloop_time);

	i_free(list->error_string);
	list->error_string =
		strftime(str, sizeof(str),
			 MAIL_ERRSTR_CRITICAL_MSG_STAMP, tm) > 0 ?
		i_strdup(str) : i_strdup(MAIL_ERRSTR_CRITICAL_MSG);
	list->error = MAIL_ERROR_TEMP;
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

bool mailbox_list_set_error_from_errno(struct mailbox_list *list)
{
	const char *error_string;
	enum mail_error error;

	if (!mail_error_from_errno(&error, &error_string))
		return FALSE;

	mailbox_list_set_error(list, error, error_string);
	return TRUE;
}
