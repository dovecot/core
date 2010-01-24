/* Copyright (c) 2006-2010 Dovecot authors, see the included COPYING file */

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
	const char **patterns;
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

int mailbox_list_create(const char *driver, struct mail_namespace *ns,
			const struct mailbox_list_settings *set,
			enum mailbox_list_flags flags, const char **error_r)
{
	const struct mailbox_list *const *class_p;
	struct mailbox_list *list;
	unsigned int idx;

	i_assert(ns->list == NULL);

	i_assert(set->root_dir == NULL || *set->root_dir != '\0');
	i_assert(set->subscription_fname == NULL ||
		 *set->subscription_fname != '\0');

	if (!mailbox_list_driver_find(driver, &idx)) {
		*error_r = t_strdup_printf("Unknown mailbox list driver: %s",
					   driver);
		return -1;
	}

	class_p = array_idx(&mailbox_list_drivers, idx);
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
	list->set.root_dir = p_strdup(list->pool, set->root_dir);
	list->set.index_dir = set->index_dir == NULL ||
		strcmp(set->index_dir, set->root_dir) == 0 ? NULL :
		p_strdup(list->pool, set->index_dir);
	list->set.control_dir = set->control_dir == NULL ||
		strcmp(set->control_dir, set->root_dir) == 0 ? NULL :
		p_strdup(list->pool, set->control_dir);

	list->set.inbox_path = p_strdup(list->pool, set->inbox_path);
	list->set.subscription_fname =
		p_strdup(list->pool, set->subscription_fname);
	list->set.maildir_name = set->maildir_name == NULL ||
		(list->props & MAILBOX_LIST_PROP_NO_MAILDIR_NAME) != 0 ? "" :
		p_strdup(list->pool, set->maildir_name);
	list->set.mailbox_dir_name =
		p_strdup(list->pool, set->mailbox_dir_name);

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
		i_debug("%s: root=%s, index=%s, control=%s, inbox=%s",
			list->name,
			list->set.root_dir == NULL ? "" : list->set.root_dir,
			list->set.index_dir == NULL ? "" : list->set.index_dir,
			list->set.control_dir == NULL ?
			"" : list->set.control_dir,
			list->set.inbox_path == NULL ?
			"" : list->set.inbox_path);
	}
	mail_namespace_finish_list_init(ns, list);

	hook_mailbox_list_created(list);
	return 0;
}

static int fix_path(struct mail_namespace *ns, const char *path,
		    const char **path_r, const char **error_r)
{
	size_t len = strlen(path);

	if (len > 1 && path[len-1] == '/')
		path = t_strndup(path, len-1);
	if (path[0] == '~' && path[1] != '/') {
		/* ~otheruser/dir */
		if (home_try_expand(&path) < 0) {
			*error_r = t_strconcat(
				"No home directory for system user. "
				"Can't expand ", t_strcut(path, '/'),
				" for ", NULL);
			return -1;
		}
	} else {
		if (mail_user_try_home_expand(ns->user, &path) < 0) {
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

int mailbox_list_settings_parse(const char *data,
				struct mailbox_list_settings *set,
				struct mail_namespace *ns, const char **error_r)
{
	const char *const *tmp, *key, *value, **dest, *str, *error;

	*error_r = NULL;

	if (*data == '\0')
		return 0;

	/* <root dir> */
	tmp = t_strsplit(data, ":");
	str = split_next_arg(&tmp);
	if (fix_path(ns, str, &set->root_dir, &error) < 0) {
		*error_r = t_strconcat(error, "mail root dir in: ", data, NULL);
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
			dest = &set->inbox_path;
		else if (strcmp(key, "INDEX") == 0)
			dest = &set->index_dir;
		else if (strcmp(key, "CONTROL") == 0)
			dest = &set->control_dir;
		else if (strcmp(key, "ALT") == 0)
			dest = &set->alt_dir;
		else if (strcmp(key, "LAYOUT") == 0)
			dest = &set->layout;
		else if (strcmp(key, "SUBSCRIPTIONS") == 0)
			dest = &set->subscription_fname;
		else if (strcmp(key, "DIRNAME") == 0)
			dest = &set->maildir_name;
		else if (strcmp(key, "MAILBOXDIR") == 0)
			dest = &set->mailbox_dir_name;
		else {
			*error_r = t_strdup_printf("Unknown setting: %s", key);
			return -1;
		}
		if (fix_path(ns, value, dest, &error) < 0) {
			*error_r = t_strconcat(error, key, " in: ", data, NULL);
			return -1;
		}
	}

	if (set->index_dir != NULL && strcmp(set->index_dir, "MEMORY") == 0)
		set->index_dir = "";
	return 0;
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

char mailbox_list_get_hierarchy_sep(const struct mailbox_list *list)
{
	return list->hierarchy_sep;
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

	path = mailbox_list_get_path(list, name, MAILBOX_LIST_PATH_TYPE_DIR);
	if (stat(path, &st) < 0) {
		if (!ENOTFOUND(errno)) {
			mailbox_list_set_critical(list, "stat(%s) failed: %m",
						  path);
		} else if (list->mail_set->mail_debug) {
			i_debug("Namespace %s: Permission lookup failed from %s",
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
		/* return safe defaults */
		*file_mode_r = 0600;
		*dir_mode_r = 0700;
		*gid_r = (gid_t)-1;
		*gid_origin_r = "defaults";
	} else {
		*file_mode_r = st.st_mode & 0666;
		*dir_mode_r = st.st_mode & 0777;
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
			"mode=0%o gid=%ld", list->ns->prefix, path,
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

bool mailbox_list_is_valid_pattern(struct mailbox_list *list,
				   const char *pattern)
{
	return list->v.is_valid_pattern(list, pattern);
}

bool mailbox_list_is_valid_existing_name(struct mailbox_list *list,
					 const char *name)
{
	if (*name == '\0' && *list->ns->prefix != '\0') {
		/* an ugly way to get to mailbox root (e.g. Maildir/ when
		   it's not the INBOX) */
		return TRUE;
	}

	return list->v.is_valid_existing_name(list, name);
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

static struct mail_namespace *
ns_next(struct ns_list_iterate_context *ctx, struct mail_namespace *ns)
{
	if ((ctx->ctx.flags & MAILBOX_LIST_ITER_SKIP_ALIASES) != 0) {
		while (ns != NULL && ns->alias_for != NULL)
			ns = ns->next;
	}
	return ns;
}

static const struct mailbox_info *
mailbox_list_ns_iter_next(struct mailbox_list_iterate_context *_ctx)
{
	struct ns_list_iterate_context *ctx =
		(struct ns_list_iterate_context *)_ctx;
	const struct mailbox_info *info;

	info = mailbox_list_iter_next(ctx->backend_ctx);
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

	if (mailbox_list_iter_deinit(&ctx->backend_ctx) < 0)
		_ctx->failed = TRUE;
	ret = _ctx->failed ? -1 : 0;
	pool_unref(&ctx->pool);
	return ret;
}

struct mailbox_list_iterate_context *
mailbox_list_iter_init_namespaces(struct mail_namespace *namespaces,
				  const char *const *patterns,
				  enum mailbox_list_iter_flags flags)
{
	struct ns_list_iterate_context *ctx;
	unsigned int i, count;
	pool_t pool;

	i_assert(namespaces != NULL);

	pool = pool_alloconly_create("mailbox list namespaces", 512);
	ctx = p_new(pool, struct ns_list_iterate_context, 1);
	ctx->pool = pool;
	ctx->ctx.flags = flags;
	ctx->ctx.list = p_new(pool, struct mailbox_list, 1);
	ctx->ctx.list->v.iter_next = mailbox_list_ns_iter_next;
	ctx->ctx.list->v.iter_deinit = mailbox_list_ns_iter_deinit;

	count = str_array_length(patterns);
	ctx->patterns = p_new(pool, const char *, count + 1);
	for (i = 0; i < count; i++)
		ctx->patterns[i] = p_strdup(pool, patterns[i]);

	namespaces = ns_next(ctx, namespaces);
	ctx->ctx.list->ns = namespaces;
	ctx->backend_ctx = mailbox_list_iter_init_multiple(namespaces->list,
							   patterns, flags);
	ctx->namespaces = ns_next(ctx, namespaces->next);
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
	struct mailbox_list_iterate_context ctx;
	const char *path;

	memset(&ctx, 0, sizeof(ctx));
	ctx.list = list;

	*flags_r = 0;
	path = mailbox_list_get_path(list, name, MAILBOX_LIST_PATH_TYPE_DIR);
	return list->v.iter_is_mailbox == NULL ? 0 :
		list->v.iter_is_mailbox(&ctx, path, "", "",
					MAILBOX_LIST_FILE_TYPE_UNKNOWN,
					flags_r);
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
	if (path == NULL)
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

	if (list->v.set_subscribed(list, name, set) < 0)
		return -1;

	/* subscriptions are about names, not about mailboxes. it's possible
	   to have a subscription to non-existing mailbox. renames also don't
	   change subscriptions. so instead of using actual GUIDs, we'll use
	   hash of the name. */
	mailbox_name_get_sha128(name, guid);
	mailbox_list_add_change(list, set ? MAILBOX_LOG_RECORD_SUBSCRIBE :
				MAILBOX_LOG_RECORD_UNSUBSCRIBE, guid);
	return 0;
}

int mailbox_list_delete_mailbox(struct mailbox_list *list, const char *name)
{
	if (!mailbox_list_is_valid_existing_name(list, name) || *name == '\0') {
		mailbox_list_set_error(list, MAIL_ERROR_PARAMS,
				       "Invalid mailbox name");
		return -1;
	}
	if (strcmp(name, "INBOX") == 0 &&
	    (list->ns->flags & NAMESPACE_FLAG_INBOX) != 0) {
		mailbox_list_set_error(list, MAIL_ERROR_NOTPOSSIBLE,
				       "INBOX can't be deleted.");
		return -1;
	}
	return list->v.delete_mailbox(list, name);
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

static bool nullequals(const void *p1, const void *p2)
{
	return (p1 == NULL && p2 == NULL) || (p1 != NULL && p2 != NULL);
}

int mailbox_list_rename_mailbox(struct mailbox_list *oldlist,
				const char *oldname,
				struct mailbox_list *newlist,
				const char *newname, bool rename_children)
{
	struct mail_storage *oldstorage;
	struct mail_storage *newstorage;
	uint8_t guid[MAIL_GUID_128_SIZE];

	if (mailbox_list_get_storage(&oldlist, &oldname, &oldstorage) < 0)
		return -1;

	newstorage = oldstorage;
	mailbox_list_get_closest_storage(newlist, &newstorage);

	if (!mailbox_list_is_valid_existing_name(oldlist, oldname) ||
	    *oldname == '\0' ||
	    !mailbox_list_is_valid_create_name(newlist, newname)) {
		mailbox_list_set_error(oldlist, MAIL_ERROR_PARAMS,
				       "Invalid mailbox name");
		return -1;
	}
	if (strcmp(oldstorage->name, newstorage->name) != 0) {
		mailbox_list_set_error(oldlist, MAIL_ERROR_NOTPOSSIBLE,
			"Can't rename mailbox to another storage type.");
		return -1;
	}
	if (!nullequals(oldlist->set.index_dir, newlist->set.index_dir) ||
	    !nullequals(oldlist->set.control_dir, newlist->set.control_dir)) {
		mailbox_list_set_error(oldlist, MAIL_ERROR_NOTPOSSIBLE,
			"Can't rename mailboxes across specified storages.");
		return -1;
	}
	if (oldlist->ns->type != NAMESPACE_PRIVATE ||
	    newlist->ns->type != NAMESPACE_PRIVATE) {
		mailbox_list_set_error(oldlist, MAIL_ERROR_NOTPOSSIBLE,
			"Renaming not supported across non-private namespaces.");
		return -1;
	}

	if (oldlist->v.rename_mailbox(oldlist, oldname, newlist, newname,
				      rename_children) < 0)
		return -1;

	/* we'll track mailbox names, instead of GUIDs. We may be renaming a
	   non-selectable mailbox (directory), which doesn't even have a GUID */
	mailbox_name_get_sha128(newname, guid);
	mailbox_list_add_change(oldlist, MAILBOX_LOG_RECORD_RENAME, guid);
	return 0;
}

void mailbox_name_get_sha128(const char *name, uint8_t guid[MAIL_GUID_128_SIZE])
{
	unsigned char sha[SHA1_RESULTLEN];

	sha1_get_digest(name, strlen(name), sha);
	memcpy(guid, sha, I_MIN(sizeof(guid), sizeof(sha)));
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

static int mailbox_list_try_delete(struct mailbox_list *list, const char *dir)
{
	if (unlink_directory(dir, TRUE) == 0 || errno == ENOENT)
		return 0;

	if (errno == ENOTEMPTY) {
		/* We're most likely using NFS and we can't delete
		   .nfs* files. */
		mailbox_list_set_error(list, MAIL_ERROR_INUSE,
			"Mailbox is still open in another session, "
			"can't delete it.");
	} else {
		mailbox_list_set_critical(list,
			"unlink_directory(%s) failed: %m", dir);
	}
	return -1;
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
		if (mailbox_list_try_delete(list, index_dir) < 0)
			return -1;
	}

	/* control directory next */
	dir = mailbox_list_get_path(list, name, MAILBOX_LIST_PATH_TYPE_CONTROL);
	if (*dir != '\0' && strcmp(dir, path) != 0 &&
	    strcmp(dir, index_dir) != 0) {
		if (mailbox_list_try_delete(list, dir) < 0)
			return -1;
	}
	return 0;
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

bool mailbox_list_try_get_absolute_path(struct mailbox_list *list,
					const char **name)
{
	if (!list->mail_set->mail_full_filesystem_access)
		return FALSE;

	if (**name == '/')
		return TRUE;
	if (**name != '~')
		return FALSE;

	/* try to expand home directory */
	if ((*name)[1] == '/') {
		/* ~/dir - use the configured home directory */
		if (mail_user_try_home_expand(list->ns->user, name) == 0)
			return TRUE;
	} else {
		/* ~otheruser/dir - assume we're using system users */
		if (home_try_expand(name) == 0)
			return TRUE;
	}
	/* fallback to using ~dir */
	return FALSE;
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
