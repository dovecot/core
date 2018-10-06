/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "path-util.h"
#include "ioloop.h"
#include "file-create-locked.h"
#include "mkdir-parents.h"
#include "hex-binary.h"
#include "str.h"
#include "sha1.h"
#include "hash.h"
#include "home-expand.h"
#include "time-util.h"
#include "unichar.h"
#include "settings-parser.h"
#include "iostream-ssl.h"
#include "fs-api-private.h"
#include "imap-utf7.h"
#include "mailbox-log.h"
#include "mailbox-tree.h"
#include "mail-storage-private.h"
#include "mail-storage-hooks.h"
#include "mailbox-list-private.h"

#include <time.h>
#include <ctype.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#define MAILBOX_LIST_LOCK_FNAME "mailboxes.lock"
#define MAILBOX_LIST_LOCK_SECS 60

#define MAILBOX_LIST_FS_CONTEXT(obj) \
	MODULE_CONTEXT(obj, mailbox_list_fs_module)

struct mailbox_list_fs_context {
	union fs_api_module_context module_ctx;
	struct mailbox_list *list;
};

struct mailbox_list_module_register mailbox_list_module_register = { 0 };

static ARRAY(const struct mailbox_list *) mailbox_list_drivers;
static MODULE_CONTEXT_DEFINE_INIT(mailbox_list_fs_module,
				  &fs_api_module_register);

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
			enum mailbox_list_flags flags,
			struct mailbox_list **list_r, const char **error_r)
{
	const struct mailbox_list *class;
	struct mailbox_list *list;

	i_assert(ns->list == NULL ||
		 (flags & MAILBOX_LIST_FLAG_SECONDARY) != 0);

	i_assert(set->subscription_fname == NULL ||
		 *set->subscription_fname != '\0');

	if ((class = mailbox_list_find_class(driver)) == NULL) {
		*error_r = "Unknown driver name";
		return -1;
	}

	if ((class->props & MAILBOX_LIST_PROP_NO_MAILDIR_NAME) != 0 &&
	    *set->maildir_name != '\0') {
		*error_r = "maildir_name not supported by this driver";
		return -1;
	}
	if ((class->props & MAILBOX_LIST_PROP_NO_ALT_DIR) != 0 &&
	    set->alt_dir != NULL) {
		*error_r = "alt_dir not supported by this driver";
		return -1;
	}

	i_assert(set->root_dir == NULL || *set->root_dir != '\0' ||
		 (class->props & MAILBOX_LIST_PROP_NO_ROOT) != 0);

	list = class->v.alloc();
	array_create(&list->module_contexts, list->pool, sizeof(void *), 5);

	list->ns = ns;
	list->mail_set = ns->mail_set;
	list->flags = flags;
	list->root_permissions.file_create_mode = (mode_t)-1;
	list->root_permissions.dir_create_mode = (mode_t)-1;
	list->root_permissions.file_create_gid = (gid_t)-1;
	list->changelog_timestamp = (time_t)-1;
	if (set->no_noselect)
		list->props |= MAILBOX_LIST_PROP_NO_NOSELECT;

	/* copy settings */
	if (set->root_dir != NULL) {
		list->set.root_dir = p_strdup(list->pool, set->root_dir);
		list->set.index_dir = set->index_dir == NULL ||
			strcmp(set->index_dir, set->root_dir) == 0 ? NULL :
			p_strdup(list->pool, set->index_dir);
		list->set.index_pvt_dir = set->index_pvt_dir == NULL ||
			strcmp(set->index_pvt_dir, set->root_dir) == 0 ? NULL :
			p_strdup(list->pool, set->index_pvt_dir);
		list->set.index_cache_dir = set->index_cache_dir == NULL ||
			strcmp(set->index_cache_dir, set->root_dir) == 0 ? NULL :
			p_strdup(list->pool, set->index_cache_dir);
		list->set.control_dir = set->control_dir == NULL ||
			strcmp(set->control_dir, set->root_dir) == 0 ? NULL :
			p_strdup(list->pool, set->control_dir);
	}

	list->set.inbox_path = p_strdup(list->pool, set->inbox_path);
	list->set.subscription_fname =
		p_strdup(list->pool, set->subscription_fname);
	list->set.list_index_fname =
		p_strdup(list->pool, set->list_index_fname);
	list->set.list_index_dir =
		p_strdup(list->pool, set->list_index_dir);
	list->set.maildir_name =
		p_strdup(list->pool, set->maildir_name);
	list->set.mailbox_dir_name =
		p_strdup(list->pool, set->mailbox_dir_name);
	list->set.alt_dir = p_strdup(list->pool, set->alt_dir);
	list->set.alt_dir_nocheck = set->alt_dir_nocheck;
	list->set.volatile_dir = p_strdup(list->pool, set->volatile_dir);
	list->set.index_control_use_maildir_name =
		set->index_control_use_maildir_name;
	list->set.iter_from_index_dir = set->iter_from_index_dir;
	list->set.no_noselect = set->no_noselect;

	if (*set->mailbox_dir_name == '\0')
		list->set.mailbox_dir_name = "";
	else if (set->mailbox_dir_name[strlen(set->mailbox_dir_name)-1] == '/') {
		list->set.mailbox_dir_name =
			p_strdup(list->pool, set->mailbox_dir_name);
	} else {
		list->set.mailbox_dir_name =
			p_strconcat(list->pool, set->mailbox_dir_name, "/", NULL);
	}
	list->set.escape_char = set->escape_char;
	list->set.broken_char = set->broken_char;
	list->set.utf8 = set->utf8;

	if (list->v.init != NULL) {
		if (list->v.init(list, error_r) < 0) {
			list->v.deinit(list);
			return -1;
		}
	}

	e_debug(ns->user->event,
		"%s: root=%s, index=%s, indexpvt=%s, control=%s, inbox=%s, alt=%s",
		list->name,
		list->set.root_dir == NULL ? "" : list->set.root_dir,
		list->set.index_dir == NULL ? "" : list->set.index_dir,
		list->set.index_pvt_dir == NULL ? "" : list->set.index_pvt_dir,
		list->set.control_dir == NULL ?
		"" : list->set.control_dir,
		list->set.inbox_path == NULL ?
		"" : list->set.inbox_path,
		list->set.alt_dir == NULL ? "" : list->set.alt_dir);
	if ((flags & MAILBOX_LIST_FLAG_SECONDARY) == 0)
		mail_namespace_finish_list_init(ns, list);

	*list_r = list;

	hook_mailbox_list_created(list);
	return 0;
}

static int fix_path(struct mail_user *user, const char *path, bool expand_home,
		    const char **path_r, const char **error_r)
{
	size_t len = strlen(path);

	if (len > 1 && path[len-1] == '/')
		path = t_strndup(path, len-1);
	if (!expand_home) {
		/* no ~ expansion */
	} else if (path[0] == '~' && path[1] != '/' && path[1] != '\0') {
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

void mailbox_list_settings_init_defaults(struct mailbox_list_settings *set_r)
{
	i_zero(set_r);
	set_r->mailbox_dir_name = "";
	set_r->maildir_name = "";
	set_r->list_index_fname = MAILBOX_LIST_INDEX_DEFAULT_PREFIX;
}

static int
mailbox_list_settings_parse_full(struct mail_user *user, const char *data,
				 bool expand_home,
				 struct mailbox_list_settings *set_r,
				 const char **error_r)
{
	const char *const *tmp, *key, *value, **dest, *str, *fname, *error;

	*error_r = NULL;

	mailbox_list_settings_init_defaults(set_r);
	if (*data == '\0')
		return 0;

	/* <root dir> */
	tmp = t_strsplit(data, ":");
	str = split_next_arg(&tmp);
	if (fix_path(user, str, expand_home, &set_r->root_dir, &error) < 0) {
		*error_r = t_strconcat(error, "mail root dir in: ", data, NULL);
		return -1;
	}
	if (str_begins(set_r->root_dir, "INBOX=")) {
		/* probably mbox user trying to avoid root_dir */
		*error_r = t_strconcat("Mail root directory not given: ",
				       data, NULL);
		return -1;
	}

	while (*tmp != NULL) {
		str = split_next_arg(&tmp);
		if (strcmp(str, "UTF-8") == 0) {
			set_r->utf8 = TRUE;
			continue;
		}

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
		else if (strcmp(key, "INDEXPVT") == 0)
			dest = &set_r->index_pvt_dir;
		else if (strcmp(key, "INDEXCACHE") == 0)
			dest = &set_r->index_cache_dir;
		else if (strcmp(key, "CONTROL") == 0)
			dest = &set_r->control_dir;
		else if (strcmp(key, "ALT") == 0)
			dest = &set_r->alt_dir;
		else if (strcmp(key, "ALTNOCHECK") == 0) {
			set_r->alt_dir_nocheck = TRUE;
			continue;
		} else if (strcmp(key, "LAYOUT") == 0)
			dest = &set_r->layout;
		else if (strcmp(key, "SUBSCRIPTIONS") == 0)
			dest = &set_r->subscription_fname;
		else if (strcmp(key, "DIRNAME") == 0)
			dest = &set_r->maildir_name;
		else if (strcmp(key, "MAILBOXDIR") == 0)
			dest = &set_r->mailbox_dir_name;
		else if (strcmp(key, "VOLATILEDIR") == 0)
			dest = &set_r->volatile_dir;
		else if (strcmp(key, "LISTINDEX") == 0)
			dest = &set_r->list_index_fname;
		else if (strcmp(key, "FULLDIRNAME") == 0) {
			set_r->index_control_use_maildir_name = TRUE;
			dest = &set_r->maildir_name;
		} else if (strcmp(key, "BROKENCHAR") == 0) {
			if (strlen(value) != 1) {
				*error_r = "BROKENCHAR value must be a single character";
				return -1;
			}
			set_r->broken_char = value[0];
			continue;
		} else if (strcmp(key, "ITERINDEX") == 0) {
			set_r->iter_from_index_dir = TRUE;
			continue;
		} else if (strcmp(key, "NO-NOSELECT") == 0) {
			set_r->no_noselect = TRUE;
			continue;
		} else if (strcmp(key, "NO-FS-VALIDATION") == 0) {
			set_r->no_fs_validation = TRUE;
			continue;
		} else {
			*error_r = t_strdup_printf("Unknown setting: %s", key);
			return -1;
		}
		if (fix_path(user, value, expand_home, dest, &error) < 0) {
			*error_r = t_strconcat(error, key, " in: ", data, NULL);
			return -1;
		}
	}

	if (set_r->index_dir != NULL && strcmp(set_r->index_dir, "MEMORY") == 0)
		set_r->index_dir = "";
	if (set_r->iter_from_index_dir &&
	    (set_r->index_dir == NULL || set_r->index_dir[0] == '\0')) {
		*error_r = "ITERINDEX requires INDEX to be explicitly set";
		return -1;
	}
	if (set_r->list_index_fname != NULL &&
	    (fname = strrchr(set_r->list_index_fname, '/')) != NULL) {
		/* non-default LISTINDEX directory */
		set_r->list_index_dir =
			t_strdup_until(set_r->list_index_fname, fname);
		set_r->list_index_fname = fname+1;
		if (set_r->list_index_dir[0] != '/' &&
		    set_r->index_dir != NULL && set_r->index_dir[0] == '\0') {
			*error_r = "LISTINDEX directory is relative but INDEX=MEMORY";
			return -1;
		}
	}
	return 0;
}

int mailbox_list_settings_parse(struct mail_user *user, const char *data,
				struct mailbox_list_settings *set_r,
				const char **error_r)
{
	return mailbox_list_settings_parse_full(user, data, TRUE,
						set_r, error_r);
}

const char *mailbox_list_get_unexpanded_path(struct mailbox_list *list,
					     enum mailbox_list_path_type type)
{
	const struct mail_storage_settings *mail_set;
	const char *location = list->ns->unexpanded_set->location;
	struct mail_user *user = list->ns->user;
	struct mailbox_list_settings set;
	const char *p, *path, *error;

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

	if (mailbox_list_settings_parse_full(user, p + 1, FALSE,
					     &set, &error) < 0)
		return "";
	if (!mailbox_list_set_get_root_path(&set, type, &path))
		return "";
	return path;
}

static bool need_escape_dirstart(const char *vname, const char *maildir_name)
{
	size_t len;

	if (vname[0] == '.') {
		if (vname[1] == '\0' || vname[1] == '/')
			return TRUE; /* "." */
		if (vname[1] == '.' && (vname[2] == '\0' || vname[2] == '/'))
			return TRUE; /* ".." */
	}
	if (*maildir_name != '\0') {
		len = strlen(maildir_name);
		if (str_begins(vname, maildir_name) &&
		    (vname[len] == '\0' || vname[len] == '/'))
			return TRUE; /* e.g. dbox-Mails */
	}
	return FALSE;
}

const char *
mailbox_list_escape_name_params(const char *vname, const char *ns_prefix,
				char ns_sep, char list_sep, char escape_char,
				const char *maildir_name)
{
	size_t ns_prefix_len = strlen(ns_prefix);
	string_t *escaped_name = t_str_new(64);
	bool dirstart = TRUE;

	/* no escaping of namespace prefix */
	if (str_begins(vname, ns_prefix)) {
		str_append_data(escaped_name, vname, ns_prefix_len);
		vname += ns_prefix_len;
	}

	/* escape the mailbox name */
	if (*vname == '~') {
		str_printfa(escaped_name, "%c%02x", escape_char, *vname);
		vname++;
		dirstart = FALSE;
	}
	for (; *vname != '\0'; vname++) {
		if (*vname == ns_sep)
			str_append_c(escaped_name, list_sep);
		else if (*vname == list_sep ||
			 *vname == escape_char ||
			 *vname == '/' ||
			 (dirstart &&
			  need_escape_dirstart(vname, maildir_name))) {
			str_printfa(escaped_name, "%c%02x",
				    escape_char, *vname);
		} else {
			str_append_c(escaped_name, *vname);
		}
		dirstart = *vname == '/';
	}
	return str_c(escaped_name);
}

const char *
mailbox_list_escape_name(struct mailbox_list *list, const char *vname)
{
	return mailbox_list_escape_name_params(vname, list->ns->prefix,
				mail_namespace_get_sep(list->ns),
				mailbox_list_get_hierarchy_sep(list),
				list->set.escape_char, list->set.maildir_name);
}

static int
mailbox_list_unescape_broken_chars(struct mailbox_list *list, char *name)
{
	char *src, *dest;
	unsigned char chr;

	if ((src = strchr(name, list->set.broken_char)) == NULL)
		return 0;
	dest = src;

	while (*src != '\0') {
		if (*src == list->set.broken_char) {
			if (src[1] >= '0' && src[1] <= '9')
				chr = (src[1]-'0') * 0x10;
			else if (src[1] >= 'a' && src[1] <= 'f')
				chr = (src[1]-'a' + 10) * 0x10;
			else
				return -1;

			if (src[2] >= '0' && src[2] <= '9')
				chr += src[2]-'0';
			else if (src[2] >= 'a' && src[2] <= 'f')
				chr += src[2]-'a' + 10;
			else
				return -1;
			*dest++ = chr;
			src += 3;
		} else {
			*dest++ = *src++;
		}
	}
	*dest++ = '\0';
	return 0;
}

static char *mailbox_list_convert_sep(const char *storage_name, char src, char dest)
{
	char *ret, *p;

	ret = p_strdup(unsafe_data_stack_pool, storage_name);
	for (p = ret; *p != '\0'; p++) {
		if (*p == src)
			*p = dest;
	}
	return ret;
}

const char *mailbox_list_default_get_storage_name(struct mailbox_list *list,
						  const char *vname)
{
	struct mail_namespace *ns = list->ns;
	size_t prefix_len = strlen(ns->prefix);
	const char *storage_name = vname;
	string_t *str;
	char list_sep, ns_sep, *ret;

	if (strcasecmp(storage_name, "INBOX") == 0 &&
	    (ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0)
		storage_name = "INBOX";
	else if (list->set.escape_char != '\0')
		storage_name = mailbox_list_escape_name(list, vname);

	if (prefix_len > 0 && (strcmp(storage_name, "INBOX") != 0 ||
			       (ns->flags & NAMESPACE_FLAG_INBOX_USER) == 0)) {
		/* skip namespace prefix, except if this is INBOX */
		if (strncmp(ns->prefix, storage_name, prefix_len) == 0)
			storage_name += prefix_len;
		else if (strncmp(ns->prefix, storage_name, prefix_len-1) == 0 &&
			 strlen(storage_name) == prefix_len-1 &&
			 ns->prefix[prefix_len-1] == mail_namespace_get_sep(ns)) {
			/* trying to access the namespace prefix itself */
			storage_name = "";
		} else {
			/* we're converting a nonexistent mailbox name,
			   such as a LIST pattern. */
		}
	}

	if (!list->set.utf8) {
		/* UTF-8 -> mUTF-7 conversion */
		str = t_str_new(strlen(storage_name)*2);
		if (imap_utf8_to_utf7(storage_name, str) < 0)
			i_panic("Mailbox name not UTF-8: %s", vname);
		storage_name = str_c(str);
	}

	list_sep = mailbox_list_get_hierarchy_sep(list);
	ns_sep = mail_namespace_get_sep(ns);

	if (*storage_name == '\0' && ns->type == MAIL_NAMESPACE_TYPE_SHARED &&
	    (ns->flags & NAMESPACE_FLAG_INBOX_ANY) != 0 &&
	    !list->mail_set->mail_shared_explicit_inbox) {
		/* opening shared/$user. it's the same as INBOX. */
		storage_name = "INBOX";
	}

	if (list_sep != ns_sep && list->set.escape_char == '\0') {
		if (ns->type == MAIL_NAMESPACE_TYPE_SHARED &&
		    (ns->flags & NAMESPACE_FLAG_AUTOCREATED) == 0) {
			/* shared namespace root. the backend storage's
			   hierarchy separator isn't known yet, so do
			   nothing. */
			return storage_name;
		}

		ret = mailbox_list_convert_sep(storage_name, ns_sep, list_sep);
	} else if (list->set.broken_char == '\0' ||
		   strchr(storage_name, list->set.broken_char) == NULL) {
		/* no need to convert broken chars */
		return storage_name;
	} else {
		ret = p_strdup(unsafe_data_stack_pool, storage_name);
	}

	if (list->set.broken_char != '\0') {
		if (mailbox_list_unescape_broken_chars(list, ret) < 0) {
			ret = mailbox_list_convert_sep(storage_name,
						       ns_sep, list_sep);
		}
	}
	return ret;
}

const char *mailbox_list_get_storage_name(struct mailbox_list *list,
					  const char *vname)
{
	return list->v.get_storage_name(list, vname);
}

const char *
mailbox_list_unescape_name_params(const char *src, const char *ns_prefix,
				  char ns_sep, char list_sep, char escape_char)
{
	size_t ns_prefix_len = strlen(ns_prefix);
	string_t *dest = t_str_new(strlen(src));
	unsigned int num;

	if (str_begins(src, ns_prefix)) {
		str_append_data(dest, src, ns_prefix_len);
		src += ns_prefix_len;
	}

	for (; *src != '\0'; src++) {
		if (*src == escape_char &&
		    i_isxdigit(src[1]) && i_isxdigit(src[2])) {
			if (src[1] >= '0' && src[1] <= '9')
				num = src[1] - '0';
			else
				num = i_toupper(src[1]) - 'A' + 10;
			num *= 16;
			if (src[2] >= '0' && src[2] <= '9')
				num += src[2] - '0';
			else
				num += i_toupper(src[2]) - 'A' + 10;

			str_append_c(dest, num);
			src += 2;
		} else if (*src == list_sep)
			str_append_c(dest, ns_sep);
		else
			str_append_c(dest, *src);
	}
	return str_c(dest);
}

const char *
mailbox_list_unescape_name(struct mailbox_list *list, const char *src)
{
	return mailbox_list_unescape_name_params(src, list->ns->prefix,
				mail_namespace_get_sep(list->ns),
				mailbox_list_get_hierarchy_sep(list),
				list->set.escape_char);
}

static void
mailbox_list_escape_broken_chars(struct mailbox_list *list, string_t *str)
{
	unsigned int i;
	char buf[3];

	if (strchr(str_c(str), list->set.broken_char) == NULL)
		return;

	for (i = 0; i < str_len(str); i++) {
		if (str_c(str)[i] == list->set.broken_char) {
			i_snprintf(buf, sizeof(buf), "%02x",
				   list->set.broken_char);
			str_insert(str, i+1, buf);
			i += 2;
		}
	}
}

static void
mailbox_list_escape_broken_name(struct mailbox_list *list,
				const char *vname, string_t *str)
{
	str_truncate(str, 0);
	for (; *vname != '\0'; vname++) {
		if (*vname == '&' || (unsigned char)*vname >= 0x80) {
			str_printfa(str, "%c%02x", list->set.broken_char,
				    (unsigned char)*vname);
		} else {
			str_append_c(str, *vname);
		}
	}
}

const char *mailbox_list_default_get_vname(struct mailbox_list *list,
					   const char *storage_name)
{
	size_t i, prefix_len, name_len;
	const char *vname = storage_name;
	char list_sep, ns_sep, *ret;

	if ((list->ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0 &&
	    strcmp(vname, "INBOX") == 0 &&
	    list->ns->user == list->ns->owner) {
		/* user's INBOX - use as-is. NOTE: don't do case-insensitive
		   comparison, otherwise we can't differentiate between INBOX
		   and <ns prefix>/inBox. */
		return vname;
	}
	if (strcmp(vname, "INBOX") == 0 &&
	    list->ns->type == MAIL_NAMESPACE_TYPE_SHARED &&
	    (list->ns->flags & NAMESPACE_FLAG_INBOX_ANY) != 0 &&
	    !list->mail_set->mail_shared_explicit_inbox) {
		/* convert to shared/$user, we don't really care about the
		   INBOX suffix here. */
		vname = "";
	}
	if (*vname == '\0') {
		/* return namespace prefix without the separator */
		if (list->ns->prefix_len == 0)
			return list->ns->prefix;
		else {
			return t_strndup(list->ns->prefix,
					 list->ns->prefix_len - 1);
		}
	} else if (!list->set.utf8) {
		/* mUTF-7 -> UTF-8 conversion */
		string_t *str = t_str_new(strlen(vname));
		if (imap_utf7_to_utf8(vname, str) == 0) {
			if (list->set.broken_char != '\0')
				mailbox_list_escape_broken_chars(list, str);
			vname = str_c(str);
		} else if (list->set.broken_char != '\0') {
			mailbox_list_escape_broken_name(list, vname, str);
			vname = str_c(str);
		}
	}

	prefix_len = strlen(list->ns->prefix);
	if (list->set.escape_char != '\0') {
		vname = mailbox_list_unescape_name(list, vname);
		return prefix_len == 0 ? vname :
			t_strconcat(list->ns->prefix, vname, NULL);
	}

	list_sep = mailbox_list_get_hierarchy_sep(list);
	ns_sep = mail_namespace_get_sep(list->ns);

	if (list_sep != ns_sep || prefix_len > 0) {
		/* @UNSAFE */
		name_len = strlen(vname);
		ret = t_malloc_no0(MALLOC_ADD(prefix_len, name_len) + 1);
		memcpy(ret, list->ns->prefix, prefix_len);
		for (i = 0; i < name_len; i++) {
			ret[i + prefix_len] =
				vname[i] == list_sep ? ns_sep : vname[i];
		}
		ret[i + prefix_len] = '\0';
		vname = ret;
	}
	return vname;
}

const char *mailbox_list_get_vname(struct mailbox_list *list, const char *name)
{
	return list->v.get_vname(list, name);
}

void mailbox_list_destroy(struct mailbox_list **_list)
{
	struct mailbox_list *list = *_list;

	*_list = NULL;
	i_free_and_null(list->error_string);
	i_free(list->last_internal_error);

	if (hash_table_is_created(list->guid_cache)) {
		hash_table_destroy(&list->guid_cache);
		pool_unref(&list->guid_cache_pool);
	}

	if (list->subscriptions != NULL)
		mailbox_tree_deinit(&list->subscriptions);
	if (list->changelog != NULL)
		mailbox_log_free(&list->changelog);

	if (array_is_created(&list->error_stack)) {
		i_assert(array_count(&list->error_stack) == 0);
		array_free(&list->error_stack);
	}
	list->v.deinit(list);
}

const char *mailbox_list_get_driver_name(const struct mailbox_list *list)
{
	return list->name;
}

const struct mailbox_list_settings *
mailbox_list_get_settings(const struct mailbox_list *list)
{
	return &list->set;
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

static int
mailbox_list_get_storage_driver(struct mailbox_list *list, const char *driver,
				struct mail_storage **storage_r)
{
	struct mail_storage *const *storagep;
	const char *error, *data;

	array_foreach(&list->ns->all_storages, storagep) {
		if (strcmp((*storagep)->name, driver) == 0) {
			*storage_r = *storagep;
			return 0;
		}
	}

	data = i_strchr_to_next(list->ns->set->location, ':');
	if (data == NULL)
		data = "";
	if (mail_storage_create_full(list->ns, driver, data, 0,
				     storage_r, &error) < 0) {
		mailbox_list_set_critical(list,
			"Namespace %s: Failed to create storage '%s': %s",
			list->ns->prefix, driver, error);
		return -1;
	}
	return 0;
}

int mailbox_list_get_storage(struct mailbox_list **list, const char *vname,
			     struct mail_storage **storage_r)
{
	const struct mailbox_settings *set;

	if ((*list)->v.get_storage != NULL)
		return (*list)->v.get_storage(list, vname, storage_r);

	set = mailbox_settings_find((*list)->ns, vname);
	if (set != NULL && set->driver != NULL && set->driver[0] != '\0') {
		return mailbox_list_get_storage_driver(*list, set->driver,
						       storage_r);
	}
	*storage_r = mail_namespace_get_default_storage((*list)->ns);
	return 0;
}

void mailbox_list_get_default_storage(struct mailbox_list *list,
				      struct mail_storage **storage)
{
	*storage = mail_namespace_get_default_storage(list->ns);
}

char mailbox_list_get_hierarchy_sep(struct mailbox_list *list)
{
	/* the current API doesn't allow returning an error, so imap code
	   looks at the list's last error. make sure the error is cleared
	   so the error-check doesn't return something irrelevant */
	mailbox_list_clear_error(list);
	return list->v.get_hierarchy_sep(list);
}

static bool
mailbox_list_get_permissions_stat(struct mailbox_list *list, const char *path,
				  struct mailbox_permissions *permissions_r)
{
	struct stat st;

	if (stat(path, &st) < 0) {
		if (errno == EACCES) {
			mailbox_list_set_critical(list, "%s",
				mail_error_eacces_msg("stat", path));
		} else if (!ENOTFOUND(errno)) {
			mailbox_list_set_critical(list, "stat(%s) failed: %m",
						  path);
		} else {
			e_debug(list->ns->user->event,
				"Namespace %s: %s doesn't exist yet, "
				"using default permissions",
				list->ns->prefix, path);
		}
		return FALSE;
	}

	permissions_r->file_uid = st.st_uid;
	permissions_r->file_gid = st.st_gid;
	permissions_r->file_create_mode = (st.st_mode & 0666) | 0600;
	permissions_r->dir_create_mode = (st.st_mode & 0777) | 0700;
	permissions_r->file_create_gid_origin = path;

	if (!S_ISDIR(st.st_mode)) {
		/* we're getting permissions from a file.
		   apply +x modes as necessary. */
		permissions_r->dir_create_mode =
			get_dir_mode(permissions_r->dir_create_mode);
	}

	if (S_ISDIR(st.st_mode) && (st.st_mode & S_ISGID) != 0) {
		/* directory's GID is used automatically for new files */
		permissions_r->file_create_gid = (gid_t)-1;
	} else if ((st.st_mode & 0070) >> 3 == (st.st_mode & 0007)) {
		/* group has same permissions as world, so don't bother
		   changing it */
		permissions_r->file_create_gid = (gid_t)-1;
	} else if (getegid() == st.st_gid) {
		/* using our own gid, no need to change it */
		permissions_r->file_create_gid = (gid_t)-1;
	} else {
		permissions_r->file_create_gid = st.st_gid;
	}
	if (!S_ISDIR(st.st_mode) &&
	    permissions_r->file_create_gid != (gid_t)-1) {
		/* we need to stat() the parent directory to see if
		   it has setgid-bit set */
		const char *p = strrchr(path, '/');
		const char *parent_path = p == NULL ? NULL :
			t_strdup_until(path, p);
		if (parent_path != NULL &&
		    stat(parent_path, &st) == 0 &&
		    (st.st_mode & S_ISGID) != 0) {
			/* directory's GID is used automatically for
			   new files */
			permissions_r->file_create_gid = (gid_t)-1;
		}
	}
	return TRUE;
}

static void ATTR_NULL(2)
mailbox_list_get_permissions_internal(struct mailbox_list *list,
				      const char *name,
				      struct mailbox_permissions *permissions_r)
{
	const char *path = NULL, *parent_name, *p;

	i_zero(permissions_r);

	/* use safe defaults */
	permissions_r->file_uid = (uid_t)-1;
	permissions_r->file_gid = (gid_t)-1;
	permissions_r->file_create_mode = 0600;
	permissions_r->dir_create_mode = 0700;
	permissions_r->file_create_gid = (gid_t)-1;
	permissions_r->file_create_gid_origin = "defaults";

	if (list->set.iter_from_index_dir ||
	    (list->flags & MAILBOX_LIST_FLAG_NO_MAIL_FILES) != 0) {
		/* a) iterating from index dir. Use the index dir's permissions
		   as well, since they might be in a faster storage.

		   b) mail files don't exist in storage, but index files
		   might. */
		(void)mailbox_list_get_path(list, name,
			MAILBOX_LIST_PATH_TYPE_INDEX, &path);
	}

	if (name != NULL && path == NULL) {
		if (mailbox_list_get_path(list, name, MAILBOX_LIST_PATH_TYPE_DIR,
					  &path) < 0)
			name = NULL;
	}
	if (name == NULL && path == NULL) {
		(void)mailbox_list_get_root_path(list, MAILBOX_LIST_PATH_TYPE_DIR,
						 &path);
	}

	if (path == NULL) {
		/* no filesystem support in storage */
	} else if (mailbox_list_get_permissions_stat(list, path, permissions_r)) {
		/* got permissions from the given path */
		permissions_r->gid_origin_is_mailbox_path = name != NULL;
	} else if (name != NULL) {
		/* path couldn't be stat()ed, try parent mailbox */
		p = strrchr(name, mailbox_list_get_hierarchy_sep(list));
		if (p == NULL) {
			/* return root defaults */
			parent_name = NULL;
		} else {
			parent_name = t_strdup_until(name, p);
		}
		mailbox_list_get_permissions(list, parent_name,
					     permissions_r);
		return;
	} else {
		/* assume current defaults for mailboxes that don't exist or
		   can't be looked up for some other reason */
		permissions_r->file_uid = geteuid();
		permissions_r->file_gid = getegid();
	}
	if (name == NULL) {
		mailbox_permissions_copy(&list->root_permissions, permissions_r,
					 list->pool);
	}

	if (name == NULL) {
		e_debug(list->ns->user->event,
			"Namespace %s: Using permissions from %s: "
			"mode=0%o gid=%s", list->ns->prefix,
			path != NULL ? path : "",
			(int)permissions_r->dir_create_mode,
			permissions_r->file_create_gid == (gid_t)-1 ? "default" :
			dec2str(permissions_r->file_create_gid));
	}
}

void mailbox_list_get_permissions(struct mailbox_list *list, const char *name,
				  struct mailbox_permissions *permissions_r)
{
	mailbox_list_get_permissions_internal(list, name, permissions_r);
}

void mailbox_list_get_root_permissions(struct mailbox_list *list,
				       struct mailbox_permissions *permissions_r)
{
	if (list->root_permissions.file_create_mode != (mode_t)-1)
		*permissions_r = list->root_permissions;
	else {
		mailbox_list_get_permissions_internal(list, NULL,
						      permissions_r);
	}
}

void mailbox_permissions_copy(struct mailbox_permissions *dest,
			      const struct mailbox_permissions *src,
			      pool_t pool)
{
	*dest = *src;
	dest->file_create_gid_origin =
		p_strdup(pool, src->file_create_gid_origin);
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

static int
mailbox_list_try_mkdir_root_parent(struct mailbox_list *list,
				   enum mailbox_list_path_type type,
				   struct mailbox_permissions *perm,
				   const char **error_r)
{
	const char *expanded, *unexpanded, *root_dir, *p;
	struct stat st;
	bool home = FALSE;

	/* get the directory path up to last %variable. for example
	   unexpanded path may be "/var/mail/%d/%2n/%n/Maildir", and we want
	   to get expanded="/var/mail/domain/nn" */
	unexpanded = mailbox_list_get_unexpanded_path(list, type);
	p = strrchr(unexpanded, '%');
	if ((p == unexpanded && p[1] == 'h') ||
	    (p == NULL && unexpanded[0] == '~')) {
		/* home directory used */
		if (!mailbox_list_get_root_path(list, type, &expanded))
			i_unreached();
		home = TRUE;
	} else if (p == NULL) {
		return 0;
	} else {
		while (p != unexpanded && *p != '/') p--;
		if (p == unexpanded)
			return 0;

		if (!mailbox_list_get_root_path(list, type, &expanded))
			i_unreached();
		expanded = get_expanded_path(unexpanded, p, expanded);
		if (*expanded == '\0')
			return 0;
	}

	/* get the first existing parent directory's permissions */
	if (stat_first_parent(expanded, &root_dir, &st) < 0) {
		*error_r = errno == EACCES ?
			mail_error_eacces_msg("stat", root_dir) :
			t_strdup_printf("stat(%s) failed: %m", root_dir);
		return -1;
	}

	/* if the parent directory doesn't have setgid-bit enabled, we don't
	   copy any permissions from it. */
	if ((st.st_mode & S_ISGID) == 0)
		return 0;

	if (!home) {
		/* assuming we have e.g. /var/vmail/%d/%n directory, here we
		   want to create up to /var/vmail/%d with permissions from
		   the parent directory. we never want to create the %n
		   directory itself. */
		if (root_dir == expanded) {
			/* this is the %n directory */
		} else {
			if (mkdir_parents_chgrp(expanded, st.st_mode,
						(gid_t)-1, root_dir) < 0 &&
			    errno != EEXIST) {
				*error_r = t_strdup_printf(
					"mkdir(%s) failed: %m", expanded);
				return -1;
			}
		}
		if (perm->file_create_gid == (gid_t)-1 &&
		    (perm->dir_create_mode & S_ISGID) == 0) {
			/* change the group for user directories */
			perm->dir_create_mode |= S_ISGID;
			perm->file_create_gid = getegid();
			perm->file_create_gid_origin = "egid";
			perm->gid_origin_is_mailbox_path = FALSE;
		}
	} else {
		/* when using %h and the parent has setgid-bit,
		   copy the permissions from it for the home we're creating */
		perm->file_create_mode = st.st_mode & 0666;
		perm->dir_create_mode = st.st_mode;
		perm->file_create_gid = (gid_t)-1;
		perm->file_create_gid_origin = "parent";
		perm->gid_origin_is_mailbox_path = FALSE;
	}
	return 0;
}

int mailbox_list_try_mkdir_root(struct mailbox_list *list, const char *path,
				enum mailbox_list_path_type type,
				const char **error_r)
{
	const char *root_dir;
	struct stat st;
	struct mailbox_permissions perm;

	if (stat(path, &st) == 0) {
		/* looks like it already exists, don't bother checking
		   further. */
		if (!S_ISDIR(st.st_mode)) {
			*error_r = t_strdup_printf(
				"Root directory is a file: %s", path);
			return -1;
		}
		return 0;
	}

	mailbox_list_get_root_permissions(list, &perm);

	if (!mailbox_list_get_root_path(list, type, &root_dir))
		i_unreached();
	i_assert(str_begins(path, root_dir));
	if (strcmp(root_dir, path) != 0 && stat(root_dir, &st) == 0) {
		/* creating a subdirectory under an already existing root dir.
		   use the root's permissions */
	} else {
		if (mailbox_list_try_mkdir_root_parent(list, type,
						       &perm, error_r) < 0)
			return -1;
	}

	/* the rest of the directories exist only for one user. create them
	   with default directory permissions */
	if (mkdir_parents_chgrp(path, perm.dir_create_mode,
				perm.file_create_gid,
				perm.file_create_gid_origin) < 0 &&
	    errno != EEXIST) {
		if (errno == EACCES)
			*error_r = mail_error_create_eacces_msg("mkdir", path);
		else
			*error_r = t_strdup_printf("mkdir(%s) failed: %m", path);
		return -1;
	}
	return 0;
}

int mailbox_list_mkdir_root(struct mailbox_list *list, const char *path,
			    enum mailbox_list_path_type type)
{
	const char *error;

	if (mailbox_list_try_mkdir_root(list, path, type, &error) < 0) {
		mailbox_list_set_critical(list, "%s", error);
		return -1;
	}
	if (type == MAILBOX_LIST_PATH_TYPE_INDEX)
		list->index_root_dir_created = TRUE;
	return 0;
}

static bool
mailbox_list_is_valid_fs_name(struct mailbox_list *list, const char *name,
			      const char **error_r)
{
	bool ret, allow_internal_dirs;

	*error_r = NULL;

	if (list->mail_set->mail_full_filesystem_access ||
	    list->set.no_fs_validation)
		return TRUE;

	/* either the list backend uses '/' as the hierarchy separator or
	   it doesn't use filesystem at all (PROP_NO_ROOT) */
	if ((list->props & MAILBOX_LIST_PROP_NO_ROOT) == 0 &&
	    mailbox_list_get_hierarchy_sep(list) != '/' &&
	    strchr(name, '/') != NULL) {
		*error_r = "Name must not have '/' characters";
		return FALSE;
	}

	/* make sure it's not absolute path */
	if (*name == '/') {
		*error_r = "Begins with '/'";
		return FALSE;
	}
	if (*name == '~') {
		*error_r = "Begins with '~'";
		return FALSE;
	}

	/* make sure the mailbox name doesn't contain any foolishness:
	   "../" could give access outside the mailbox directory.
	   "./" and "//" could fool ACL checks.

	   some mailbox formats have reserved directory names, such as
	   Maildir's cur/new/tmp. if any of those would conflict with the
	   mailbox directory name, it's not valid. */
	allow_internal_dirs = list->v.is_internal_name == NULL ||
		*list->set.maildir_name != '\0' ||
		(list->props & MAILBOX_LIST_PROP_NO_INTERNAL_NAMES) != 0;
	T_BEGIN {
		const char *const *names;

		names = t_strsplit(name, "/");
		for (; *names != NULL; names++) {
			const char *n = *names;

			if (*n == '\0') {
				*error_r = "Has adjacent '/' chars";
				break; /* // */
			}
			if (*n == '.') {
				if (n[1] == '\0') {
					*error_r = "Contains '.' part";
					break; /* ./ */
				}
				if (n[1] == '.' && n[2] == '\0') {
					*error_r = "Contains '..' part";
					break; /* ../ */
				}
			}
			if (*list->set.maildir_name != '\0' &&
			    strcmp(list->set.maildir_name, n) == 0) {
				/* don't allow maildir_name to be used as part
				   of the mailbox name */
				*error_r = "Contains reserved name";
				break;
			}
			if (!allow_internal_dirs &&
			    list->v.is_internal_name(list, n)) {
				*error_r = "Contains reserved name";
				break;
			}
		}
		ret = *names == NULL;
	} T_END;

	return ret;
}


bool mailbox_list_is_valid_name(struct mailbox_list *list,
				const char *name, const char **error_r)
{
	if (*name == '\0') {
		if (*list->ns->prefix != '\0') {
			/* an ugly way to get to mailbox root (e.g. Maildir/
			   when it's not the INBOX) */
			return TRUE;
		}
		*error_r = "Name is empty";
		return FALSE;
	}

	return mailbox_list_is_valid_fs_name(list, name, error_r);
}

int mailbox_list_get_path(struct mailbox_list *list, const char *name,
			  enum mailbox_list_path_type type,
			  const char **path_r)
{
	int ret;

	if ((ret = list->v.get_path(list, name, type, path_r)) <= 0)
		*path_r = NULL;
	else
		i_assert(*path_r != NULL);
	return ret;
}

bool mailbox_list_get_root_path(struct mailbox_list *list,
				enum mailbox_list_path_type type,
				const char **path_r)
{
	int ret;

	if ((ret = list->v.get_path(list, NULL, type, path_r)) < 0)
		i_unreached();
	if (ret == 0)
		*path_r = NULL;
	else
		i_assert(*path_r != NULL);
	return ret > 0;
}

const char *mailbox_list_get_root_forced(struct mailbox_list *list,
					 enum mailbox_list_path_type type)
{
	const char *path;

	if (!mailbox_list_get_root_path(list, type, &path))
		i_unreached();
	return path;
}

bool mailbox_list_set_get_root_path(const struct mailbox_list_settings *set,
				    enum mailbox_list_path_type type,
				    const char **path_r)
{
	const char *path = NULL;

	switch (type) {
	case MAILBOX_LIST_PATH_TYPE_DIR:
		path = set->root_dir;
		break;
	case MAILBOX_LIST_PATH_TYPE_ALT_DIR:
		path = set->alt_dir;
		break;
	case MAILBOX_LIST_PATH_TYPE_MAILBOX:
		if (*set->mailbox_dir_name == '\0')
			path = set->root_dir;
		else {
			path = t_strconcat(set->root_dir, "/",
					   set->mailbox_dir_name, NULL);
			path = t_strndup(path, strlen(path)-1);
		}
		break;
	case MAILBOX_LIST_PATH_TYPE_ALT_MAILBOX:
		if (*set->mailbox_dir_name == '\0')
			path = set->alt_dir;
		else if (set->alt_dir != NULL) {
			path = t_strconcat(set->alt_dir, "/",
					   set->mailbox_dir_name, NULL);
			path = t_strndup(path, strlen(path)-1);
		}
		break;
	case MAILBOX_LIST_PATH_TYPE_CONTROL:
		path = set->control_dir != NULL ?
			set->control_dir : set->root_dir;
		break;
	case MAILBOX_LIST_PATH_TYPE_VOLATILEDIR:
		path = set->volatile_dir != NULL ?
			set->volatile_dir : set->root_dir;
		break;
	case MAILBOX_LIST_PATH_TYPE_LIST_INDEX:
		if (set->list_index_dir != NULL) {
			if (set->list_index_dir[0] == '/') {
				path = set->list_index_dir;
				break;
			}
			/* relative path */
			if (!mailbox_list_set_get_root_path(set,
					MAILBOX_LIST_PATH_TYPE_INDEX, &path))
				i_unreached();
			path = t_strconcat(path, "/", set->list_index_dir, NULL);
			break;
		}
		/* fall through - default to index directory */
	case MAILBOX_LIST_PATH_TYPE_INDEX_CACHE:
		if (set->index_cache_dir != NULL &&
		    type == MAILBOX_LIST_PATH_TYPE_INDEX_CACHE) {
			path = set->index_cache_dir;
			break;
		}
		/* fall through */
	case MAILBOX_LIST_PATH_TYPE_INDEX:
		if (set->index_dir != NULL) {
			if (set->index_dir[0] == '\0') {
				/* in-memory indexes */
				return 0;
			}
			path = set->index_dir;
		} else {
			path = set->root_dir;
		}
		break;
	case MAILBOX_LIST_PATH_TYPE_INDEX_PRIVATE:
		path = set->index_pvt_dir;
		break;
	}
	*path_r = path;
	return path != NULL;
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

int mailbox_has_children(struct mailbox_list *list, const char *name)
{
	struct mailbox_list_iterate_context *iter;
	const char *pattern;
	int ret;

	pattern = t_strdup_printf("%s%c%%", name,
				  mail_namespace_get_sep(list->ns));
	iter = mailbox_list_iter_init(list, pattern,
				      MAILBOX_LIST_ITER_RETURN_NO_FLAGS);
	ret = mailbox_list_iter_next(iter) != NULL ? 1 : 0;
	if (mailbox_list_iter_deinit(&iter) < 0)
		ret = -1;
	return ret;
}

int mailbox_list_mailbox(struct mailbox_list *list, const char *name,
			 enum mailbox_info_flags *flags_r)
{
	const char *path, *fname, *rootdir, *dir, *inbox;
	size_t len;

	*flags_r = 0;

	if ((list->ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0 &&
	    strcasecmp(name, "INBOX") == 0) {
		/* special handling for INBOX, mainly because with Maildir++
		   layout it needs to check if the cur/ directory exists,
		   which the Maildir++ layout backend itself can't do.. */
		struct mailbox *box;
		enum mailbox_existence existence;
		int ret;

		/* kludge: with imapc backend we can get here with
		   list=Maildir++ (for indexes), but list->ns->list=imapc */
		box = mailbox_alloc(list->ns->list, "INBOX", 0);
		ret = mailbox_exists(box, FALSE, &existence);
		if (ret < 0) {
			const char *errstr;
			enum mail_error error;

			/* internal error or with imapc we can get here with
			   login failures */
			errstr = mailbox_get_last_error(box, &error);
			mailbox_list_set_error(list, error, errstr);
		}
		mailbox_free(&box);
		if (ret < 0)
			return -1;
		switch (existence) {
		case MAILBOX_EXISTENCE_NONE:
		case MAILBOX_EXISTENCE_NOSELECT:
			*flags_r |= MAILBOX_NONEXISTENT;
			return 0;
		case MAILBOX_EXISTENCE_SELECT:
			break;
		}
		return 1;
	}

	if (list->v.get_mailbox_flags == NULL) {
		/* can't do this optimized. do it the slow way. */
		struct mailbox_list_iterate_context *iter;
		const struct mailbox_info *info;
		const char *vname;

		vname = mailbox_list_get_vname(list, name);
		iter = mailbox_list_iter_init(list, vname, 0);
		info = mailbox_list_iter_next(iter);
		if (info == NULL)
			*flags_r = MAILBOX_NONEXISTENT;
		else
			*flags_r = info->flags;
		return mailbox_list_iter_deinit(&iter);
	}

	if (!list->set.iter_from_index_dir) {
		rootdir = mailbox_list_get_root_forced(list, MAILBOX_LIST_PATH_TYPE_MAILBOX);
		if (mailbox_list_get_path(list, name, MAILBOX_LIST_PATH_TYPE_DIR, &path) <= 0)
			i_unreached();
	} else {
		rootdir = mailbox_list_get_root_forced(list, MAILBOX_LIST_PATH_TYPE_INDEX);
		if (mailbox_list_get_path(list, name, MAILBOX_LIST_PATH_TYPE_INDEX, &path) <= 0)
			i_unreached();
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
	if (str_begins(path, rootdir) && path[len] == '/') {
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
		if (mailbox_list_get_path(list, "INBOX",
					  MAILBOX_LIST_PATH_TYPE_MAILBOX,
					  &inbox) <= 0)
			i_unreached();
		if (strcmp(inbox, dir) == 0) {
			*flags_r |= MAILBOX_NONEXISTENT;
			return 0;
		}
	}
	return list->v.get_mailbox_flags(list, dir, fname,
					 MAILBOX_LIST_FILE_TYPE_UNKNOWN,
					 flags_r);
}

static bool mailbox_list_init_changelog(struct mailbox_list *list)
{
	struct mailbox_permissions perm;
	const char *path;

	if (list->changelog != NULL)
		return TRUE;

	/* don't do this in mailbox_list_create(), because _get_path() might be
	   overridden by storage (mbox). */
	if (!mailbox_list_get_root_path(list, MAILBOX_LIST_PATH_TYPE_INDEX, &path))
		return FALSE;

	path = t_strconcat(path, "/"MAILBOX_LOG_FILE_NAME, NULL);
	list->changelog = mailbox_log_alloc(path);

	mailbox_list_get_root_permissions(list, &perm);
	mailbox_log_set_permissions(list->changelog, perm.file_create_mode,
				    perm.file_create_gid,
				    perm.file_create_gid_origin);
	return TRUE;
}

int mailbox_list_mkdir_missing_index_root(struct mailbox_list *list)
{
	const char *index_dir;

	if (list->index_root_dir_created)
		return 1;

	/* If index root dir hasn't been created yet, do it now.
	   Do this here even if the index directory is the same as mail root
	   directory, because it may not have been created elsewhere either. */
	if (!mailbox_list_get_root_path(list, MAILBOX_LIST_PATH_TYPE_INDEX,
					&index_dir))
		return 0;

	if (mailbox_list_mkdir_root(list, index_dir,
				    MAILBOX_LIST_PATH_TYPE_INDEX) < 0)
		return -1;
	list->index_root_dir_created = TRUE;
	return 1;
}

int mailbox_list_mkdir_missing_list_index_root(struct mailbox_list *list)
{
	const char *index_dir;

	if (list->set.list_index_dir == NULL)
		return mailbox_list_mkdir_missing_index_root(list);

	/* LISTINDEX points outside the index root directory */
	if (list->list_index_root_dir_created)
		return 1;

	if (!mailbox_list_get_root_path(list, MAILBOX_LIST_PATH_TYPE_LIST_INDEX,
					&index_dir))
		return 0;
	if (mailbox_list_mkdir_root(list, index_dir,
				    MAILBOX_LIST_PATH_TYPE_LIST_INDEX) < 0)
		return -1;
	list->list_index_root_dir_created = TRUE;
	return 1;
}

void mailbox_list_add_change(struct mailbox_list *list,
			     enum mailbox_log_record_type type,
			     const guid_128_t mailbox_guid)
{
	struct mailbox_log_record rec;
	time_t stamp;

	if (!mailbox_list_init_changelog(list) ||
	    guid_128_is_empty(mailbox_guid))
		return;

	if (mailbox_list_mkdir_missing_index_root(list) <= 0)
		return;

	stamp = list->changelog_timestamp != (time_t)-1 ?
		list->changelog_timestamp : ioloop_time;

	i_zero(&rec);
	rec.type = type;
	memcpy(rec.mailbox_guid, mailbox_guid, sizeof(rec.mailbox_guid));
	mailbox_log_record_set_timestamp(&rec, stamp);
	(void)mailbox_log_append(list->changelog, &rec);
}

int mailbox_list_set_subscribed(struct mailbox_list *list,
				const char *name, bool set)
{
	int ret;

	/* make sure we'll refresh the file on next list */
	list->subscriptions_mtime = (time_t)-1;

	if ((ret = list->v.set_subscribed(list, name, set)) <= 0)
		return ret;
	return 0;
}

int mailbox_list_delete_dir(struct mailbox_list *list, const char *name)
{
	const char *error;

	if (!mailbox_list_is_valid_name(list, name, &error) || *name == '\0') {
		mailbox_list_set_error(list, MAIL_ERROR_PARAMS,
				       "Invalid mailbox name");
		return -1;
	}
	return list->v.delete_dir(list, name);
}

int mailbox_list_delete_symlink(struct mailbox_list *list, const char *name)
{
	const char *error;

	if (!mailbox_list_is_valid_name(list, name, &error) || *name == '\0') {
		mailbox_list_set_error(list, MAIL_ERROR_PARAMS,
				       "Invalid mailbox name");
		return -1;
	}
	return list->v.delete_symlink(list, name);
}

void mailbox_name_get_sha128(const char *name, guid_128_t guid_128_r)
{
	unsigned char sha[SHA1_RESULTLEN];

	sha1_get_digest(name, strlen(name), sha);
	memcpy(guid_128_r, sha, I_MIN(GUID_128_SIZE, sizeof(sha)));
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

int mailbox_list_dirent_is_alias_symlink(struct mailbox_list *list,
					 const char *dir_path,
					 const struct dirent *d)
{
	struct stat st;
	int ret;

	if (mailbox_list_get_file_type(d) == MAILBOX_LIST_FILE_TYPE_SYMLINK)
		return 1;

	T_BEGIN {
		const char *path, *linkpath, *error;

		path = t_strconcat(dir_path, "/", d->d_name, NULL);
		if (lstat(path, &st) < 0) {
			mailbox_list_set_critical(list,
						  "lstat(%s) failed: %m", path);
			ret = -1;
		} else if (!S_ISLNK(st.st_mode)) {
			ret = 0;
		} else if (t_readlink(path, &linkpath, &error) < 0) {
			i_error("t_readlink(%s) failed: %s", path, error);
			ret = -1;
		} else {
			/* it's an alias only if it points to the same
			   directory */
			ret = strchr(linkpath, '/') == NULL ? 1 : 0;
		}
	} T_END;
	return ret;
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
	size_t len;

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
	root_dir = mailbox_list_get_root_forced(list, MAILBOX_LIST_PATH_TYPE_MAILBOX);
	len = strlen(root_dir);
	if (str_begins(*name, root_dir) && (*name)[len] == '/') {
		mailbox_name = *name + len + 1;
		if (mailbox_list_get_path(list, mailbox_name,
					  MAILBOX_LIST_PATH_TYPE_MAILBOX,
					  &path) <= 0)
			return FALSE;
		if (strcmp(path, *name) == 0) {
			/* yeah, we can replace the full path with mailbox
			   name. this way we can use indexes. */
			*name = mailbox_name;
			return FALSE;
		}
	}
	return TRUE;
}

const char *mailbox_list_get_last_error(struct mailbox_list *list,
					enum mail_error *error_r)
{
	if (error_r != NULL)
		*error_r = list->error;

	return list->error_string != NULL ? list->error_string :
		"Unknown internal list error";
}

enum mail_error mailbox_list_get_last_mail_error(struct mailbox_list *list)
{
	return list->error;
}

const char *mailbox_list_get_last_internal_error(struct mailbox_list *list,
						 enum mail_error *error_r)
{
	if (error_r != NULL)
		*error_r = list->error;
	if (list->last_error_is_internal) {
		i_assert(list->last_internal_error != NULL);
		return list->last_internal_error;
	}
	return mailbox_list_get_last_error(list, error_r);
}

void mailbox_list_clear_error(struct mailbox_list *list)
{
	i_free_and_null(list->error_string);

	i_free(list->last_internal_error);
	list->last_error_is_internal = FALSE;
	list->error = MAIL_ERROR_NONE;
}

void mailbox_list_set_error(struct mailbox_list *list,
			    enum mail_error error, const char *string)
{
	i_free(list->error_string);
	list->error_string = i_strdup(string);

	list->last_error_is_internal = FALSE;
	list->error = error;
}

void mailbox_list_set_internal_error(struct mailbox_list *list)
{
	const char *str;

	str = t_strflocaltime(MAIL_ERRSTR_CRITICAL_MSG_STAMP, ioloop_time);
	i_free(list->error_string);
	list->error_string = i_strdup(str);
	list->error = MAIL_ERROR_TEMP;
}

void mailbox_list_set_critical(struct mailbox_list *list, const char *fmt, ...)
{
	va_list va;

	i_free(list->last_internal_error);
	va_start(va, fmt);
	list->last_internal_error = i_strdup_vprintf(fmt, va);
	va_end(va);
	list->last_error_is_internal = TRUE;
	i_error("%s", list->last_internal_error);

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

void mailbox_list_last_error_push(struct mailbox_list *list)
{
	struct mail_storage_error *err;

	if (!array_is_created(&list->error_stack))
		i_array_init(&list->error_stack, 2);
	err = array_append_space(&list->error_stack);
	err->error_string = i_strdup(list->error_string);
	err->error = list->error;
	err->last_error_is_internal = list->last_error_is_internal;
	if (err->last_error_is_internal)
		err->last_internal_error = i_strdup(list->last_internal_error);
}

void mailbox_list_last_error_pop(struct mailbox_list *list)
{
	unsigned int count = array_count(&list->error_stack);
	const struct mail_storage_error *err =
		array_idx(&list->error_stack, count-1);

	i_free(list->error_string);
	i_free(list->last_internal_error);
	list->error_string = err->error_string;
	list->error = err->error;
	list->last_error_is_internal = err->last_error_is_internal;
	list->last_internal_error = err->last_internal_error;
	array_delete(&list->error_stack, count-1, 1);
}

int mailbox_list_init_fs(struct mailbox_list *list, const char *driver,
			 const char *args, const char *root_dir,
			 struct fs **fs_r, const char **error_r)
{
	struct fs_settings fs_set;
	struct ssl_iostream_settings ssl_set;
	struct mailbox_list_fs_context *ctx;
	struct fs *parent_fs;

	i_zero(&ssl_set);
	i_zero(&fs_set);
	mail_user_init_fs_settings(list->ns->user, &fs_set, &ssl_set);
	fs_set.root_path = root_dir;
	fs_set.temp_file_prefix = mailbox_list_get_global_temp_prefix(list);

	if (fs_init(driver, args, &fs_set, fs_r, error_r) < 0)
		return -1;

	/* add mailbox_list context to the parent fs, which allows
	   mailbox_list_fs_get_list() to work */
	for (parent_fs = *fs_r; parent_fs->parent != NULL;
	     parent_fs = parent_fs->parent) ;

	ctx = p_new(list->pool, struct mailbox_list_fs_context, 1);
	ctx->list = list;
	MODULE_CONTEXT_SET(parent_fs, mailbox_list_fs_module, ctx);

	/* a bit kludgy notification to the fs that we're now finished setting
	   up the module context. */
	(void)fs_get_properties(*fs_r);
	return 0;
}

struct mailbox_list *mailbox_list_fs_get_list(struct fs *fs)
{
	struct mailbox_list_fs_context *ctx;

	while (fs->parent != NULL)
		fs = fs->parent;

	ctx = MAILBOX_LIST_FS_CONTEXT(fs);
	return ctx == NULL ? NULL : ctx->list;
}

int mailbox_list_lock(struct mailbox_list *list)
{
	struct mailbox_permissions perm;
	struct file_create_settings set;
	const char *lock_dir, *lock_fname, *lock_path, *error;

	if (list->lock_refcount > 0) {
		list->lock_refcount++;
		return 0;
	}

	mailbox_list_get_root_permissions(list, &perm);
	i_zero(&set);
	set.lock_timeout_secs = list->mail_set->mail_max_lock_timeout == 0 ?
		MAILBOX_LIST_LOCK_SECS :
		I_MIN(MAILBOX_LIST_LOCK_SECS, list->mail_set->mail_max_lock_timeout);
	set.lock_method = list->mail_set->parsed_lock_method;
	set.mode = perm.file_create_mode;
	set.gid = perm.file_create_gid;
	set.gid_origin = perm.file_create_gid_origin;

	lock_fname = MAILBOX_LIST_LOCK_FNAME;
	if (list->set.volatile_dir != NULL) {
		/* Use VOLATILEDIR. It's shared with all mailbox_lists, so use
		   hash of the namespace prefix as a way to make this lock name
		   unique across the namespaces. */
		unsigned char ns_prefix_hash[SHA1_RESULTLEN];
		sha1_get_digest(list->ns->prefix, list->ns->prefix_len,
				ns_prefix_hash);
		lock_fname = t_strconcat(MAILBOX_LIST_LOCK_FNAME,
			binary_to_hex(ns_prefix_hash, sizeof(ns_prefix_hash)), NULL);
		lock_dir = list->set.volatile_dir;
		set.mkdir_mode = 0700;
	} else if (mailbox_list_get_root_path(list, MAILBOX_LIST_PATH_TYPE_INDEX,
					      &lock_dir)) {
		/* use index root directory */
		if (mailbox_list_mkdir_missing_index_root(list) < 0)
			return -1;
	} else if (mailbox_list_get_root_path(list, MAILBOX_LIST_PATH_TYPE_DIR,
					      &lock_dir)) {
		/* use mailbox root directory */
		if (mailbox_list_mkdir_root(list, lock_dir,
					    MAILBOX_LIST_PATH_TYPE_DIR) < 0)
			return -1;
	} else {
		/* No filesystem used by mailbox list (e.g. imapc).
		   Just assume it's locked */
		list->lock_refcount = 1;
		return 0;
	}
	lock_path = t_strdup_printf("%s/%s", lock_dir, lock_fname);
	if (mail_storage_lock_create(lock_path, &set, list->mail_set,
				     &list->lock, &error) <= 0) {
		mailbox_list_set_critical(list,
			"Couldn't create mailbox list lock %s: %s",
			lock_path, error);
		return -1;
	}

	list->lock_refcount = 1;
	return 0;
}

void mailbox_list_unlock(struct mailbox_list *list)
{
	i_assert(list->lock_refcount > 0);
	if (--list->lock_refcount > 0)
		return;

	file_lock_free(&list->lock);
}
