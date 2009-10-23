/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "var-expand.h"
#include "settings-parser.h"
#include "mail-index.h"
#include "mail-user.h"
#include "mail-namespace.h"
#include "mail-storage-private.h"
#include "mail-storage-settings.h"

#include <stddef.h>

static bool mail_storage_settings_check(void *_set, pool_t pool, const char **error_r);
static bool namespace_settings_check(void *_set, pool_t pool, const char **error_r);
static bool mail_user_settings_check(void *_set, pool_t pool, const char **error_r);

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct mail_storage_settings, name), NULL }

static struct setting_define mail_storage_setting_defines[] = {
	DEF(SET_STR_VARS, mail_location),
	DEF(SET_STR, mail_cache_fields),
	DEF(SET_STR, mail_never_cache_fields),
	DEF(SET_UINT, mail_cache_min_mail_count),
	DEF(SET_UINT, mailbox_idle_check_interval),
	DEF(SET_UINT, mail_max_keyword_length),
	DEF(SET_BOOL, mail_save_crlf),
	DEF(SET_BOOL, fsync_disable),
	DEF(SET_BOOL, mmap_disable),
	DEF(SET_BOOL, dotlock_use_excl),
	DEF(SET_BOOL, mail_nfs_storage),
	DEF(SET_BOOL, mail_nfs_index),
	DEF(SET_BOOL, mailbox_list_index_disable),
	DEF(SET_BOOL, mail_debug),
	DEF(SET_BOOL, mail_full_filesystem_access),
	DEF(SET_ENUM, lock_method),
	DEF(SET_STR, pop3_uidl_format),

	SETTING_DEFINE_LIST_END
};

struct mail_storage_settings mail_storage_default_settings = {
	MEMBER(mail_location) "",
	MEMBER(mail_cache_fields) "flags",
	MEMBER(mail_never_cache_fields) "imap.envelope",
	MEMBER(mail_cache_min_mail_count) 0,
	MEMBER(mailbox_idle_check_interval) 30,
	MEMBER(mail_max_keyword_length) 50,
	MEMBER(mail_save_crlf) FALSE,
	MEMBER(fsync_disable) FALSE,
	MEMBER(mmap_disable) FALSE,
	MEMBER(dotlock_use_excl) FALSE,
	MEMBER(mail_nfs_storage) FALSE,
	MEMBER(mail_nfs_index) FALSE,
	MEMBER(mailbox_list_index_disable) FALSE,
	MEMBER(mail_debug) FALSE,
	MEMBER(mail_full_filesystem_access) FALSE,
	MEMBER(lock_method) "fcntl:flock:dotlock",
	MEMBER(pop3_uidl_format) "%08Xu%08Xv"
};

struct setting_parser_info mail_storage_setting_parser_info = {
	MEMBER(module_name) "mail",
	MEMBER(defines) mail_storage_setting_defines,
	MEMBER(defaults) &mail_storage_default_settings,

	MEMBER(type_offset) (size_t)-1,
	MEMBER(struct_size) sizeof(struct mail_storage_settings),

	MEMBER(parent_offset) (size_t)-1,
	MEMBER(parent) &mail_user_setting_parser_info,

	MEMBER(check_func) mail_storage_settings_check
};

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct mail_namespace_settings, name), NULL }

static struct setting_define mail_namespace_setting_defines[] = {
	DEF(SET_ENUM, type),
	DEF(SET_STR, separator),
	DEF(SET_STR_VARS, prefix),
	DEF(SET_STR_VARS, location),
	DEF(SET_STR_VARS, alias_for),

	DEF(SET_BOOL, inbox),
	DEF(SET_BOOL, hidden),
	DEF(SET_ENUM, list),
	DEF(SET_BOOL, subscriptions),

	SETTING_DEFINE_LIST_END
};

struct mail_namespace_settings mail_namespace_default_settings = {
	MEMBER(type) "private:shared:public",
	MEMBER(separator) "",
	MEMBER(prefix) "",
	MEMBER(location) "",
	MEMBER(alias_for) NULL,

	MEMBER(inbox) FALSE,
	MEMBER(hidden) FALSE,
	MEMBER(list) "yes:no:children",
	MEMBER(subscriptions) TRUE
};

struct setting_parser_info mail_namespace_setting_parser_info = {
	MEMBER(module_name) NULL,
	MEMBER(defines) mail_namespace_setting_defines,
	MEMBER(defaults) &mail_namespace_default_settings,

	MEMBER(type_offset) offsetof(struct mail_namespace_settings, prefix),
	MEMBER(struct_size) sizeof(struct mail_namespace_settings),

	MEMBER(parent_offset) offsetof(struct mail_namespace_settings, user_set),
	MEMBER(parent) &mail_user_setting_parser_info,

	MEMBER(check_func) namespace_settings_check
};

#undef DEF
#undef DEFLIST_UNIQUE
#define DEF(type, name) \
	{ type, #name, offsetof(struct mail_user_settings, name), NULL }
#define DEFLIST_UNIQUE(field, name, defines) \
	{ SET_DEFLIST_UNIQUE, name, \
	  offsetof(struct mail_user_settings, field), defines }

static struct setting_define mail_user_setting_defines[] = {
	DEF(SET_STR, base_dir),
	DEF(SET_STR, auth_socket_path),

	DEF(SET_STR, mail_uid),
	DEF(SET_STR, mail_gid),
	DEF(SET_STR_VARS, mail_home),
	DEF(SET_STR_VARS, mail_chroot),
	DEF(SET_STR, mail_access_groups),
	DEF(SET_STR, mail_privileged_group),
	DEF(SET_STR, valid_chroot_dirs),

	DEF(SET_UINT, first_valid_uid),
	DEF(SET_UINT, last_valid_uid),
	DEF(SET_UINT, first_valid_gid),
	DEF(SET_UINT, last_valid_gid),

	DEF(SET_STR, mail_plugins),
	DEF(SET_STR, mail_plugin_dir),

	DEF(SET_STR, mail_log_prefix),

	DEFLIST_UNIQUE(namespaces, "namespace", &mail_namespace_setting_parser_info),
	{ SET_STRLIST, "plugin", offsetof(struct mail_user_settings, plugin_envs), NULL },

	SETTING_DEFINE_LIST_END
};

static struct mail_user_settings mail_user_default_settings = {
	MEMBER(base_dir) PKG_RUNDIR,
	MEMBER(auth_socket_path) "auth-userdb",

	MEMBER(mail_uid) "",
	MEMBER(mail_gid) "",
	MEMBER(mail_home) "",
	MEMBER(mail_chroot) "",
	MEMBER(mail_access_groups) "",
	MEMBER(mail_privileged_group) "",
	MEMBER(valid_chroot_dirs) "",

	MEMBER(first_valid_uid) 500,
	MEMBER(last_valid_uid) 0,
	MEMBER(first_valid_gid) 1,
	MEMBER(last_valid_gid) 0,

	MEMBER(mail_plugins) "",
	MEMBER(mail_plugin_dir) MODULEDIR,

	MEMBER(mail_log_prefix) "%s(%u): ",

	MEMBER(namespaces) ARRAY_INIT,
	MEMBER(plugin_envs) ARRAY_INIT
};

struct setting_parser_info mail_user_setting_parser_info = {
	MEMBER(module_name) "mail",
	MEMBER(defines) mail_user_setting_defines,
	MEMBER(defaults) &mail_user_default_settings,

	MEMBER(type_offset) (size_t)-1,
	MEMBER(struct_size) sizeof(struct mail_user_settings),

	MEMBER(parent_offset) (size_t)-1,
	MEMBER(parent) NULL,

	MEMBER(check_func) mail_user_settings_check
};

const void *
mail_user_set_get_driver_settings(const struct setting_parser_info *info,
				  const struct mail_user_settings *set,
				  const char *driver)
{
	const void *dset;

	dset = settings_find_dynamic(info, set, driver);
	if (dset == NULL) {
		i_panic("Default settings not found for storage driver %s",
			driver);
	}
	return dset;
}

const struct mail_storage_settings *
mail_user_set_get_storage_set(struct mail_user *user)
{
	return mail_user_set_get_driver_settings(user->set_info, user->set,
						 MAIL_STORAGE_SET_DRIVER_NAME);
}

const void *mail_storage_get_driver_settings(struct mail_storage *storage)
{
	return mail_user_set_get_driver_settings(storage->user->set_info,
						 storage->user->set,
						 storage->name);
}

enum mail_index_open_flags
mail_storage_settings_to_index_flags(const struct mail_storage_settings *set)
{
	enum mail_index_open_flags index_flags = 0;

	if (set->fsync_disable)
		index_flags |= MAIL_INDEX_OPEN_FLAG_FSYNC_DISABLE;
#ifndef MMAP_CONFLICTS_WRITE
	if (set->mmap_disable)
#endif
		index_flags |= MAIL_INDEX_OPEN_FLAG_MMAP_DISABLE;
	if (set->dotlock_use_excl)
		index_flags |= MAIL_INDEX_OPEN_FLAG_DOTLOCK_USE_EXCL;
	if (set->mail_nfs_index)
		index_flags |= MAIL_INDEX_OPEN_FLAG_NFS_FLUSH;
	return index_flags;
}

const struct dynamic_settings_parser *mail_storage_get_dynamic_parsers(void)
{
	struct dynamic_settings_parser *parsers;
	struct mail_storage *const *storages;
	unsigned int i, j, count;

	storages = array_get(&mail_storage_classes, &count);
	parsers = t_new(struct dynamic_settings_parser, count + 1);
	parsers[0].name = MAIL_STORAGE_SET_DRIVER_NAME;
	parsers[0].info = &mail_storage_setting_parser_info;

	for (i = 0, j = 1; i < count; i++) {
		if (storages[i]->v.get_setting_parser_info == NULL)
			continue;

		parsers[j].name = storages[i]->name;
		parsers[j].info = storages[i]->v.get_setting_parser_info();
		j++;
	}
	return parsers;
}

static void
fix_base_path(struct mail_user_settings *set, pool_t pool, const char **str)
{
	if (*str != NULL && **str != '\0' && **str != '/')
		*str = p_strconcat(pool, set->base_dir, "/", *str, NULL);
}

/* <settings checks> */
static bool mail_storage_settings_check(void *_set, pool_t pool ATTR_UNUSED,
					const char **error_r)
{
	struct mail_storage_settings *set = _set;
	const char *p;
	bool uidl_format_ok;
	char c;

	if (set->mail_nfs_index && !set->mmap_disable) {
		*error_r = "mail_nfs_index=yes requires mmap_disable=yes";
		return FALSE;
	}
	if (set->mail_nfs_index && set->fsync_disable) {
		*error_r = "mail_nfs_index=yes requires fsync_disable=no";
		return FALSE;
	}

	if (!file_lock_method_parse(set->lock_method,
				    &set->parsed_lock_method)) {
		*error_r = t_strdup_printf("Unknown lock_method: %s",
					   set->lock_method);
		return FALSE;
	}

	uidl_format_ok = FALSE;
	for (p = set->pop3_uidl_format; *p != '\0'; p++) {
		if (p[0] != '%' || p[1] == '\0')
			continue;

		c = var_get_key(++p);
		switch (c) {
		case 'v':
		case 'u':
		case 'm':
		case 'f':
			uidl_format_ok = TRUE;
			break;
		case '%':
			break;
		default:
			*error_r = t_strdup_printf(
				"Unknown pop3_uidl_format variable: %%%c", c);
			return FALSE;
		}
	}
	if (!uidl_format_ok) {
		*error_r = "pop3_uidl_format setting doesn't contain any "
			"%% variables.";
		return FALSE;
	}
	return TRUE;
}

static bool namespace_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				     const char **error_r)
{
	struct mail_namespace_settings *ns = _set;
	struct mail_namespace_settings *const *namespaces;
	const char *name;
	unsigned int i, count;

	name = ns->prefix != NULL ? ns->prefix : "";

	if (ns->separator[0] != '\0' && ns->separator[1] != '\0') {
		*error_r = t_strdup_printf("Namespace '%s': "
			"Hierarchy separator must be only one character long",
			name);
		return FALSE;
	}

	if (ns->alias_for != NULL) {
		if (array_is_created(&ns->user_set->namespaces)) {
			namespaces = array_get(&ns->user_set->namespaces,
					       &count);
		} else {
			namespaces = NULL;
			count = 0;
		}
		for (i = 0; i < count; i++) {
			if (strcmp(namespaces[i]->prefix, ns->alias_for) == 0)
				break;
		}
		if (i == count) {
			*error_r = t_strdup_printf(
				"Namespace '%s': alias_for points to "
				"unknown namespace: %s", name, ns->alias_for);
			return FALSE;
		}
		if (namespaces[i]->alias_for != NULL) {
			*error_r = t_strdup_printf(
				"Namespace '%s': alias_for chaining isn't "
				"allowed: %s -> %s", name, ns->alias_for,
				namespaces[i]->alias_for);
			return FALSE;
		}
	}
	return TRUE;
}

static bool mail_user_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				     const char **error_r)
{
	struct mail_user_settings *set = _set;

#ifndef CONFIG_BINARY
	fix_base_path(set, pool, &set->auth_socket_path);
#endif

	if (*set->mail_plugins != '\0' &&
	    access(set->mail_plugin_dir, R_OK | X_OK) < 0) {
		*error_r = t_strdup_printf(
			"mail_plugin_dir: access(%s) failed: %m",
			set->mail_plugin_dir);
		return FALSE;
	}
	return TRUE;
}
/* </settings checks> */
