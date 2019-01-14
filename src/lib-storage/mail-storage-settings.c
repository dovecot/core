/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash-format.h"
#include "var-expand.h"
#include "unichar.h"
#include "hostpid.h"
#include "settings-parser.h"
#include "message-address.h"
#include "smtp-address.h"
#include "mail-index.h"
#include "mail-user.h"
#include "mail-namespace.h"
#include "mail-storage-private.h"
#include "mail-storage-settings.h"

#include <stddef.h>

static bool mail_storage_settings_check(void *_set, pool_t pool, const char **error_r);
static bool namespace_settings_check(void *_set, pool_t pool, const char **error_r);
static bool mailbox_settings_check(void *_set, pool_t pool, const char **error_r);
static bool mail_user_settings_check(void *_set, pool_t pool, const char **error_r);
static bool mail_user_settings_expand_check(void *_set, pool_t pool ATTR_UNUSED, const char **error_r);

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct mail_storage_settings, name), NULL }

static const struct setting_define mail_storage_setting_defines[] = {
	DEF(SET_STR_VARS, mail_location),
	{ SET_ALIAS, "mail", 0, NULL },
	DEF(SET_STR_VARS, mail_attachment_fs),
	DEF(SET_STR_VARS, mail_attachment_dir),
	DEF(SET_STR, mail_attachment_hash),
	DEF(SET_SIZE, mail_attachment_min_size),
	DEF(SET_STR, mail_attachment_detection_options),
	DEF(SET_STR_VARS, mail_attribute_dict),
	DEF(SET_UINT, mail_prefetch_count),
	DEF(SET_STR, mail_cache_fields),
	DEF(SET_STR, mail_always_cache_fields),
	DEF(SET_STR, mail_never_cache_fields),
	DEF(SET_STR, mail_server_comment),
	DEF(SET_STR, mail_server_admin),
	DEF(SET_UINT, mail_cache_min_mail_count),
	DEF(SET_TIME, mail_cache_unaccessed_field_drop),
	DEF(SET_SIZE, mail_cache_record_max_size),
	DEF(SET_SIZE, mail_cache_compress_min_size),
	DEF(SET_UINT, mail_cache_compress_delete_percentage),
	DEF(SET_UINT, mail_cache_compress_continued_percentage),
	DEF(SET_UINT, mail_cache_compress_header_continue_count),
	DEF(SET_SIZE, mail_index_rewrite_min_log_bytes),
	DEF(SET_SIZE, mail_index_rewrite_max_log_bytes),
	DEF(SET_SIZE, mail_index_log_rotate_min_size),
	DEF(SET_SIZE, mail_index_log_rotate_max_size),
	DEF(SET_TIME, mail_index_log_rotate_min_age),
	DEF(SET_TIME, mail_index_log2_max_age),
	DEF(SET_TIME, mailbox_idle_check_interval),
	DEF(SET_UINT, mail_max_keyword_length),
	DEF(SET_TIME, mail_max_lock_timeout),
	DEF(SET_TIME, mail_temp_scan_interval),
	DEF(SET_UINT, mail_vsize_bg_after_count),
	DEF(SET_UINT, mail_sort_max_read_count),
	DEF(SET_BOOL, mail_save_crlf),
	DEF(SET_ENUM, mail_fsync),
	DEF(SET_BOOL, mmap_disable),
	DEF(SET_BOOL, dotlock_use_excl),
	DEF(SET_BOOL, mail_nfs_storage),
	DEF(SET_BOOL, mail_nfs_index),
	DEF(SET_BOOL, mailbox_list_index),
	DEF(SET_BOOL, mailbox_list_index_very_dirty_syncs),
	DEF(SET_BOOL, mailbox_list_index_include_inbox),
	DEF(SET_BOOL, mail_debug),
	DEF(SET_BOOL, mail_full_filesystem_access),
	DEF(SET_BOOL, maildir_stat_dirs),
	DEF(SET_BOOL, mail_shared_explicit_inbox),
	DEF(SET_ENUM, lock_method),
	DEF(SET_STR, pop3_uidl_format),

	DEF(SET_STR, hostname),
	DEF(SET_STR, recipient_delimiter),

	DEF(SET_STR, ssl_client_ca_file),
	DEF(SET_STR, ssl_client_ca_dir),
	DEF(SET_STR, ssl_client_cert),
	DEF(SET_STR, ssl_client_key),
	DEF(SET_STR, ssl_cipher_list),
	DEF(SET_STR, ssl_curve_list),
	DEF(SET_STR, ssl_min_protocol),
	DEF(SET_STR, ssl_crypto_device),
	DEF(SET_BOOL, ssl_client_require_valid_cert),
	DEF(SET_BOOL, verbose_ssl),

	SETTING_DEFINE_LIST_END
};

const struct mail_storage_settings mail_storage_default_settings = {
	.mail_location = "",
	.mail_attachment_fs = "sis posix",
	.mail_attachment_dir = "",
	.mail_attachment_hash = "%{sha1}",
	.mail_attachment_min_size = 1024*128,
	.mail_attachment_detection_options = "",
	.mail_attribute_dict = "",
	.mail_prefetch_count = 0,
	.mail_cache_fields = "flags",
	.mail_always_cache_fields = "",
	.mail_never_cache_fields = "imap.envelope",
	.mail_server_comment = "",
	.mail_server_admin = "",
	.mail_cache_min_mail_count = 0,
	.mail_cache_unaccessed_field_drop = 60*60*24*30,
	.mail_cache_record_max_size = 64 * 1024,
	.mail_cache_compress_min_size = 32 * 1024,
	.mail_cache_compress_delete_percentage = 20,
	.mail_cache_compress_continued_percentage = 200,
	.mail_cache_compress_header_continue_count = 4,
	.mail_index_rewrite_min_log_bytes = 8 * 1024,
	.mail_index_rewrite_max_log_bytes = 128 * 1024,
	.mail_index_log_rotate_min_size = 32 * 1024,
	.mail_index_log_rotate_max_size = 1024 * 1024,
	.mail_index_log_rotate_min_age = 5 * 60,
	.mail_index_log2_max_age = 3600 * 24 * 2,
	.mailbox_idle_check_interval = 30,
	.mail_max_keyword_length = 50,
	.mail_max_lock_timeout = 0,
	.mail_temp_scan_interval = 7*24*60*60,
	.mail_vsize_bg_after_count = 0,
	.mail_sort_max_read_count = 0,
	.mail_save_crlf = FALSE,
	.mail_fsync = "optimized:never:always",
	.mmap_disable = FALSE,
	.dotlock_use_excl = TRUE,
	.mail_nfs_storage = FALSE,
	.mail_nfs_index = FALSE,
	.mailbox_list_index = TRUE,
	.mailbox_list_index_very_dirty_syncs = FALSE,
	.mailbox_list_index_include_inbox = FALSE,
	.mail_debug = FALSE,
	.mail_full_filesystem_access = FALSE,
	.maildir_stat_dirs = FALSE,
	.mail_shared_explicit_inbox = FALSE,
	.lock_method = "fcntl:flock:dotlock",
	.pop3_uidl_format = "%08Xu%08Xv",

	.hostname = "",
	.recipient_delimiter = "+",

	/* Keep synced with master-service-ssl-settings */
	.ssl_client_ca_file = "",
	.ssl_client_ca_dir = "",
	.ssl_client_cert = "",
	.ssl_client_key = "",
	.ssl_cipher_list = "ALL:!kRSA:!SRP:!kDHd:!DSS:!aNULL:!eNULL:!EXPORT:!DES:!3DES:!MD5:!PSK:!RC4:!ADH:!LOW@STRENGTH",
	.ssl_curve_list = "",
	.ssl_min_protocol = "TLSv1",
	.ssl_crypto_device = "",
	.ssl_client_require_valid_cert = TRUE,
	.verbose_ssl = FALSE,
};

const struct setting_parser_info mail_storage_setting_parser_info = {
	.module_name = "mail",
	.defines = mail_storage_setting_defines,
	.defaults = &mail_storage_default_settings,

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct mail_storage_settings),

	.parent_offset = (size_t)-1,
	.parent = &mail_user_setting_parser_info,

	.check_func = mail_storage_settings_check,
};

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct mailbox_settings, name), NULL }

static const struct setting_define mailbox_setting_defines[] = {
	DEF(SET_STR, name),
	{ SET_ENUM, "auto", offsetof(struct mailbox_settings, autocreate), NULL } ,
	DEF(SET_STR, special_use),
	DEF(SET_STR, driver),
	DEF(SET_STR, comment),
	DEF(SET_TIME, autoexpunge),
	DEF(SET_UINT, autoexpunge_max_mails),

	SETTING_DEFINE_LIST_END
};

const struct mailbox_settings mailbox_default_settings = {
	.name = "",
	.autocreate = MAILBOX_SET_AUTO_NO":"
		MAILBOX_SET_AUTO_CREATE":"
		MAILBOX_SET_AUTO_SUBSCRIBE,
	.special_use = "",
	.driver = "",
	.comment = "",
	.autoexpunge = 0,
	.autoexpunge_max_mails = 0
};

const struct setting_parser_info mailbox_setting_parser_info = {
	.defines = mailbox_setting_defines,
	.defaults = &mailbox_default_settings,

	.type_offset = offsetof(struct mailbox_settings, name),
	.struct_size = sizeof(struct mailbox_settings),

	.parent_offset = (size_t)-1,
	.parent = &mail_user_setting_parser_info,

	.check_func = mailbox_settings_check
};

#undef DEF
#undef DEFLIST_UNIQUE
#define DEF(type, name) \
	{ type, #name, offsetof(struct mail_namespace_settings, name), NULL }
#define DEFLIST_UNIQUE(field, name, defines) \
	{ SET_DEFLIST_UNIQUE, name, \
	  offsetof(struct mail_namespace_settings, field), defines }

static const struct setting_define mail_namespace_setting_defines[] = {
	DEF(SET_STR, name),
	DEF(SET_ENUM, type),
	DEF(SET_STR, separator),
	DEF(SET_STR_VARS, prefix),
	DEF(SET_STR_VARS, location),
	{ SET_ALIAS, "mail", 0, NULL },
	{ SET_ALIAS, "mail_location", 0, NULL },
	DEF(SET_STR_VARS, alias_for),

	DEF(SET_BOOL, inbox),
	DEF(SET_BOOL, hidden),
	DEF(SET_ENUM, list),
	DEF(SET_BOOL, subscriptions),
	DEF(SET_BOOL, ignore_on_failure),
	DEF(SET_BOOL, disabled),
	DEF(SET_UINT, order),

	DEFLIST_UNIQUE(mailboxes, "mailbox", &mailbox_setting_parser_info),

	SETTING_DEFINE_LIST_END
};

const struct mail_namespace_settings mail_namespace_default_settings = {
	.name = "",
	.type = "private:shared:public",
	.separator = "",
	.prefix = "",
	.location = "",
	.alias_for = NULL,

	.inbox = FALSE,
	.hidden = FALSE,
	.list = "yes:no:children",
	.subscriptions = TRUE,
	.ignore_on_failure = FALSE,
	.disabled = FALSE,
	.order = 0,

	.mailboxes = ARRAY_INIT
};

const struct setting_parser_info mail_namespace_setting_parser_info = {
	.defines = mail_namespace_setting_defines,
	.defaults = &mail_namespace_default_settings,

	.type_offset = offsetof(struct mail_namespace_settings, name),
	.struct_size = sizeof(struct mail_namespace_settings),

	.parent_offset = offsetof(struct mail_namespace_settings, user_set),
	.parent = &mail_user_setting_parser_info,

	.check_func = namespace_settings_check
};

#undef DEF
#undef DEFLIST_UNIQUE
#define DEF(type, name) \
	{ type, #name, offsetof(struct mail_user_settings, name), NULL }
#define DEFLIST_UNIQUE(field, name, defines) \
	{ SET_DEFLIST_UNIQUE, name, \
	  offsetof(struct mail_user_settings, field), defines }

static const struct setting_define mail_user_setting_defines[] = {
	DEF(SET_STR, base_dir),
	DEF(SET_STR, auth_socket_path),
	DEF(SET_STR_VARS, mail_temp_dir),

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

	DEF(SET_STR, hostname),
	DEF(SET_STR_VARS, postmaster_address),

	DEFLIST_UNIQUE(namespaces, "namespace", &mail_namespace_setting_parser_info),
	{ SET_STRLIST, "plugin", offsetof(struct mail_user_settings, plugin_envs), NULL },

	SETTING_DEFINE_LIST_END
};

static const struct mail_user_settings mail_user_default_settings = {
	.base_dir = PKG_RUNDIR,
	.auth_socket_path = "auth-userdb",
	.mail_temp_dir = "/tmp",

	.mail_uid = "",
	.mail_gid = "",
	.mail_home = "",
	.mail_chroot = "",
	.mail_access_groups = "",
	.mail_privileged_group = "",
	.valid_chroot_dirs = "",

	.first_valid_uid = 500,
	.last_valid_uid = 0,
	.first_valid_gid = 1,
	.last_valid_gid = 0,

	.mail_plugins = "",
	.mail_plugin_dir = MODULEDIR,

	.mail_log_prefix = "%s(%u)<%{pid}><%{session}>: ",

	.hostname = "",
	.postmaster_address = "postmaster@%{if;%d;ne;;%d;%{hostname}}",

	.namespaces = ARRAY_INIT,
	.plugin_envs = ARRAY_INIT
};

const struct setting_parser_info mail_user_setting_parser_info = {
	.module_name = "mail",
	.defines = mail_user_setting_defines,
	.defaults = &mail_user_default_settings,

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct mail_user_settings),

	.parent_offset = (size_t)-1,

	.check_func = mail_user_settings_check,
#ifndef CONFIG_BINARY
	.expand_check_func = mail_user_settings_expand_check,
#endif
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

const void *mail_namespace_get_driver_settings(struct mail_namespace *ns,
					       struct mail_storage *storage)
{
	return mail_user_set_get_driver_settings(storage->user->set_info,
						 ns->user_set, storage->name);
}

const struct dynamic_settings_parser *
mail_storage_get_dynamic_parsers(pool_t pool)
{
	struct dynamic_settings_parser *parsers;
	struct mail_storage *const *storages;
	unsigned int i, j, count;

	storages = array_get(&mail_storage_classes, &count);
	parsers = p_new(pool, struct dynamic_settings_parser, 1 + count + 1);
	parsers[0].name = MAIL_STORAGE_SET_DRIVER_NAME;
	parsers[0].info = &mail_storage_setting_parser_info;

	for (i = 0, j = 1; i < count; i++) {
		if (storages[i]->v.get_setting_parser_info == NULL)
			continue;

		parsers[j].name = storages[i]->name;
		parsers[j].info = storages[i]->v.get_setting_parser_info();
		j++;
	}
	parsers[j].name = NULL;
	return parsers;
}

static void
fix_base_path(struct mail_user_settings *set, pool_t pool, const char **str)
{
	if (*str != NULL && **str != '\0' && **str != '/')
		*str = p_strconcat(pool, set->base_dir, "/", *str, NULL);
}

/* <settings checks> */
static bool mail_storage_settings_check(void *_set, pool_t pool,
					const char **error_r)
{
	struct mail_storage_settings *set = _set;
	struct hash_format *format;
	const char *p, *error;
	bool uidl_format_ok;
	char c;

	if (set->mailbox_idle_check_interval == 0) {
		*error_r = "mailbox_idle_check_interval must not be 0";
		return FALSE;
	}

	if (strcmp(set->mail_fsync, "optimized") == 0)
		set->parsed_fsync_mode = FSYNC_MODE_OPTIMIZED;
	else if (strcmp(set->mail_fsync, "never") == 0)
		set->parsed_fsync_mode = FSYNC_MODE_NEVER;
	else if (strcmp(set->mail_fsync, "always") == 0)
		set->parsed_fsync_mode = FSYNC_MODE_ALWAYS;
	else {
		*error_r = t_strdup_printf("Unknown mail_fsync: %s",
					   set->mail_fsync);
		return FALSE;
	}

	if (set->mail_nfs_index && !set->mmap_disable) {
		*error_r = "mail_nfs_index=yes requires mmap_disable=yes";
		return FALSE;
	}
	if (set->mail_nfs_index &&
	    set->parsed_fsync_mode != FSYNC_MODE_ALWAYS) {
		*error_r = "mail_nfs_index=yes requires mail_fsync=always";
		return FALSE;
	}

	if (!file_lock_method_parse(set->lock_method,
				    &set->parsed_lock_method)) {
		*error_r = t_strdup_printf("Unknown lock_method: %s",
					   set->lock_method);
		return FALSE;
	}

	if (set->mail_cache_compress_delete_percentage > 100) {
		*error_r = "mail_cache_compress_delete_percentage can't be over 100";
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
		case 'g':
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

	if (strchr(set->mail_attachment_hash, '/') != NULL) {
		*error_r = "mail_attachment_hash setting "
			"must not contain '/' characters";
		return FALSE;
	}
	if (hash_format_init(set->mail_attachment_hash, &format, &error) < 0) {
		*error_r = t_strconcat("Invalid mail_attachment_hash setting: ",
				       error, NULL);
		return FALSE;
	}
	if (strchr(set->mail_attachment_hash, '-') != NULL) {
		*error_r = "mail_attachment_hash setting "
			"must not contain '-' characters";
		return FALSE;
	}
	hash_format_deinit_free(&format);
#ifndef CONFIG_BINARY
	if (*set->ssl_client_ca_dir != '\0' &&
	    access(set->ssl_client_ca_dir, X_OK) < 0) {
		*error_r = t_strdup_printf(
			"ssl_client_ca_dir: access(%s) failed: %m",
			set->ssl_client_ca_dir);
		return FALSE;
	}
#endif

	// FIXME: check set->mail_server_admin syntax (RFC 5464, Section 6.2.2)

#ifndef CONFIG_BINARY
	if (*set->hostname == '\0')
		set->hostname = p_strdup(pool, my_hostdomain());
#endif

	/* parse mail_attachment_indicator_options */
	if (*set->mail_attachment_detection_options != '\0') {
		ARRAY_TYPE(const_string) content_types;
		p_array_init(&content_types, pool, 2);

		const char *const *options =
			t_strsplit_spaces(set->mail_attachment_detection_options, " ");

		while(*options != NULL) {
			const char *opt = *options;

			if (strcmp(opt, "add-flags-on-save") == 0) {
				set->parsed_mail_attachment_detection_add_flags_on_save = TRUE;
			} else if (strcmp(opt, "exclude-inlined") == 0) {
				set->parsed_mail_attachment_exclude_inlined = TRUE;
			} else if (str_begins(opt, "content-type=")) {
				const char *value = p_strdup(pool, opt+13);
				array_push_back(&content_types, &value);
			} else {
				*error_r = t_strdup_printf("mail_attachment_detection_options: "
					"Unknown option: %s", opt);
				return FALSE;
			}
			options++;
		}

		array_append_zero(&content_types);
		set->parsed_mail_attachment_content_type_filter = array_front(&content_types);
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
	if (!uni_utf8_str_is_valid(name)) {
		*error_r = t_strdup_printf("Namespace prefix not valid UTF8: %s",
					   name);
		return FALSE;
	}

	if (ns->alias_for != NULL && !ns->disabled) {
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

static bool mailbox_special_use_exists(const char *name)
{
	if (name[0] != '\\')
		return FALSE;
	name++;

	if (strcasecmp(name, "All") == 0)
		return TRUE;
	if (strcasecmp(name, "Archive") == 0)
		return TRUE;
	if (strcasecmp(name, "Drafts") == 0)
		return TRUE;
	if (strcasecmp(name, "Flagged") == 0)
		return TRUE;
	if (strcasecmp(name, "Junk") == 0)
		return TRUE;
	if (strcasecmp(name, "Sent") == 0)
		return TRUE;
	if (strcasecmp(name, "Trash") == 0)
		return TRUE;
	return FALSE;
}

static bool
mailbox_special_use_check(struct mailbox_settings *set, pool_t pool,
			  const char **error_r)
{
	const char *const *uses, *str;
	unsigned int i;

	uses = t_strsplit_spaces(set->special_use, " ");
	for (i = 0; uses[i] != NULL; i++) {
		if (!mailbox_special_use_exists(uses[i])) {
			*error_r = t_strdup_printf(
				"mailbox %s: unknown special_use: %s",
				set->name, uses[i]);
			return FALSE;
		}
	}
	/* make sure there are no extra spaces */
	str = t_strarray_join(uses, " ");
	if (strcmp(str, set->special_use) != 0)
		set->special_use = p_strdup(pool, str);
	return TRUE;
}

static bool mailbox_settings_check(void *_set, pool_t pool,
				   const char **error_r)
{
	struct mailbox_settings *set = _set;

	if (!uni_utf8_str_is_valid(set->name)) {
		*error_r = t_strdup_printf("mailbox %s: name isn't valid UTF-8",
					   set->name);
		return FALSE;
	}
	if (*set->special_use != '\0') {
		if (!mailbox_special_use_check(set, pool, error_r))
			return FALSE;
	}
	return TRUE;
}

static bool mail_user_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				     const char **error_r ATTR_UNUSED)
{
	struct mail_user_settings *set = _set;

#ifndef CONFIG_BINARY
	fix_base_path(set, pool, &set->auth_socket_path);

	if (*set->hostname == '\0')
		set->hostname = p_strdup(pool, my_hostdomain());
	if (set->postmaster_address[0] == SETTING_STRVAR_UNEXPANDED[0] &&
	    set->postmaster_address[1] == '\0') {
		/* check for valid looking fqdn in hostname */
		if (strchr(set->hostname, '.') == NULL) {
			*error_r = "postmaster_address setting not given";
			return FALSE;
		}
		set->postmaster_address =
			p_strconcat(pool, SETTING_STRVAR_UNEXPANDED,
				    "postmaster@", set->hostname, NULL);
	}
#else
	if (*set->mail_plugins != '\0' &&
	    access(set->mail_plugin_dir, R_OK | X_OK) < 0) {
		*error_r = t_strdup_printf(
			"mail_plugin_dir: access(%s) failed: %m",
			set->mail_plugin_dir);
		return FALSE;
	}
#endif
	return TRUE;
}

#ifndef CONFIG_BINARY
static bool parse_postmaster_address(const char *address, pool_t pool,
				     struct mail_user_settings *set,
				     const char **error_r) ATTR_NULL(3)
{
	struct message_address *addr;
	struct smtp_address *smtp_addr;

	addr = message_address_parse(pool,
		(const unsigned char *)address,
		strlen(address), 2, 0);
	if (addr == NULL || addr->domain == NULL || addr->invalid_syntax ||
	    smtp_address_create_from_msg(pool, addr, &smtp_addr) < 0) {
		*error_r = t_strdup_printf(
			"invalid address `%s' specified for the "
			"postmaster_address setting", address);
		return FALSE;
	}
	if (addr->next != NULL) {
		*error_r = "more than one address specified for the "
			"postmaster_address setting";
		return FALSE;
	}
	if (addr->name == NULL || *addr->name == '\0')
		addr->name = "Postmaster";
	if (set != NULL) {
		set->_parsed_postmaster_address = addr;
		set->_parsed_postmaster_address_smtp = smtp_addr;
	}
	return TRUE;
}

static bool
mail_user_settings_expand_check(void *_set, pool_t pool,
				const char **error_r ATTR_UNUSED)
{
	struct mail_user_settings *set = _set;
	const char *error;

	/* Parse if possible. Perform error handling later. */
	(void)parse_postmaster_address(set->postmaster_address, pool,
				       set, &error);
	return TRUE;
}
#endif

/* </settings checks> */

static void
get_postmaster_address_error(const struct mail_user_settings *set,
			     const char **error_r)
{
	if (parse_postmaster_address(set->postmaster_address,
				     pool_datastack_create(), NULL, error_r))
		i_panic("postmaster_address='%s' parsing succeeded unexpectedly after it had already failed",
			set->postmaster_address);
}

bool mail_user_set_get_postmaster_address(const struct mail_user_settings *set,
					  const struct message_address **address_r,
					  const char **error_r)
{
	*address_r = set->_parsed_postmaster_address;
	if (*address_r != NULL)
		return TRUE;
	/* parsing failed - do it again to get the error */
	get_postmaster_address_error(set, error_r);
	return FALSE;
}

bool mail_user_set_get_postmaster_smtp(const struct mail_user_settings *set,
				       const struct smtp_address **address_r,
				       const char **error_r)
{
	*address_r = set->_parsed_postmaster_address_smtp;
	if (*address_r != NULL)
		return TRUE;
	/* parsing failed - do it again to get the error */
	get_postmaster_address_error(set, error_r);
	return FALSE;
}

