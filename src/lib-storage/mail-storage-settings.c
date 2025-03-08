/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash-format.h"
#include "unichar.h"
#include "hostpid.h"
#include "uri-util.h"
#include "settings.h"
#include "message-address.h"
#include "message-header-parser.h"
#include "smtp-address.h"
#include "mail-index.h"
#include "mail-user.h"
#include "mail-namespace.h"
#include "mail-storage-private.h"
#include "mail-storage-settings.h"
#include "iostream-ssl.h"

static bool mail_storage_settings_apply(struct event *event, void *_set, const char *key, const char **value, enum setting_apply_flags, const char **error_r);
static bool mail_storage_settings_ext_check(struct event *event, void *_set, pool_t pool, const char **error_r);
static bool namespace_settings_ext_check(struct event *event, void *_set, pool_t pool, const char **error_r);
static bool mailbox_settings_check(void *_set, pool_t pool, const char **error_r);
static bool mail_user_settings_apply(struct event *event, void *_set, const char *key, const char **value, enum setting_apply_flags, const char **error_r);
static bool mail_user_settings_check(void *_set, pool_t pool, const char **error_r);

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct mail_storage_settings)

static const struct setting_define mail_storage_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "layout_index" },
	{ .type = SET_FILTER_NAME, .key = "layout_maildir++" },
	{ .type = SET_FILTER_NAME, .key = "layout_imapdir" },
	{ .type = SET_FILTER_NAME, .key = "layout_fs" },
	{ .type = SET_FILTER_NAME, .key = "mail_ext_attachment",
	  .required_setting = "fs", },
	DEF(STR, mail_ext_attachment_path),
	DEF(STR_NOVARS_HIDDEN, mail_ext_attachment_hash),
	DEF(SIZE, mail_ext_attachment_min_size),
	DEF(BOOLLIST, mail_attachment_detection_options),
	{ .type = SET_FILTER_NAME, .key = "mail_attribute",
	  .required_setting = "dict", },
	DEF(UINT, mail_prefetch_count),
	DEF(BOOLLIST, mail_cache_fields),
	DEF(BOOLLIST, mail_always_cache_fields),
	DEF(BOOLLIST, mail_never_cache_fields),
	DEF(STR, mail_server_comment),
	DEF(STR, mail_server_admin),
	DEF(TIME_HIDDEN, mail_cache_unaccessed_field_drop),
	DEF(SIZE_HIDDEN, mail_cache_record_max_size),
	DEF(UINT_HIDDEN, mail_cache_max_header_name_length),
	DEF(UINT_HIDDEN, mail_cache_max_headers_count),
	DEF(SIZE_HIDDEN, mail_cache_max_size),
	DEF(UINT_HIDDEN, mail_cache_min_mail_count),
	DEF(SIZE_HIDDEN, mail_cache_purge_min_size),
	DEF(UINT_HIDDEN, mail_cache_purge_delete_percentage),
	DEF(UINT_HIDDEN, mail_cache_purge_continued_percentage),
	DEF(UINT_HIDDEN, mail_cache_purge_header_continue_count),
	DEF(SIZE_HIDDEN, mail_index_rewrite_min_log_bytes),
	DEF(SIZE_HIDDEN, mail_index_rewrite_max_log_bytes),
	DEF(SIZE_HIDDEN, mail_index_log_rotate_min_size),
	DEF(SIZE_HIDDEN, mail_index_log_rotate_max_size),
	DEF(TIME_HIDDEN, mail_index_log_rotate_min_age),
	DEF(TIME_HIDDEN, mail_index_log2_max_age),
	DEF(TIME_HIDDEN, mailbox_idle_check_interval),
	DEF(UINT_HIDDEN, mail_max_keyword_length),
	DEF(TIME, mail_max_lock_timeout),
	DEF(TIME, mail_temp_scan_interval),
	DEF(UINT, mail_vsize_bg_after_count),
	DEF(UINT, mail_sort_max_read_count),
	DEF(BOOL_HIDDEN, mail_save_crlf),
	DEF(ENUM, mail_fsync),
	DEF(BOOL, mmap_disable),
	DEF(BOOL, dotlock_use_excl),
	DEF(BOOL, mail_nfs_storage),
	DEF(BOOL, mail_nfs_index),
	DEF(BOOL, mailbox_list_index),
	DEF(BOOL, mailbox_list_index_very_dirty_syncs),
	DEF(BOOL, mailbox_list_index_include_inbox),
	DEF(STR, mailbox_list_layout),
	DEF(STR, mailbox_list_index_prefix),
	DEF(BOOL_HIDDEN, mailbox_list_iter_from_index_dir),
	DEF(BOOL_HIDDEN, mailbox_list_drop_noselect),
	DEF(BOOL_HIDDEN, mailbox_list_validate_fs_names),
	DEF(BOOL_HIDDEN, mailbox_list_utf8),
	DEF(STR, mailbox_list_visible_escape_char),
	DEF(STR, mailbox_list_storage_escape_char),
	DEF(STR_HIDDEN, mailbox_list_lost_mailbox_prefix),
	DEF(STR_HIDDEN, mailbox_directory_name),
	DEF(BOOL, mailbox_directory_name_legacy),
	DEF(STR_HIDDEN, mailbox_root_directory_name),
	DEF(STR_HIDDEN, mailbox_subscriptions_filename),
	DEF(STR, mail_driver),
	DEF(STR, mail_path),
	DEF(STR, mail_inbox_path),
	DEF(STR, mail_index_path),
	DEF(STR, mail_index_private_path),
	DEF(STR_HIDDEN, mail_cache_path),
	DEF(STR, mail_control_path),
	DEF(STR, mail_volatile_path),
	DEF(STR, mail_alt_path),
	DEF(BOOL_HIDDEN, mail_alt_check),
	DEF(BOOL_HIDDEN, mail_full_filesystem_access),
	DEF(BOOL, maildir_stat_dirs),
	DEF(BOOL, mail_shared_explicit_inbox),
	DEF(ENUM, lock_method),
	DEF(STR_NOVARS, pop3_uidl_format),

	DEF(STR, recipient_delimiter),

	SETTING_DEFINE_LIST_END
};

const struct mail_storage_settings mail_storage_default_settings = {
	.mail_ext_attachment_path = "",
	.mail_ext_attachment_hash = "%{sha1}",
	.mail_ext_attachment_min_size = 1024*128,
	.mail_attachment_detection_options = ARRAY_INIT,
	.mail_prefetch_count = 0,
	.mail_always_cache_fields = ARRAY_INIT,
	.mail_server_comment = "",
	.mail_server_admin = "",
	.mail_cache_min_mail_count = 0,
	.mail_cache_unaccessed_field_drop = 60*60*24*30,
	.mail_cache_record_max_size = 64 * 1024,
	.mail_cache_max_header_name_length = 100,
	.mail_cache_max_headers_count = 100,
	.mail_cache_max_size = 1024 * 1024 * 1024,
	.mail_cache_purge_min_size = 32 * 1024,
	.mail_cache_purge_delete_percentage = 20,
	.mail_cache_purge_continued_percentage = 200,
	.mail_cache_purge_header_continue_count = 4,
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
	.mailbox_list_layout = "fs",
	.mailbox_list_index_prefix = "dovecot.list.index",
	.mailbox_list_iter_from_index_dir = FALSE,
	.mailbox_list_drop_noselect = TRUE,
	.mailbox_list_validate_fs_names = TRUE,
	.mailbox_list_utf8 = FALSE,
	.mailbox_list_visible_escape_char = "",
	.mailbox_list_storage_escape_char = "",
	.mailbox_list_lost_mailbox_prefix = "recovered-lost-folder-",
	.mailbox_directory_name = "",
	.mailbox_directory_name_legacy = TRUE,
	.mailbox_root_directory_name = "",
	.mailbox_subscriptions_filename = "subscriptions",
	.mail_driver = "",
	.mail_path = "",
	.mail_inbox_path = "",
	.mail_index_path = "",
	.mail_index_private_path = "",
	.mail_cache_path = "",
	.mail_control_path = "",
	.mail_volatile_path = "",
	.mail_alt_path = "",
	.mail_alt_check = TRUE,
	.mail_full_filesystem_access = FALSE,
	.maildir_stat_dirs = FALSE,
	.mail_shared_explicit_inbox = FALSE,
	.lock_method = "fcntl:flock:dotlock",
	.pop3_uidl_format = "%{uid | hex(8)}%{uidvalidity | hex(8)}",

	.recipient_delimiter = "+",
};

static const struct setting_keyvalue mail_storage_default_settings_keyvalue[] = {
	{ "layout_index/mailbox_list_storage_escape_char", "^" },
#define MAIL_CACHE_FIELDS_DEFAULT \
	"flags " \
	/* IMAP ENVELOPE: */ \
	"hdr.date hdr.subject hdr.from hdr.sender hdr.reply-to hdr.to hdr.cc hdr.bcc hdr.in-reply-to hdr.message-id " \
	/* Commonly used by clients: */ \
	"date.received size.virtual imap.bodystructure mime.parts hdr.references " \
	/* AppSuite, at least: */ \
	"hdr.importance hdr.x-priority " \
	"hdr.x-open-xchange-share-url " \
	/* POP3: */ \
	"pop3.uidl pop3.order"
	{ "mail_cache_fields", MAIL_CACHE_FIELDS_DEFAULT },
#ifdef DOVECOT_PRO_EDITION
	{ "mail_always_cache_fields", MAIL_CACHE_FIELDS_DEFAULT },
#endif
	{ "mail_never_cache_fields", "imap.envelope" },
	{ NULL, NULL }
};

const struct setting_parser_info mail_storage_setting_parser_info = {
	.name = "mail_storage",

	.defines = mail_storage_setting_defines,
	.defaults = &mail_storage_default_settings,
	.default_settings = mail_storage_default_settings_keyvalue,

	.struct_size = sizeof(struct mail_storage_settings),
	.pool_offset1 = 1 + offsetof(struct mail_storage_settings, pool),
	.setting_apply = mail_storage_settings_apply,
	.ext_check_func = mail_storage_settings_ext_check,
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct mail_driver_settings)

static const struct setting_define mail_driver_setting_defines[] = {
	DEF(STR, mail_driver),
	SETTING_DEFINE_LIST_END
};

const struct mail_driver_settings mail_driver_default_settings = {
	.mail_driver = "",
};

const struct setting_parser_info mail_driver_setting_parser_info = {
	.name = "mail_driver",

	.defines = mail_driver_setting_defines,
	.defaults = &mail_driver_default_settings,

	.struct_size = sizeof(struct mail_driver_settings),
	.pool_offset1 = 1 + offsetof(struct mail_driver_settings, pool),
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct mailbox_list_layout_settings)

static const struct setting_define mailbox_list_layout_setting_defines[] = {
	DEF(STR, mailbox_list_layout),
	SETTING_DEFINE_LIST_END
};

const struct mailbox_list_layout_settings mailbox_list_layout_default_settings = {
	.mailbox_list_layout = "fs",
};

const struct setting_parser_info mailbox_list_layout_setting_parser_info = {
	.name = "mailbox_list_layout",

	.defines = mailbox_list_layout_setting_defines,
	.defaults = &mailbox_list_layout_default_settings,

	.struct_size = sizeof(struct mailbox_list_layout_settings),
	.pool_offset1 = 1 + offsetof(struct mailbox_list_layout_settings, pool),
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("mailbox_"#name, name, struct mailbox_settings)

static const struct setting_define mailbox_setting_defines[] = {
	DEF(STR, name),
	{ .type = SET_ENUM, .key = "mailbox_auto",
	  .offset = offsetof(struct mailbox_settings, autocreate) } ,
	DEF(BOOLLIST, special_use),
	DEF(STR, comment),
	DEF(TIME, autoexpunge),
	DEF(UINT, autoexpunge_max_mails),

	SETTING_DEFINE_LIST_END
};

const struct mailbox_settings mailbox_default_settings = {
	.name = "",
	.autocreate = MAILBOX_SET_AUTO_NO":"
		MAILBOX_SET_AUTO_CREATE":"
		MAILBOX_SET_AUTO_SUBSCRIBE,
	.special_use = ARRAY_INIT,
	.comment = "",
	.autoexpunge = 0,
	.autoexpunge_max_mails = 0
};

const struct setting_parser_info mailbox_setting_parser_info = {
	.name = "mailbox",

	.defines = mailbox_setting_defines,
	.defaults = &mailbox_default_settings,

	.struct_size = sizeof(struct mailbox_settings),
	.pool_offset1 = 1 + offsetof(struct mailbox_settings, pool),

	.check_func = mailbox_settings_check
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("namespace_"#name, name, struct mail_namespace_settings)

static const struct setting_define mail_namespace_setting_defines[] = {
	DEF(STR, name),
	DEF(ENUM, type),
	DEF(STR, separator),
	DEF(STR, prefix),
	DEF(STR, alias_for),

	DEF(BOOL, inbox),
	DEF(BOOL, hidden),
	DEF(ENUM, list),
	DEF(BOOL, subscriptions),
	DEF(BOOL, ignore_on_failure),
	DEF(BOOL, disabled),
	DEF(UINT, order),

	{ .type = SET_FILTER_ARRAY, .key = "mailbox",
	   .offset = offsetof(struct mail_namespace_settings, mailboxes),
	   .filter_array_field_name = "mailbox_name" },

	SETTING_DEFINE_LIST_END
};

const struct mail_namespace_settings mail_namespace_default_settings = {
	.name = "",
	.type = "private:shared:public",
	.separator = "",
	.prefix = "",
	.alias_for = "",

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
	.name = "mail_namespace",

	.defines = mail_namespace_setting_defines,
	.defaults = &mail_namespace_default_settings,

	.struct_size = sizeof(struct mail_namespace_settings),
	.pool_offset1 = 1 + offsetof(struct mail_namespace_settings, pool),

	.ext_check_func = namespace_settings_ext_check,
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct mail_user_settings)

static const struct setting_define mail_user_setting_defines[] = {
	DEF(STR_HIDDEN, base_dir),
	DEF(STR, auth_socket_path),
	DEF(STR, mail_temp_dir),
	DEF(BOOL, mail_debug),

	DEF(STR, mail_uid),
	DEF(STR, mail_gid),
	DEF(STR, mail_home),
	DEF(STR, mail_chroot),
	DEF(BOOLLIST, mail_access_groups),
	DEF(STR, mail_privileged_group),
	DEF(BOOLLIST, valid_chroot_dirs),

	DEF(UINT, first_valid_uid),
	DEF(UINT, last_valid_uid),
	DEF(UINT, first_valid_gid),
	DEF(UINT, last_valid_gid),

	DEF(BOOLLIST, mail_plugins),
	DEF(STR, mail_plugin_dir),

	DEF(STR, mail_log_prefix),

	{ .type = SET_FILTER_ARRAY, .key = "namespace",
	   .offset = offsetof(struct mail_user_settings, namespaces),
	   .filter_array_field_name = "namespace_name" },
	DEF(STR, hostname),
	DEF(STR, postmaster_address),

	SETTING_DEFINE_LIST_END
};

static const struct mail_user_settings mail_user_default_settings = {
	.base_dir = PKG_RUNDIR,
	.auth_socket_path = "auth-userdb",
#ifdef DOVECOT_PRO_EDITION
	.mail_temp_dir = "/dev/shm/dovecot",
#else
	.mail_temp_dir = "/tmp",
#endif
	.mail_debug = FALSE,

#ifdef DOVECOT_PRO_EDITION
	.mail_uid = "vmail",
	.mail_gid = "vmail",
#else
	.mail_uid = "",
	.mail_gid = "",
#endif
	.mail_home = "",
	.mail_chroot = "",
	.mail_access_groups = ARRAY_INIT,
	.mail_privileged_group = "",
	.valid_chroot_dirs = ARRAY_INIT,

	.first_valid_uid = 500,
	.last_valid_uid = 0,
	.first_valid_gid = 1,
	.last_valid_gid = 0,

	.mail_plugins = ARRAY_INIT,
	.mail_plugin_dir = MODULEDIR,

	.mail_log_prefix = "%{service}(%{user})<%{process:pid}><%{session}>: ",

	.namespaces = ARRAY_INIT,
	.hostname = "",
	.postmaster_address = "postmaster@%{user|domain|default(hostname)}",
};

const struct setting_parser_info mail_user_setting_parser_info = {
	.name = "mail_user",

	.defines = mail_user_setting_defines,
	.defaults = &mail_user_default_settings,

	.struct_size = sizeof(struct mail_user_settings),
	.pool_offset1 = 1 + offsetof(struct mail_user_settings, pool),
	.setting_apply = mail_user_settings_apply,
	.check_func = mail_user_settings_check,
};

static struct mail_user *mail_storage_event_get_user(struct event *event)
{
	struct mail_user *user;

	for (; event != NULL; event = event_get_parent(event)) {
		user = event_get_ptr(event, SETTINGS_EVENT_MAIL_USER);
		if (user != NULL)
			return user;
	}
	i_panic("mail_user not found from event");
}

static void
fix_base_path(struct mail_user_settings *set, pool_t pool, const char **str)
{
	if (*str != NULL && **str != '\0' && **str != '/')
		*str = p_strconcat(pool, set->base_dir, "/", *str, NULL);
}

/* <settings checks> */
static bool mail_cache_fields_parse(const char *key,
				    const ARRAY_TYPE(const_string) *value,
				    const char **error_r)
{
	const char *const *arr;
	bool has_asterisk = FALSE;
	size_t fields_count = 0;

	for (arr = settings_boollist_get(value); *arr != NULL; arr++) {
		const char *name = *arr;

		if (str_begins_icase(name, "hdr.", &name) &&
		    !message_header_name_is_valid(name)) {
			*error_r = t_strdup_printf(
				"Invalid %s: %s is not a valid header name",
				key, name);
			return FALSE;
		} else if (strcmp(name, "*") == 0) {
			has_asterisk = TRUE;
		}
		fields_count++;
	}
	if (has_asterisk && fields_count > 1) {
		*error_r = t_strdup_printf(
			"Invalid %s: has multiple values while having \"*\" set", key);
		return FALSE;
	}
	return TRUE;
}

static bool
mailbox_list_get_path_setting(const char *key, const char **value,
			      pool_t pool, enum mailbox_list_path_type *type_r)
{
	const char *fname;

	if (strcmp(key, "mailbox_list_index_prefix") == 0) {
		if ((fname = strrchr(*value, '/')) == NULL)
			*value = NULL;
		else
			*value = p_strdup_until(pool, *value, fname);
		*type_r = MAILBOX_LIST_PATH_TYPE_LIST_INDEX;
		return TRUE;
	}
	struct {
		const char *set_name;
		enum mailbox_list_path_type type;
	} set_types[] = {
		{ "mail_path", MAILBOX_LIST_PATH_TYPE_DIR },
		{ "mail_index_path", MAILBOX_LIST_PATH_TYPE_INDEX },
		{ "mail_index_private_path", MAILBOX_LIST_PATH_TYPE_INDEX_PRIVATE },
		{ "mail_cache_path", MAILBOX_LIST_PATH_TYPE_INDEX_CACHE },
		{ "mail_control_path", MAILBOX_LIST_PATH_TYPE_CONTROL },
		{ "mail_alt_path", MAILBOX_LIST_PATH_TYPE_ALT_DIR },
	};
	for (unsigned int i = 0; i < N_ELEMENTS(set_types); i++) {
		if (strcmp(set_types[i].set_name, key) == 0) {
			*type_r = set_types[i].type;
			return TRUE;
		}
	}
	return FALSE;
}

static bool
mail_storage_settings_apply(struct event *event ATTR_UNUSED, void *_set,
			    const char *key, const char **value,
			    enum setting_apply_flags flags,
			    const char **error_r)
{
	struct mail_storage_settings *set = _set;
	enum mailbox_list_path_type type;
	const char *unexpanded_value = *value;

	unsigned int key_len = strlen(key);
	if (key_len > 5 && strcmp(key + key_len - 5, "_path") == 0) {
		unsigned int value_len = strlen(*value);
		bool truncate = FALSE;

		/* drop trailing '/' and convert ~/ to %{home}/ */
		if (value_len > 0 && (*value)[value_len-1] == '/')
			truncate = TRUE;
		if ((str_begins_with(*value, "~/") ||
		     strcmp(*value, "~") == 0) &&
		    (flags & SETTING_APPLY_FLAG_NO_EXPAND) == 0) {
#ifndef CONFIG_BINARY
			struct mail_user *user =
				mail_storage_event_get_user(event);
			const char *home;
			if (mail_user_get_home(user, &home) > 0)
				;
			else if (user->nonexistent) {
				/* Nonexistent shared user. Don't fail the user
				   creation due to this. */
				home = "";
			} else {
				*error_r = t_strdup_printf(
					"%s setting used home directory (~/) but there is no "
					"mail_home and userdb didn't return it", key);
				return FALSE;
			}
			if (!truncate)
				*value = p_strconcat(set->pool, home, *value + 1, NULL);
			else T_BEGIN {
				*value = p_strconcat(set->pool, home,
					t_strndup(*value + 1, value_len - 2), NULL);
			} T_END;
#else
			*error_r = "~/ expansion not supported in config binary";
			return FALSE;
#endif
		} else if (truncate) {
			*value = p_strndup(set->pool, *value, value_len - 1);
		}
	}

	if (mailbox_list_get_path_setting(key, &unexpanded_value,
					  set->pool, &type)) {
		set->unexpanded_mailbox_list_path[type] = unexpanded_value;
		set->unexpanded_mailbox_list_override[type] =
			(flags & SETTING_APPLY_FLAG_OVERRIDE) != 0;
	}
	return TRUE;
}

static bool
mail_storage_settings_ext_check(struct event *event ATTR_UNUSED,
				void *_set, pool_t pool, const char **error_r)
{
	struct mail_storage_settings *set = _set;
	struct hash_format *format;
	const char *value, *fname, *error;
	bool uidl_format_ok;

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

	if (set->mail_cache_max_size > 1024 * 1024 * 1024) {
		*error_r = "mail_cache_max_size can't be over 1 GB";
		return FALSE;
	}
	if (set->mail_cache_purge_delete_percentage > 100) {
		*error_r = "mail_cache_purge_delete_percentage can't be over 100";
		return FALSE;
	}

	uidl_format_ok = FALSE;
	struct var_expand_program *prog;
	if (var_expand_program_create(set->pop3_uidl_format, &prog, &error) < 0) {
		*error_r = t_strdup_printf("Invalid pop3_uidl_format: %s", error);
		return FALSE;
	}

	const char *const *pop3_uidl_vars = var_expand_program_variables(prog);
	const char *const pop3_uidl_allowed_vars[] = {
		"uidvalidity",
		"uid",
		"md5",
		"filename",
		"guid",
		NULL
	};
	*error_r = NULL;
	for (; *pop3_uidl_vars != NULL; pop3_uidl_vars++) {
		if (!str_array_find(pop3_uidl_allowed_vars, *pop3_uidl_vars)) {
			*error_r = t_strdup_printf(
					"Unknown pop3_uidl_format variable: %%{%s}",
					*pop3_uidl_vars);
			break;
		}
		uidl_format_ok = TRUE;
	}
	var_expand_program_free(&prog);

	if (!uidl_format_ok) {
		if (*error_r == NULL)
			*error_r = "pop3_uidl_format setting doesn't contain any "
				   "%{variables}.";
		return FALSE;
	}

	if (strchr(set->mail_ext_attachment_hash, '/') != NULL) {
		*error_r = "mail_attachment_hash setting "
			"must not contain '/' characters";
		return FALSE;
	}
	if (hash_format_init(set->mail_ext_attachment_hash,
			     &format, &error) < 0) {
		*error_r = t_strconcat("Invalid mail_attachment_hash setting: ",
				       error, NULL);
		return FALSE;
	}
	if (strchr(set->mail_ext_attachment_hash, '-') != NULL) {
		*error_r = "mail_attachment_hash setting "
			"must not contain '-' characters";
		return FALSE;
	}
	hash_format_deinit_free(&format);

	/* check mail_server_admin syntax (RFC 5464, Section 6.2.2) */
	if (*set->mail_server_admin != '\0' &&
	    uri_check(set->mail_server_admin, 0, &error) < 0) {
		*error_r = t_strdup_printf("mail_server_admin: "
					   "'%s' is not a valid URI: %s",
					   set->mail_server_admin, error);
		return FALSE;
	}

	/* parse mail_attachment_indicator_options */
	if (array_not_empty(&set->mail_attachment_detection_options)) {
		ARRAY_TYPE(const_string) content_types;
		p_array_init(&content_types, pool, 2);

		const char *const *options =
			settings_boollist_get(&set->mail_attachment_detection_options);

		while(*options != NULL) {
			const char *opt = *options;

			if (strcmp(opt, "add-flags") == 0 ||
			    strcmp(opt, "add-flags-on-save") == 0) {
				set->parsed_mail_attachment_detection_add_flags = TRUE;
			} else if (strcmp(opt, "no-flags-on-fetch") == 0) {
				set->parsed_mail_attachment_detection_no_flags_on_fetch = TRUE;
			} else if (strcmp(opt, "exclude-inlined") == 0) {
				set->parsed_mail_attachment_exclude_inlined = TRUE;
			} else if (str_begins(opt, "content-type=", &value)) {
				value = p_strdup(pool, value);
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

	if (!mail_cache_fields_parse("mail_cache_fields",
				     &set->mail_cache_fields, error_r))
		return FALSE;
	if (!mail_cache_fields_parse("mail_always_cache_fields",
				     &set->mail_always_cache_fields, error_r))
		return FALSE;
	if (!mail_cache_fields_parse("mail_never_cache_fields",
				     &set->mail_never_cache_fields, error_r))
		return FALSE;

	if ((fname = strrchr(set->mailbox_list_index_prefix, '/')) == NULL)
		set->parsed_list_index_fname = set->mailbox_list_index_prefix;
	else {
		/* non-default list index directory */
		set->parsed_list_index_dir =
			p_strdup_until(pool, set->mailbox_list_index_prefix, fname);
		set->parsed_list_index_fname = fname+1;
		if (set->parsed_list_index_dir[0] != '/' &&
		    set->mail_index_path[0] == '\0') {
			*error_r = "mailbox_list_index_prefix directory is relative, but mail_index_path is empty";
			return FALSE;
		}
	}
	if (set->mailbox_root_directory_name[0] == '\0')
		set->parsed_mailbox_root_directory_prefix = "";
	else if (strchr(set->mailbox_root_directory_name, '/') != NULL) {
		*error_r = "mailbox_root_directory_name must not contain '/'";
		return FALSE;
	} else {
		set->parsed_mailbox_root_directory_prefix = p_strconcat(pool,
			set->mailbox_root_directory_name, "/", NULL);
	}

	if (set->mailbox_list_visible_escape_char != set_value_unknown &&
	    strlen(set->mailbox_list_visible_escape_char) > 1) {
		*error_r = "mailbox_list_visible_escape_char value must be a single character";
		return FALSE;
	}
	if (set->mailbox_list_storage_escape_char != set_value_unknown &&
	    strlen(set->mailbox_list_storage_escape_char) > 1) {
		*error_r = "mailbox_list_storage_escape_char value must be a single character";
		return FALSE;
	}

	if (set->mail_inbox_path[0] != '\0' && set->mail_inbox_path[0] != '/') {
		/* Convert to absolute path */
		if (strcmp(set->mail_inbox_path, ".") == 0)
			set->mail_inbox_path = set->mail_path;
		else {
			set->mail_inbox_path = p_strdup_printf(pool, "%s/%s",
				set->mail_path, set->mail_inbox_path);
		}
	}
	return TRUE;
}

static int
namespace_parse_mailboxes(struct event *event, pool_t pool,
			  struct mail_namespace_settings *ns,
			  const char **error_r)
{
	const struct mailbox_settings *box_set;
	const char *box_name, *error;
	int ret = 0;

	if (array_is_empty(&ns->mailboxes))
		return 0;

	p_array_init(&ns->parsed_mailboxes, pool,
		     array_count(&ns->mailboxes));
	event = event_create(event);
	event_add_str(event, SETTINGS_EVENT_NAMESPACE_NAME, ns->name);
	settings_event_add_list_filter_name(event,
		SETTINGS_EVENT_NAMESPACE_NAME, ns->name);
	array_foreach_elem(&ns->mailboxes, box_name) {
		if (settings_get_filter(event,
					"mailbox", box_name,
					&mailbox_setting_parser_info, 0,
					&box_set, &error) < 0) {
			*error_r = t_strdup_printf(
				"Failed to get mailbox %s: %s",
				box_name, error);
			ret = -1;
			break;
		}
		array_push_back(&ns->parsed_mailboxes, &box_set);
		pool_add_external_ref(pool, box_set->pool);
		bool have_special_use = array_not_empty(&box_set->special_use);
		settings_free(box_set);
		if (have_special_use)
			ns->parsed_have_special_use_mailboxes = TRUE;
	}
	event_unref(&event);
	return ret;
}

static bool namespace_settings_ext_check(struct event *event,
					 void *_set, pool_t pool,
					 const char **error_r)
{
	struct mail_namespace_settings *ns = _set;

	if (ns->separator[0] != '\0' && ns->separator[1] != '\0') {
		*error_r = t_strdup_printf("Namespace %s: "
			"Hierarchy separator must be only one character long",
			ns->name);
		return FALSE;
	}
	if (!uni_utf8_str_is_valid(ns->prefix)) {
		*error_r = t_strdup_printf("Namespace %s: prefix not valid UTF8: %s",
					   ns->name, ns->prefix);
		return FALSE;
	}

	return namespace_parse_mailboxes(event, pool, ns, error_r) == 0;
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
	if (strcasecmp(name, "Important") == 0)
		return TRUE;
	if (strcasecmp(name, "Junk") == 0)
		return TRUE;
	if (strcasecmp(name, "Sent") == 0)
		return TRUE;
	if (strcasecmp(name, "Trash") == 0)
		return TRUE;
	return FALSE;
}

static void
mailbox_special_use_check(struct mailbox_settings *set)
{
	const char *const *uses;
	unsigned int i;

	uses = settings_boollist_get(&set->special_use);
	for (i = 0; uses[i] != NULL; i++) {
		if (!mailbox_special_use_exists(uses[i])) {
			i_warning("mailbox %s: special_use label %s is not an "
				  "RFC-defined label - allowing anyway",
				  set->name, uses[i]);
		}
	}
}

static bool mailbox_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				   const char **error_r)
{
	struct mailbox_settings *set = _set;

	if (!uni_utf8_str_is_valid(set->name)) {
		*error_r = t_strdup_printf("mailbox %s: name isn't valid UTF-8",
					   set->name);
		return FALSE;
	}
	mailbox_special_use_check(set);
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
#endif

static bool
mail_user_settings_apply(struct event *event ATTR_UNUSED, void *_set,
			 const char *key, const char **value,
			 enum setting_apply_flags flags ATTR_UNUSED,
			 const char **error_r ATTR_UNUSED)
{
	struct mail_user_settings *set = _set;

	if (strcmp(key, "mail_log_prefix") == 0)
		set->unexpanded_mail_log_prefix = *value;
	return TRUE;
}

static bool mail_user_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				     const char **error_r ATTR_UNUSED)
{
	struct mail_user_settings *set = _set;

#ifndef CONFIG_BINARY
	i_assert(set->unexpanded_mail_log_prefix != NULL);
	fix_base_path(set, pool, &set->auth_socket_path);

	if (*set->hostname == '\0')
		set->hostname = p_strdup(pool, my_hostdomain());
	/* Parse if possible. Perform error handling later. */
	const char *error ATTR_UNUSED;
	(void)parse_postmaster_address(set->postmaster_address, pool,
				       set, &error);
#else
	if (array_is_created(&set->mail_plugins) &&
	    array_not_empty(&set->mail_plugins) &&
	    faccessat(AT_FDCWD, set->mail_plugin_dir, R_OK | X_OK, AT_EACCESS) < 0) {
		*error_r = t_strdup_printf(
			"mail_plugin_dir: access(%s) failed: %m",
			set->mail_plugin_dir);
		return FALSE;
	}
#endif
	return TRUE;
}

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

#define OFFSET(name) offsetof(struct mail_storage_settings, name)
static const size_t mail_storage_2nd_reset_offsets[] = {
	OFFSET(mailbox_list_layout),
	OFFSET(mailbox_list_index_prefix),
	OFFSET(mailbox_list_iter_from_index_dir),
	OFFSET(mailbox_list_utf8),
	OFFSET(mailbox_list_visible_escape_char),
	OFFSET(mailbox_list_storage_escape_char),
	OFFSET(mailbox_directory_name),
	OFFSET(mailbox_directory_name_legacy),
	OFFSET(mailbox_root_directory_name),
	OFFSET(mailbox_subscriptions_filename),
	OFFSET(mail_driver),
	OFFSET(mail_path),
	OFFSET(mail_inbox_path),
	OFFSET(mail_index_path),
	OFFSET(mail_index_private_path),
	OFFSET(mail_cache_path),
	OFFSET(mail_control_path),
	OFFSET(mail_volatile_path),
	OFFSET(mail_alt_path),
	OFFSET(mail_alt_check),
};

static void
mail_storage_2nd_setting_reset_def(struct settings_instance *instance,
				   const struct setting_define *def,
				   const char *key_prefix)
{
	const char *value;

	switch (def->type) {
	case SET_BOOL: {
		const bool *v = CONST_PTR_OFFSET(&mail_storage_default_settings,
						 def->offset);
		value = *v ? "yes" : "no";
		break;
	}
	case SET_STR: {
		const char *const *v =
			CONST_PTR_OFFSET(&mail_storage_default_settings,
					 def->offset);
		value = *v;
		break;
	}
	default:
		i_panic("Unsupported type %d", def->type);
	}
	settings_override(instance,
			  t_strdup_printf("%s%s", key_prefix, def->key),
			  value, SETTINGS_OVERRIDE_TYPE_2ND_DEFAULT);
}

static void
mail_storage_2nd_setting_reset_offset(struct settings_instance *instance,
				      size_t offset, const char *key_prefix)
{
	for (unsigned int i = 0; mail_storage_setting_defines[i].key != NULL; i++) {
		if (mail_storage_setting_defines[i].offset == offset) {
			mail_storage_2nd_setting_reset_def(instance,
				&mail_storage_setting_defines[i], key_prefix);
			return;
		}
	}
	i_panic("mail_storage_setting_defines didn't have offset %zu", offset);
}

void mail_storage_2nd_settings_reset(struct settings_instance *instance,
				     const char *key_prefix)
{
	unsigned int i;

	T_BEGIN {
		for (i = 0; i < N_ELEMENTS(mail_storage_2nd_reset_offsets); i++) {
			mail_storage_2nd_setting_reset_offset(instance,
				mail_storage_2nd_reset_offsets[i], key_prefix);
		}
	} T_END;
}

const char *
mailbox_settings_get_vname(pool_t pool, const struct mail_namespace *ns,
			   const struct mailbox_settings *set)
{
	if (ns->prefix_len == 0 || strcasecmp(set->name, "INBOX") == 0)
		return set->name;

	if (*set->name == '\0') {
		/* namespace prefix itself */
		return p_strndup(pool, ns->prefix, ns->prefix_len-1);
	} else {
		return p_strconcat(pool, ns->prefix, set->name, NULL);
	}
}
