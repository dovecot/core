#ifndef MAIL_STORAGE_SETTINGS_H
#define MAIL_STORAGE_SETTINGS_H

#include "file-lock.h"
#include "fsync-mode.h"
#include "mailbox-list.h"

/* mail_index_path setting points to using in-memory indexes */
#define MAIL_INDEX_PATH_MEMORY "MEMORY"

struct mail_user;
struct mail_namespace;
struct mail_storage;
struct message_address;
struct smtp_address;
struct setting_parser_context;
struct settings_instance;

struct mail_driver_settings {
	pool_t pool;
	const char *mail_driver;
};

struct mailbox_list_layout_settings {
	pool_t pool;
	const char *mailbox_list_layout;
};

struct mail_storage_settings {
	pool_t pool;
	const char *mail_driver;
	const char *mail_ext_attachment_path;
	const char *mail_ext_attachment_hash;
	uoff_t mail_ext_attachment_min_size;
	unsigned int mail_prefetch_count;
	ARRAY_TYPE(const_string) mail_cache_fields;
	ARRAY_TYPE(const_string) mail_always_cache_fields;
	ARRAY_TYPE(const_string) mail_never_cache_fields;
	const char *mail_server_comment;
	const char *mail_server_admin;
	unsigned int mail_cache_min_mail_count;
	unsigned int mail_cache_unaccessed_field_drop;
	uoff_t mail_cache_record_max_size;
	unsigned int mail_cache_max_header_name_length;
	unsigned int mail_cache_max_headers_count;
	uoff_t mail_cache_max_size;
	uoff_t mail_cache_purge_min_size;
	unsigned int mail_cache_purge_delete_percentage;
	unsigned int mail_cache_purge_continued_percentage;
	unsigned int mail_cache_purge_header_continue_count;
	uoff_t mail_index_rewrite_min_log_bytes;
	uoff_t mail_index_rewrite_max_log_bytes;
	uoff_t mail_index_log_rotate_min_size;
	uoff_t mail_index_log_rotate_max_size;
	unsigned int mail_index_log_rotate_min_age;
	unsigned int mail_index_log2_max_age;
	unsigned int mailbox_idle_check_interval;
	unsigned int mail_max_keyword_length;
	unsigned int mail_max_lock_timeout;
	unsigned int mail_temp_scan_interval;
	unsigned int mail_vsize_bg_after_count;
	unsigned int mail_sort_max_read_count;
	bool mail_save_crlf;
	const char *mail_fsync;
	bool mmap_disable;
	bool dotlock_use_excl;
	bool mail_nfs_storage;
	bool mail_nfs_index;
	bool mailbox_list_index;
	bool mailbox_list_index_very_dirty_syncs;
	bool mailbox_list_index_include_inbox;
	const char *mailbox_list_layout;
	const char *mailbox_list_index_prefix;
	bool mailbox_list_iter_from_index_dir;
	bool mailbox_list_drop_noselect;
	bool mailbox_list_validate_fs_names;
	bool mailbox_list_utf8;
	const char *mailbox_list_visible_escape_char;
	const char *mailbox_list_storage_escape_char;
	const char *mailbox_list_lost_mailbox_prefix;
	const char *mailbox_directory_name;
	bool mailbox_directory_name_legacy;
	const char *mailbox_root_directory_name;
	const char *mailbox_subscriptions_filename;
	const char *mail_path;
	const char *mail_inbox_path;
	const char *mail_index_path;
	const char *mail_index_private_path;
	const char *mail_cache_path;
	const char *mail_control_path;
	const char *mail_volatile_path;
	const char *mail_alt_path;
	bool mail_alt_check;
	bool mail_full_filesystem_access;
	bool maildir_stat_dirs;
	bool mail_shared_explicit_inbox;
	const char *lock_method;
	const char *pop3_uidl_format;

	const char *recipient_delimiter;

	ARRAY_TYPE(const_string) mail_attachment_detection_options;

	enum file_lock_method parsed_lock_method;
	enum fsync_mode parsed_fsync_mode;

	const char *const *parsed_mail_attachment_content_type_filter;
	bool parsed_mail_attachment_exclude_inlined;
	bool parsed_mail_attachment_detection_add_flags;
	bool parsed_mail_attachment_detection_no_flags_on_fetch;
	/* Filename part of mailbox_list_index_prefix */
	const char *parsed_list_index_fname;
	/* Directory part of mailbox_list_index_prefix. NULL defaults to index
	   directory. The path may be relative to the index directory. */
	const char *parsed_list_index_dir;
	/* If set, store mailboxes under root_dir/mailbox_dir_name/.
	   This setting contains either "" or "dir/" with trailing "/". */
	const char *parsed_mailbox_root_directory_prefix;

	const char *unexpanded_mailbox_list_path[MAILBOX_LIST_PATH_TYPE_COUNT];
	bool unexpanded_mailbox_list_override[MAILBOX_LIST_PATH_TYPE_COUNT];
};

struct mail_namespace_settings {
	pool_t pool;
	const char *name;
	const char *type;
	const char *separator;
	const char *prefix;
	const char *alias_for;

	bool inbox;
	bool hidden;
	const char *list;
	bool subscriptions;
	bool ignore_on_failure;
	bool disabled;
	unsigned int order;

	/* List of mailbox filter names */
	ARRAY_TYPE(const_string) mailboxes;
	/* mailbox_settings of each configured mailbox in the namespace. */
	ARRAY(const struct mailbox_settings *) parsed_mailboxes;
	bool parsed_have_special_use_mailboxes;
};

/* <settings checks> */
#define MAILBOX_SET_AUTO_NO "no"
#define MAILBOX_SET_AUTO_CREATE "create"
#define MAILBOX_SET_AUTO_SUBSCRIBE "subscribe"
/* </settings checks> */
struct mailbox_settings {
	pool_t pool;
	const char *name;
	const char *autocreate;
	ARRAY_TYPE(const_string) special_use;
	const char *comment;
	unsigned int autoexpunge;
	unsigned int autoexpunge_max_mails;
};

struct mail_user_settings {
	pool_t pool;
	const char *base_dir;
	const char *auth_socket_path;
	const char *mail_temp_dir;
	bool mail_debug;

	const char *mail_uid;
	const char *mail_gid;
	const char *mail_home;
	const char *mail_chroot;
	ARRAY_TYPE(const_string) mail_access_groups;
	const char *mail_privileged_group;
	ARRAY_TYPE(const_string) valid_chroot_dirs;

	unsigned int first_valid_uid, last_valid_uid;
	unsigned int first_valid_gid, last_valid_gid;

	ARRAY_TYPE(const_string) mail_plugins;
	const char *mail_plugin_dir;

	const char *mail_log_prefix;

	ARRAY_TYPE(const_string) namespaces;
	const char *hostname;
	const char *postmaster_address;

	/* May be NULL - use mail_storage_get_postmaster_address() instead of
	   directly accessing this. */
	const struct message_address *_parsed_postmaster_address;
	const struct smtp_address *_parsed_postmaster_address_smtp;
	const char *unexpanded_mail_log_prefix;
};

extern const struct setting_parser_info mail_user_setting_parser_info;
extern const struct setting_parser_info mail_namespace_setting_parser_info;
extern const struct setting_parser_info mail_driver_setting_parser_info;
extern const struct setting_parser_info mailbox_list_layout_setting_parser_info;
extern const struct setting_parser_info mail_storage_setting_parser_info;
extern const struct setting_parser_info mailbox_setting_parser_info;
extern const struct mail_namespace_settings mail_namespace_default_settings;
extern const struct mailbox_settings mailbox_default_settings;

struct ssl_iostream_settings;

bool mail_user_set_get_postmaster_address(const struct mail_user_settings *set,
					  const struct message_address **address_r,
					  const char **error_r);
bool mail_user_set_get_postmaster_smtp(const struct mail_user_settings *set,
				       const struct smtp_address **address_r,
				       const char **error_r);

/* Reset "2nd storage" settings to defaults using
   SETTINGS_OVERRIDE_TYPE_2ND_DEFAULT, so the actually intended settings
   can be overridden on top of them. For example with "doveadm import" command
   the -o parameters should apply only to the import destination, not to the
   import source. This allows clearing away such unwanted storage-specific
   settings. */
void mail_storage_2nd_settings_reset(struct settings_instance *instance,
				     const char *key_prefix);

/* Return mailbox_settings->name as vname (with namespace prefix). */
const char *
mailbox_settings_get_vname(pool_t pool, const struct mail_namespace *ns,
			   const struct mailbox_settings *set);

#endif
