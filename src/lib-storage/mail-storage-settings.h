#ifndef MAIL_STORAGE_SETTINGS_H
#define MAIL_STORAGE_SETTINGS_H

#include "file-lock.h"
#include "fsync-mode.h"

#define MAIL_STORAGE_SET_DRIVER_NAME "MAIL"

struct mail_user;
struct mail_namespace;
struct mail_storage;
struct message_address;
struct smtp_address;

struct mail_storage_settings {
	const char *mail_location;
	const char *mail_attachment_fs;
	const char *mail_attachment_dir;
	const char *mail_attachment_hash;
	uoff_t mail_attachment_min_size;
	const char *mail_attribute_dict;
	unsigned int mail_prefetch_count;
	const char *mail_cache_fields;
	const char *mail_always_cache_fields;
	const char *mail_never_cache_fields;
	const char *mail_server_comment;
	const char *mail_server_admin;
	unsigned int mail_cache_min_mail_count;
	unsigned int mail_cache_unaccessed_field_drop;
	uoff_t mail_cache_record_max_size;
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
	bool mail_debug;
	bool mail_full_filesystem_access;
	bool maildir_stat_dirs;
	bool mail_shared_explicit_inbox;
	const char *lock_method;
	const char *pop3_uidl_format;

	const char *hostname;
	const char *recipient_delimiter;

	const char *ssl_client_ca_file;
	const char *ssl_client_ca_dir;
	const char *ssl_client_cert;
	const char *ssl_client_key;
	const char *ssl_cipher_list;
	const char *ssl_curve_list;
	const char *ssl_min_protocol;
	const char *ssl_crypto_device;
	bool ssl_client_require_valid_cert;
	bool verbose_ssl;
	const char *mail_attachment_detection_options;

	enum file_lock_method parsed_lock_method;
	enum fsync_mode parsed_fsync_mode;

	const char *const *parsed_mail_attachment_content_type_filter;
	bool parsed_mail_attachment_exclude_inlined;
	bool parsed_mail_attachment_detection_add_flags_on_save;
};

struct mail_namespace_settings {
	const char *name;
	const char *type;
	const char *separator;
	const char *prefix;
	const char *location;
	const char *alias_for;

	bool inbox;
	bool hidden;
	const char *list;
	bool subscriptions;
	bool ignore_on_failure;
	bool disabled;
	unsigned int order;

	ARRAY(struct mailbox_settings *) mailboxes;
	struct mail_user_settings *user_set;
};

/* <settings checks> */
#define MAILBOX_SET_AUTO_NO "no"
#define MAILBOX_SET_AUTO_CREATE "create"
#define MAILBOX_SET_AUTO_SUBSCRIBE "subscribe"
/* </settings checks> */
struct mailbox_settings {
	const char *name;
	const char *autocreate;
	const char *special_use;
	const char *driver;
	const char *comment;
	unsigned int autoexpunge;
	unsigned int autoexpunge_max_mails;
};

struct mail_user_settings {
	const char *base_dir;
	const char *auth_socket_path;
	const char *mail_temp_dir;

	const char *mail_uid;
	const char *mail_gid;
	const char *mail_home;
	const char *mail_chroot;
	const char *mail_access_groups;
	const char *mail_privileged_group;
	const char *valid_chroot_dirs;

	unsigned int first_valid_uid, last_valid_uid;
	unsigned int first_valid_gid, last_valid_gid;

	const char *mail_plugins;
	const char *mail_plugin_dir;

	const char *mail_log_prefix;

	const char *hostname;
	const char *postmaster_address;

	ARRAY(struct mail_namespace_settings *) namespaces;
	ARRAY(const char *) plugin_envs;

	/* May be NULL - use mail_storage_get_postmaster_address() instead of
	   directly accessing this. */
	const struct message_address *_parsed_postmaster_address;
	const struct smtp_address *_parsed_postmaster_address_smtp;
};

extern const struct setting_parser_info mail_user_setting_parser_info;
extern const struct setting_parser_info mail_namespace_setting_parser_info;
extern const struct setting_parser_info mail_storage_setting_parser_info;
extern const struct mail_namespace_settings mail_namespace_default_settings;
extern const struct mailbox_settings mailbox_default_settings;

struct ssl_iostream_settings;

const void *
mail_user_set_get_driver_settings(const struct setting_parser_info *info,
				  const struct mail_user_settings *set,
				  const char *driver);

const struct mail_storage_settings *
mail_user_set_get_storage_set(struct mail_user *user);
/* Get storage-specific settings, which may be namespace-specific. */
const void *mail_namespace_get_driver_settings(struct mail_namespace *ns,
					       struct mail_storage *storage);

const struct dynamic_settings_parser *
mail_storage_get_dynamic_parsers(pool_t pool);

bool mail_user_set_get_postmaster_address(const struct mail_user_settings *set,
					  const struct message_address **address_r,
					  const char **error_r);
bool mail_user_set_get_postmaster_smtp(const struct mail_user_settings *set,
				       const struct smtp_address **address_r,
				       const char **error_r);

void mail_storage_settings_init_ssl_client_settings(const struct mail_storage_settings *mail_set,
						    struct ssl_iostream_settings *ssl_set_r);

#endif
