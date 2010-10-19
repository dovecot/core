#ifndef MAIL_STORAGE_SETTINGS_H
#define MAIL_STORAGE_SETTINGS_H

#include "file-lock.h"
#include "fsync-mode.h"

#define MAIL_STORAGE_SET_DRIVER_NAME "MAIL"

struct mail_user;
struct mail_storage;

struct mail_storage_settings {
	const char *mail_location;
	const char *mail_attachment_fs;
	const char *mail_attachment_dir;
	const char *mail_attachment_hash;
	uoff_t mail_attachment_min_size;
	const char *mail_cache_fields;
	const char *mail_never_cache_fields;
	unsigned int mail_cache_min_mail_count;
	unsigned int mailbox_idle_check_interval;
	unsigned int mail_max_keyword_length;
	unsigned int mail_max_lock_timeout;
	bool mail_save_crlf;
	const char *mail_fsync;
	bool mmap_disable;
	bool dotlock_use_excl;
	bool mail_nfs_storage;
	bool mail_nfs_index;
	bool mailbox_list_index_disable;
	bool mail_debug;
	bool mail_full_filesystem_access;
	bool maildir_stat_dirs;
	const char *lock_method;
	const char *pop3_uidl_format;

	enum file_lock_method parsed_lock_method;
	enum fsync_mode parsed_fsync_mode;
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

	struct mail_user_settings *user_set;
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

	ARRAY_DEFINE(namespaces, struct mail_namespace_settings *);
	ARRAY_DEFINE(plugin_envs, const char *);
};

extern const struct setting_parser_info mail_user_setting_parser_info;
extern const struct setting_parser_info mail_namespace_setting_parser_info;
extern const struct setting_parser_info mail_storage_setting_parser_info;
extern const struct mail_namespace_settings mail_namespace_default_settings;

const void *
mail_user_set_get_driver_settings(const struct setting_parser_info *info,
				  const struct mail_user_settings *set,
				  const char *driver);
const struct mail_storage_settings *
mail_user_set_get_storage_set(struct mail_user *user);
const void *mail_storage_get_driver_settings(struct mail_storage *storage);

enum mail_index_open_flags
mail_storage_settings_to_index_flags(const struct mail_storage_settings *set);

const struct dynamic_settings_parser *
mail_storage_get_dynamic_parsers(pool_t pool);

#endif
