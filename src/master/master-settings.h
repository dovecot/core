#ifndef MASTER_SETTINGS_H
#define MASTER_SETTINGS_H

struct file_listener_settings {
	const char *path;
	unsigned int mode;
	const char *user;
	const char *group;
};
ARRAY_DEFINE_TYPE(file_listener_settings, struct file_listener_settings *);

struct inet_listener_settings {
	const char *address;
	unsigned int port;
};

struct service_settings {
	struct master_settings *master_set;

	const char *type;
	const char *executable;
	const char *user;
	const char *group;
	const char *privileged_group;
	const char *extra_groups;
	const char *chroot;
	const char *auth_dest_service;

	bool drop_priv_before_exec;

	unsigned int process_limit;
	unsigned int client_limit;
	unsigned int vsz_limit;

	ARRAY_TYPE(file_listener_settings) unix_listeners;
	ARRAY_TYPE(file_listener_settings) fifo_listeners;
	ARRAY_DEFINE(inet_listeners, struct inet_listener_settings *);
};

struct master_settings {
	const char *base_dir;
	const char *libexec_dir;
	unsigned int default_process_limit;
	unsigned int default_client_limit;

	bool version_ignore;

	unsigned int first_valid_uid, last_valid_uid;
	unsigned int first_valid_gid, last_valid_gid;

	ARRAY_DEFINE(services, struct service_settings *);
};

extern struct setting_parser_info master_setting_parser_info;

struct master_settings *
master_settings_read(pool_t pool, const char *config_binary,
		     const char *config_path);
bool master_settings_do_fixes(const struct master_settings *set);

#endif
