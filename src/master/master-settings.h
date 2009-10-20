#ifndef MASTER_SETTINGS_H
#define MASTER_SETTINGS_H

/* <settings checks> */
enum service_type {
	SERVICE_TYPE_UNKNOWN,
	SERVICE_TYPE_LOG,
	SERVICE_TYPE_ANVIL,
	SERVICE_TYPE_CONFIG,
	SERVICE_TYPE_LOGIN
};
/* </settings checks> */

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
	bool ssl;
};

struct service_settings {
	struct master_settings *master_set;

	const char *name;
	const char *protocol;
	const char *type;
	const char *executable;
	const char *user;
	const char *group;
	const char *privileged_group;
	const char *extra_groups;
	const char *chroot;

	bool drop_priv_before_exec;

	unsigned int process_min_avail;
	unsigned int process_limit;
	unsigned int client_limit;
	unsigned int service_count;
	unsigned int vsz_limit;

	ARRAY_TYPE(file_listener_settings) unix_listeners;
	ARRAY_TYPE(file_listener_settings) fifo_listeners;
	ARRAY_DEFINE(inet_listeners, struct inet_listener_settings *);

	enum service_type parsed_type;
};

struct master_settings {
	const char *base_dir;
	const char *libexec_dir;
	const char *protocols;
	const char *listen;
	const char *ssl;
	unsigned int default_process_limit;
	unsigned int default_client_limit;
	unsigned int default_vsz_limit;

	bool version_ignore;
	bool mail_debug;
	bool auth_debug;
	bool verbose_proctitle;

	unsigned int first_valid_uid, last_valid_uid;
	unsigned int first_valid_gid, last_valid_gid;

	ARRAY_DEFINE(services, struct service_settings *);
	char **protocols_split;
};

extern struct setting_parser_info master_setting_parser_info;

bool master_settings_do_fixes(const struct master_settings *set);

#endif
