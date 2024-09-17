#ifndef SERVICE_SETTINGS_H
#define SERVICE_SETTINGS_H

#include "net.h"

/* <settings checks> */
enum service_user_default {
	SERVICE_USER_DEFAULT_NONE = 0,
	SERVICE_USER_DEFAULT_INTERNAL,
	SERVICE_USER_DEFAULT_LOGIN
};

enum service_type {
	SERVICE_TYPE_UNKNOWN,
	SERVICE_TYPE_LOG,
	SERVICE_TYPE_ANVIL,
	SERVICE_TYPE_CONFIG,
	SERVICE_TYPE_LOGIN,
	SERVICE_TYPE_STARTUP,
	/* Worker processes are intentionally limited to their process_limit,
	   and they can regularly reach it. There shouldn't be unnecessary
	   warnings about temporarily reaching the limit. */
	SERVICE_TYPE_WORKER,
};

struct config_service {
	const struct service_settings *set;
	const struct setting_keyvalue *defaults;
};
ARRAY_DEFINE_TYPE(config_service, struct config_service);
/* </settings checks> */

struct file_listener_settings {
	pool_t pool;
	const char *path;
	const char *type;
	unsigned int mode;
	const char *user;
	const char *group;
};
ARRAY_DEFINE_TYPE(file_listener_settings, struct file_listener_settings *);

struct inet_listener_settings {
	pool_t pool;
	const char *name;
	const char *type;
	in_port_t port;
	/* copied from master_settings: */
	ARRAY_TYPE(const_string) listen;
	bool ssl;
	bool reuse_port;
	bool haproxy;
};
ARRAY_DEFINE_TYPE(inet_listener_settings, struct inet_listener_settings *);

struct service_settings {
	pool_t pool;
	const char *name;
	const char *protocol;
	const char *type;
	const char *executable;
	const char *user;
	const char *group;
	const char *privileged_group;
	ARRAY_TYPE(const_string) extra_groups;
	const char *chroot;

	bool drop_priv_before_exec;

	unsigned int process_min_avail;
	unsigned int process_limit;
	unsigned int client_limit;
	unsigned int restart_request_count;
	unsigned int idle_kill_interval;
	uoff_t vsz_limit;

	ARRAY_TYPE(const_string) unix_listeners;
	ARRAY_TYPE(const_string) fifo_listeners;
	ARRAY_TYPE(const_string) inet_listeners;

	/* internal to master: */
	enum service_type parsed_type;
	enum service_user_default user_default;
	bool login_dump_core:1;

	ARRAY_TYPE(file_listener_settings) parsed_unix_listeners;
	ARRAY_TYPE(file_listener_settings) parsed_fifo_listeners;
	ARRAY_TYPE(inet_listener_settings) parsed_inet_listeners;

	/* -- flags that can be set internally -- */

	/* process_limit must not be higher than 1 */
	bool process_limit_1:1;
};
ARRAY_DEFINE_TYPE(service_settings, struct service_settings *);

#endif
