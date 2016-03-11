#ifndef DOVEADM_SETTINGS_H
#define DOVEADM_SETTINGS_H

#include "net.h"

struct doveadm_settings {
	const char *base_dir;
	const char *libexec_dir;
	const char *mail_plugins;
	const char *mail_plugin_dir;
	bool auth_debug;
	const char *auth_socket_path;
	const char *doveadm_socket_path;
	unsigned int doveadm_worker_count;
	in_port_t doveadm_port;
	const char *doveadm_username;
	const char *doveadm_password;
	const char *doveadm_allowed_commands;
	const char *dsync_alt_char;
	const char *dsync_remote_cmd;
	const char *ssl_client_ca_dir;
	const char *ssl_client_ca_file;
	const char *director_username_hash;
	const char *doveadm_api_key;

	ARRAY(const char *) plugin_envs;
};

extern const struct setting_parser_info doveadm_setting_parser_info;
extern struct doveadm_settings *doveadm_settings;
extern const struct master_service_settings *service_set;

#endif
