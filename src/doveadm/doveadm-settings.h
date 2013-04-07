#ifndef DOVEADM_SETTINGS_H
#define DOVEADM_SETTINGS_H

struct doveadm_settings {
	const char *base_dir;
	const char *libexec_dir;
	const char *mail_plugins;
	const char *mail_plugin_dir;
	const char *doveadm_socket_path;
	unsigned int doveadm_worker_count;
	unsigned int doveadm_port;
	const char *doveadm_password;
	const char *doveadm_allowed_commands;
	const char *dsync_alt_char;
	const char *dsync_remote_cmd;
	const char *ssl_client_ca_dir;
	const char *ssl_client_ca_file;

	ARRAY(const char *) plugin_envs;
};

extern const struct setting_parser_info doveadm_setting_parser_info;
extern struct doveadm_settings *doveadm_settings;
extern const struct master_service_settings *service_set;

#endif
