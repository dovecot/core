#ifndef DOVEADM_SETTINGS_H
#define DOVEADM_SETTINGS_H

struct doveadm_settings {
	const char *base_dir;
	const char *mail_plugins;
	const char *mail_plugin_dir;
	const char *doveadm_socket_path;
	unsigned int doveadm_worker_count;
	unsigned int doveadm_proxy_port;
	const char *doveadm_password;
	const char *doveadm_allowed_commands;

	ARRAY_DEFINE(plugin_envs, const char *);
};

extern const struct setting_parser_info doveadm_setting_parser_info;
extern struct doveadm_settings *doveadm_settings;

#endif
