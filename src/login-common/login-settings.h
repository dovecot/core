#ifndef LOGIN_SETTINGS_H
#define LOGIN_SETTINGS_H

struct login_settings {
	pool_t pool;
	ARRAY_TYPE(const_string) login_trusted_networks;
	ARRAY_TYPE(const_string) login_source_ips;
	const char *login_greeting;
	const char *login_log_format_elements, *login_log_format;
	const char *login_access_sockets;
	const char *login_proxy_notify_path;
	const char *login_plugin_dir;
	ARRAY_TYPE(const_string) login_plugins;
	unsigned int login_proxy_timeout;
	unsigned int login_proxy_max_reconnects;
	unsigned int login_proxy_max_disconnect_delay;
	const char *login_proxy_rawlog_dir;
	const char *login_socket_path;
	const char *ssl; /* for settings check */

	bool auth_ssl_require_client_cert;
	bool auth_ssl_username_from_cert;

	bool auth_allow_cleartext;
	bool auth_verbose;
	bool auth_debug;
	bool auth_debug_passwords;
	bool verbose_proctitle;

	unsigned int mail_max_userip_connections;

	/* generated: */
	char *const *log_format_elements_split;
};

extern const struct setting_parser_info login_setting_parser_info;

#endif
