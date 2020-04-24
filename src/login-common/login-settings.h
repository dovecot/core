#ifndef LOGIN_SETTINGS_H
#define LOGIN_SETTINGS_H

struct master_service_ssl_settings;

struct login_settings {
	const char *login_trusted_networks;
	const char *login_source_ips;
	const char *login_greeting;
	const char *login_log_format_elements, *login_log_format;
	const char *login_access_sockets;
	const char *login_proxy_notify_path;
	const char *login_plugin_dir;
	const char *login_plugins;
	unsigned int login_proxy_timeout;
	unsigned int login_proxy_max_disconnect_delay;
	const char *director_username_hash;

	bool auth_ssl_require_client_cert;
	bool auth_ssl_username_from_cert;

	bool disable_plaintext_auth;
	bool auth_verbose;
	bool auth_debug;
	bool auth_debug_passwords;
	bool verbose_proctitle;

	unsigned int mail_max_userip_connections;

	/* generated: */
	char *const *log_format_elements_split;
};

extern const struct setting_parser_info **login_set_roots;
extern const struct setting_parser_info login_setting_parser_info;

struct login_settings *
login_settings_read(pool_t pool,
		    const struct ip_addr *local_ip,
		    const struct ip_addr *remote_ip,
		    const char *local_name,
		    const struct master_service_ssl_settings **ssl_set_r,
		    void ***other_settings_r) ATTR_NULL(2, 3, 4);
void login_settings_deinit(void);

#endif
