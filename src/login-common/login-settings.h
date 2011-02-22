#ifndef LOGIN_SETTINGS_H
#define LOGIN_SETTINGS_H

struct login_settings {
	const char *login_trusted_networks;
	const char *login_greeting;
	const char *login_log_format_elements, *login_log_format;
	const char *login_access_sockets;

	const char *ssl;
	const char *ssl_ca;
	const char *ssl_cert;
	const char *ssl_key;
	const char *ssl_key_password;
	const char *ssl_parameters_file;
	const char *ssl_cipher_list;
	const char *ssl_cert_username_field;
	bool ssl_verify_client_cert;
	bool auth_ssl_require_client_cert;
	bool auth_ssl_username_from_cert;
	bool verbose_ssl;

	bool disable_plaintext_auth;
	bool verbose_auth;
	bool auth_debug;
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
		    void ***other_settings_r);
void login_settings_deinit(void);

#endif
