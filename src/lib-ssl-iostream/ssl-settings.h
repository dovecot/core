#ifndef SSL_SETTINGS_H
#define SSL_SETTINGS_H

struct ssl_iostream_settings;

struct ssl_settings {
	pool_t pool;

	const char *ssl_client_ca;
	const char *ssl_client_ca_file;
	const char *ssl_client_ca_dir;
	const char *ssl_client_cert_file;
	const char *ssl_client_key_file;

	const char *ssl_cipher_list;
	const char *ssl_cipher_suites;
	const char *ssl_curve_list;
	const char *ssl_min_protocol;
	const char *ssl_crypto_device;
	const char *ssl_options;

	bool ssl_client_require_valid_cert;

	/* These are derived from ssl_options, not set directly */
	struct {
		bool compression;
		bool tickets;
	} parsed_opts;
};

struct ssl_server_settings {
	pool_t pool;

	const char *ssl;
	const char *ssl_ca;
	const char *ssl_cert_file;
	const char *ssl_alt_cert_file;
	const char *ssl_key_file;
	const char *ssl_alt_key_file;
	const char *ssl_key_password;
	const char *ssl_dh_file;
	const char *ssl_cert_username_field;

	bool ssl_require_crl;
	bool ssl_prefer_server_ciphers;
	bool ssl_request_client_cert;
};

extern const struct setting_parser_info ssl_setting_parser_info;
extern const struct setting_parser_info ssl_server_setting_parser_info;

void ssl_client_settings_to_iostream_set(
	const struct ssl_settings *ssl_set,
	const struct ssl_iostream_settings **set_r);
void ssl_server_settings_to_iostream_set(
	const struct ssl_settings *ssl_set,
	const struct ssl_server_settings *ssl_server_set,
	const struct ssl_iostream_settings **set_r);

#endif
