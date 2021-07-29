#ifndef MASTER_SERVICE_SSL_SETTINGS_H
#define MASTER_SERVICE_SSL_SETTINGS_H

struct master_service;
struct setting_parser_context;
struct ssl_iostream_settings;

struct master_service_ssl_settings {
	const char *ssl;
	const char *ssl_ca;
	const char *ssl_client_ca_file;
	const char *ssl_client_ca_dir;
	const char *ssl_client_cert;
	const char *ssl_client_key;
	const char *ssl_cipher_list;
	const char *ssl_cipher_suites;
	const char *ssl_curve_list;
	const char *ssl_min_protocol;
	const char *ssl_cert_username_field;
	const char *ssl_crypto_device;
	const char *ssl_options;

	bool ssl_verify_client_cert;
	bool ssl_client_require_valid_cert;
	bool ssl_require_crl;
	bool verbose_ssl;
	bool ssl_prefer_server_ciphers;

	/* These are derived from ssl_options, not set directly */
	struct {
		bool compression;
		bool tickets;
	} parsed_opts;
};

struct master_service_ssl_server_settings {
	const char *ssl_cert;
	const char *ssl_alt_cert;
	const char *ssl_key;
	const char *ssl_alt_key;
	const char *ssl_key_password;
	const char *ssl_dh;
};

extern const struct setting_parser_info master_service_ssl_setting_parser_info;
extern const struct setting_parser_info master_service_ssl_server_setting_parser_info;

const struct master_service_ssl_settings *
master_service_ssl_settings_get(struct master_service *service);
const struct master_service_ssl_settings *
master_service_ssl_settings_get_from_parser(struct setting_parser_context *set_parser);

const struct master_service_ssl_server_settings *
master_service_ssl_server_settings_get(struct master_service *service);

/* Provides master service ssl settings to iostream settings */
void master_service_ssl_client_settings_to_iostream_set(
	const struct master_service_ssl_settings *ssl_set, pool_t pool,
	struct ssl_iostream_settings *set_r);
void master_service_ssl_server_settings_to_iostream_set(
	const struct master_service_ssl_settings *ssl_set,
	const struct master_service_ssl_server_settings *ssl_server_set,
	pool_t pool, struct ssl_iostream_settings *set_r);

#endif
