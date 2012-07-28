#ifndef MASTER_SERVICE_SSL_SETTINGS_H
#define MASTER_SERVICE_SSL_SETTINGS_H

struct master_service;

struct master_service_ssl_settings {
	const char *ssl;
	const char *ssl_ca;
	const char *ssl_cert;
	const char *ssl_key;
	const char *ssl_key_password;
	const char *ssl_cipher_list;
	const char *ssl_protocols;
	const char *ssl_cert_username_field;
	const char *ssl_crypto_device;
	bool ssl_verify_client_cert;
	bool ssl_require_crl;
	bool verbose_ssl;
};

extern const struct setting_parser_info master_service_ssl_setting_parser_info;

const struct master_service_ssl_settings *
master_service_ssl_settings_get(struct master_service *service);

#endif
