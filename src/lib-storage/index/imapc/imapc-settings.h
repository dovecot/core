#ifndef IMAPC_SETTINGS_H
#define IMAPC_SETTINGS_H

struct imapc_settings {
	const char *imapc_host;
	unsigned int imapc_port;

	const char *imapc_user;
	const char *imapc_master_user;
	const char *imapc_password;

	const char *imapc_ssl;
	const char *imapc_ssl_ca_dir;
	bool imapc_ssl_verify;

	const char *imapc_rawlog_dir;
	const char *ssl_crypto_device;
};

const struct setting_parser_info *imapc_get_setting_parser_info(void);

#endif
