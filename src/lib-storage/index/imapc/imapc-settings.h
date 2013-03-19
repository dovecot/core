#ifndef IMAPC_SETTINGS_H
#define IMAPC_SETTINGS_H

/* <settings checks> */
enum imapc_features {
	IMAPC_FEATURE_RFC822_SIZE	= 0x01,
	IMAPC_FEATURE_GUID_FORCED	= 0x02
};
/* </settings checks> */

struct imapc_settings {
	const char *imapc_host;
	unsigned int imapc_port;

	const char *imapc_user;
	const char *imapc_master_user;
	const char *imapc_password;

	const char *imapc_ssl;
	bool imapc_ssl_verify;

	const char *imapc_features;
	const char *imapc_rawlog_dir;
	const char *imapc_list_prefix;
	unsigned int imapc_max_idle_time;

	enum imapc_features parsed_features;
};

const struct setting_parser_info *imapc_get_setting_parser_info(void);

#endif
