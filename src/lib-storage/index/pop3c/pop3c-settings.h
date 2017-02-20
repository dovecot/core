#ifndef POP3C_SETTINGS_H
#define POP3C_SETTINGS_H

#include "net.h"

/* <settings checks> */
enum pop3c_features {
        POP3C_FEATURE_NO_PIPELINING = 0x1,
};
/* </settings checks> */


struct pop3c_settings {
	const char *pop3c_host;
	in_port_t pop3c_port;

	const char *pop3c_user;
	const char *pop3c_master_user;
	const char *pop3c_password;

	const char *pop3c_ssl;
	bool pop3c_ssl_verify;

	const char *pop3c_rawlog_dir;
	bool pop3c_quick_received_date;

	const char *pop3c_features;
	enum pop3c_features parsed_features;
};

const struct setting_parser_info *pop3c_get_setting_parser_info(void);

#endif
