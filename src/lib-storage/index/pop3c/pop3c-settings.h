#ifndef POP3C_SETTINGS_H
#define POP3C_SETTINGS_H

struct pop3c_settings {
	const char *pop3c_host;
	unsigned int pop3c_port;

	const char *pop3c_user;
	const char *pop3c_master_user;
	const char *pop3c_password;

	const char *pop3c_ssl;
	bool pop3c_ssl_verify;

	const char *pop3c_rawlog_dir;
};

const struct setting_parser_info *pop3c_get_setting_parser_info(void);

#endif
