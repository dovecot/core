#ifndef SUBMISSION_LOGIN_SETTINGS_H
#define SUBMISSION_LOGIN_SETTINGS_H

/* <settings checks> */
enum submission_login_client_workarounds {
	SUBMISSION_LOGIN_WORKAROUND_IMPLICIT_AUTH_EXTERNAL	= BIT(0),
	SUBMISSION_LOGIN_WORKAROUND_EXOTIC_BACKEND		= BIT(1),
};
/* </settings checks> */

struct submission_login_settings {
	pool_t pool;
	const char *hostname;
	bool mail_utf8_extensions;

	/* submission: */
	uoff_t submission_max_mail_size;
	ARRAY_TYPE(const_string) submission_client_workarounds;
	ARRAY_TYPE(const_string) submission_backend_capabilities;

	enum submission_login_client_workarounds parsed_workarounds;
};

extern const struct setting_parser_info submission_login_setting_parser_info;

#endif
