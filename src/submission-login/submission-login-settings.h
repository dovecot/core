#ifndef SUBMISSION_LOGIN_SETTINGS_H
#define SUBMISSION_LOGIN_SETTINGS_H

struct submission_login_settings {
	const char *hostname;

	/* submission: */
	uoff_t submission_max_mail_size;
	const char *submission_backend_capabilities;
};

extern const struct setting_parser_info *submission_login_setting_roots[];

#endif
