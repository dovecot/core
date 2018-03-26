#ifndef SMTP_SUBMIT_SETTINGS_H
#define SMTP_SUBMIT_SETTINGS_H

struct smtp_submit_settings {
	const char *hostname;
	bool mail_debug;

	const char *submission_host;
	const char *sendmail_path;
	unsigned int submission_timeout;

	const char *submission_ssl;
};

extern const struct setting_parser_info smtp_submit_setting_parser_info;

#endif
