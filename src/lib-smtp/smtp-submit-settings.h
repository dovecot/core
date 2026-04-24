#ifndef SMTP_SUBMIT_SETTINGS_H
#define SMTP_SUBMIT_SETTINGS_H

#define SMTP_SUBMIT_SETTINGS_FILTER "mail_submit"

struct smtp_submit_settings {
	pool_t pool;
	bool mail_debug;
	unsigned int timeout_msecs;

	/* deprecated */
	const char *submission_host;
	const char *sendmail_path;
};

extern const struct setting_parser_info smtp_submit_setting_parser_info;

#endif
