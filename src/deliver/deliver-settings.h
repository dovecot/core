#ifndef DELIVER_SETTINGS_H
#define DELIVER_SETTINGS_H

struct mail_user_settings;

struct deliver_settings {
	const char *postmaster_address;
	const char *hostname;
	const char *sendmail_path;
	const char *rejection_subject;
	const char *rejection_reason;
	const char *deliver_log_format;
	bool quota_full_tempfail;

	ARRAY_DEFINE(plugin_envs, const char *);
};

extern struct setting_parser_info deliver_setting_parser_info;

#endif
