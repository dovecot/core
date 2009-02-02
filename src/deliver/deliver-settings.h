#ifndef DELIVER_SETTINGS_H
#define DELIVER_SETTINGS_H

struct mail_user_settings;

struct deliver_settings {
	const char *base_dir;
	const char *log_path;
	const char *info_log_path;
	const char *log_timestamp;
	const char *syslog_facility;
	bool version_ignore;
	unsigned int umask;

	const char *mail_plugins;
	const char *mail_plugin_dir;

	/* deliver: */
	const char *postmaster_address;
	const char *hostname;
	const char *sendmail_path;
	const char *rejection_subject;
	const char *rejection_reason;
	const char *auth_socket_path;
	const char *deliver_log_format;
	bool quota_full_tempfail;

	ARRAY_DEFINE(plugin_envs, const char *);
};

struct setting_parser_context *
deliver_settings_read(const char *path,
		      struct deliver_settings **set_r,
		      struct mail_user_settings **user_set_r);
void deliver_settings_add(struct setting_parser_context *parser,
			  const ARRAY_TYPE(const_string) *extra_fields);

#endif
