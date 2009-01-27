#ifndef POP3_SETTINGS_H
#define POP3_SETTINGS_H

struct mail_user_settings;

struct pop3_settings {
	bool mail_debug;
	bool shutdown_clients;
	bool verbose_proctitle;

	const char *mail_plugins;
	const char *mail_plugin_dir;
	const char *mail_log_prefix;

	/* pop3: */
	bool pop3_no_flag_updates;
	bool pop3_enable_last;
	bool pop3_reuse_xuidl;
	bool pop3_lock_session;
	const char *pop3_client_workarounds;
	const char *pop3_logout_format;
	const char *pop3_uidl_format;
};

void pop3_settings_read(const struct pop3_settings **set_r,
			const struct mail_user_settings **user_set_r);

#endif
