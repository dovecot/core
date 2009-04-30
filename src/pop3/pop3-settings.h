#ifndef POP3_SETTINGS_H
#define POP3_SETTINGS_H

struct mail_user_settings;

struct pop3_settings {
	bool mail_debug;
	bool shutdown_clients;
	bool verbose_proctitle;

	/* pop3: */
	bool pop3_no_flag_updates;
	bool pop3_enable_last;
	bool pop3_reuse_xuidl;
	bool pop3_lock_session;
	const char *pop3_client_workarounds;
	const char *pop3_logout_format;
};

extern struct setting_parser_info pop3_setting_parser_info;

#endif
