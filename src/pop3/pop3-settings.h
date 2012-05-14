#ifndef POP3_SETTINGS_H
#define POP3_SETTINGS_H

struct mail_user_settings;

/* <settings checks> */
enum pop3_client_workarounds {
	WORKAROUND_OUTLOOK_NO_NULS		= 0x01,
	WORKAROUND_OE_NS_EOH			= 0x02
};
/* </settings checks> */

struct pop3_settings {
	bool verbose_proctitle;

	/* pop3: */
	bool pop3_no_flag_updates;
	bool pop3_enable_last;
	bool pop3_reuse_xuidl;
	bool pop3_save_uidl;
	bool pop3_lock_session;
	bool pop3_fast_size_lookups;
	const char *pop3_client_workarounds;
	const char *pop3_logout_format;
	const char *pop3_uidl_duplicates;

	enum pop3_client_workarounds parsed_workarounds;
};

extern const struct setting_parser_info pop3_setting_parser_info;

#endif
