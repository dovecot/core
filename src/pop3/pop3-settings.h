#ifndef POP3_SETTINGS_H
#define POP3_SETTINGS_H

struct mail_user_settings;

/* <settings checks> */
enum pop3_client_workarounds {
	WORKAROUND_OUTLOOK_NO_NULS		= 0x01,
	WORKAROUND_OE_NS_EOH			= 0x02
};
enum pop3_delete_type {
	POP3_DELETE_TYPE_EXPUNGE = 0,
	POP3_DELETE_TYPE_FLAG,
};
/* </settings checks> */

struct pop3_settings {
	bool verbose_proctitle;
	const char *rawlog_dir;

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
	const char *pop3_deleted_flag;
	const char *pop3_delete_type;

	enum pop3_client_workarounds parsed_workarounds;
	enum pop3_delete_type parsed_delete_type;
};

extern const struct setting_parser_info pop3_setting_parser_info;

#endif
