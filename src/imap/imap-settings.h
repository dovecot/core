#ifndef IMAP_SETTINGS_H
#define IMAP_SETTINGS_H

struct mail_user_settings;

/* <settings checks> */
enum imap_client_workarounds {
	WORKAROUND_DELAY_NEWMAIL		= 0x01,
	WORKAROUND_NETSCAPE_EOH			= 0x04,
	WORKAROUND_TB_EXTRA_MAILBOX_SEP		= 0x08
};
/* </settings checks> */

struct imap_settings {
	bool mail_debug;
	bool shutdown_clients;

	/* imap: */
	unsigned int imap_max_line_length;
	unsigned int imap_idle_notify_interval;
	const char *imap_capability;
	const char *imap_client_workarounds;
	const char *imap_logout_format;
	const char *imap_id_send;
	const char *imap_id_log;

	enum imap_client_workarounds parsed_workarounds;
};

extern struct setting_parser_info imap_setting_parser_info;

#endif
