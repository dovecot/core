#ifndef SUBMISSION_SETTINGS_H
#define SUBMISSION_SETTINGS_H

#include "smtp-server.h"

/* <settings checks> */
#define SUBMISSION_RELAY_SETTINGS_FILTER "submission_relay"

enum submission_client_workarounds {
	SUBMISSION_WORKAROUND_WHITESPACE_BEFORE_PATH	= BIT(0),
	SUBMISSION_WORKAROUND_MAILBOX_FOR_PATH		= BIT(1),
};
/* </settings checks> */

struct submission_settings {
	pool_t pool;
	bool verbose_proctitle;
	const char *rawlog_dir;

	const char *hostname;

	const char *login_greeting;
	ARRAY_TYPE(const_string) login_trusted_networks;

	const char *recipient_delimiter;

	/* submission: */
	uoff_t submission_max_mail_size;
	unsigned int submission_max_recipients;
	ARRAY_TYPE(const_string) submission_client_workarounds;
	const char *submission_logout_format;
	bool submission_add_received_header;
	bool mail_utf8_extensions;

	/* submission backend: */
	ARRAY_TYPE(const_string) submission_backend_capabilities;

	/* submission relay: */
	unsigned int submission_relay_max_idle_time;

	/* imap urlauth: */
	const char *imap_urlauth_host;
	in_port_t imap_urlauth_port;

	enum submission_client_workarounds parsed_workarounds;
};

extern const struct setting_parser_info submission_setting_parser_info;

#endif
