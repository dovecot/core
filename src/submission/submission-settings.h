#ifndef SUBMISSION_SETTINGS_H
#define SUBMISSION_SETTINGS_H

#include "smtp-server.h"

/* <settings checks> */
enum submission_client_workarounds {
	WORKAROUND_WHITESPACE_BEFORE_PATH	= BIT(0),
	WORKAROUND_MAILBOX_FOR_PATH		= BIT(1),
};
/* </settings checks> */

struct submission_settings {
	bool verbose_proctitle;
	const char *rawlog_dir;

	const char *hostname;

	const char *login_greeting;
	const char *login_trusted_networks;

	/* submission: */
	size_t submission_max_mail_size;
	unsigned int submission_max_recipients;
	const char *submission_client_workarounds;
	const char *submission_logout_format;

	/* submission backend: */
	const char *submission_backend_capabilities;

	/* submission relay: */
	const char *submission_relay_host;
	in_port_t submission_relay_port;
	bool submission_relay_trusted;

	const char *submission_relay_user;
	const char *submission_relay_master_user;
	const char *submission_relay_password;

	const char *submission_relay_ssl;
	bool submission_relay_ssl_verify;

	const char *submission_relay_rawlog_dir;
	unsigned int submission_relay_max_idle_time;

	unsigned int submission_relay_connect_timeout;
	unsigned int submission_relay_command_timeout;

	/* imap urlauth: */
	const char *imap_urlauth_host;
	in_port_t imap_urlauth_port;

	enum submission_client_workarounds parsed_workarounds;
};

extern const struct setting_parser_info submission_setting_parser_info;

#endif
