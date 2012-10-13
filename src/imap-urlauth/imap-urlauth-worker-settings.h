#ifndef IMAP_URLAUTH_SETTINGS_H
#define IMAP_URLAUTH_SETTINGS_H

struct mail_user_settings;

struct imap_urlauth_worker_settings {
	bool verbose_proctitle;

	/* imap_urlauth: */
	const char *imap_urlauth_host;
	unsigned int imap_urlauth_port;
};

extern const struct imap_urlauth_worker_settings imap_urlauth_worker_default_settings;

extern const struct setting_parser_info imap_urlauth_worker_setting_parser_info;

#endif
