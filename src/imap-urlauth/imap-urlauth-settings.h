#ifndef IMAP_URLAUTH_SETTINGS_H
#define IMAP_URLAUTH_SETTINGS_H

struct mail_user_settings;

struct imap_urlauth_settings {
	const char *base_dir;

	bool mail_debug;

	bool verbose_proctitle;

	/* imap_urlauth: */
	const char *imap_urlauth_logout_format;

	const char *imap_urlauth_submit_user;
	const char *imap_urlauth_stream_user;
};

extern const struct imap_urlauth_settings imap_urlauth_default_settings;

extern const struct setting_parser_info imap_urlauth_setting_parser_info;

#endif
