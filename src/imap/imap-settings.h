#ifndef IMAP_SETTINGS_H
#define IMAP_SETTINGS_H

struct mail_user_settings;

struct imap_settings {
	bool mail_debug;
	bool shutdown_clients;
	bool verbose_proctitle;

	/* imap: */
	unsigned int imap_max_line_length;
	const char *imap_capability;
	const char *imap_client_workarounds;
	const char *imap_logout_format;
	const char *imap_id_send;
	const char *imap_id_log;
};

void imap_settings_read(const struct imap_settings **set_r,
			const struct mail_user_settings **user_set_r);

#endif
