#ifndef LDA_SETTINGS_H
#define LDA_SETTINGS_H

struct mail_user_settings;

struct lda_settings {
	const char *postmaster_address;
	const char *hostname;
	const char *submission_host;
	const char *sendmail_path;
	const char *rejection_subject;
	const char *rejection_reason;
	const char *deliver_log_format;
	const char *recipient_delimiter;
	const char *lda_original_recipient_header;

	bool quota_full_tempfail;
	bool lda_mailbox_autocreate;
	bool lda_mailbox_autosubscribe;
};

extern const struct setting_parser_info lda_setting_parser_info;

#endif
