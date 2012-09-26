#ifndef LMTP_SETTINGS_H
#define LMTP_SETTINGS_H

struct lda_settings;
struct lmtp_settings;

struct lmtp_settings {
	bool lmtp_proxy;
	bool lmtp_save_to_detail_mailbox;
	bool lmtp_rcpt_check_quota;
	const char *lmtp_address_translate;
	const char *login_greeting;
	const char *login_trusted_networks;
};

extern const struct setting_parser_info lmtp_setting_parser_info;

void lmtp_settings_dup(const struct setting_parser_context *set_parser,
		       pool_t pool,
		       struct lmtp_settings **lmtp_set_r,
		       struct lda_settings **lda_set_r);

#endif
