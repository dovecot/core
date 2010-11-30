#ifndef LMTP_SETTINGS_H
#define LMTP_SETTINGS_H

struct lda_settings;
struct lmtp_settings;

struct lmtp_settings {
	bool lmtp_proxy;
	bool lmtp_save_to_detail_mailbox;
};

extern const struct setting_parser_info lmtp_setting_parser_info;

void lmtp_settings_dup(const struct setting_parser_context *set_parser,
		       pool_t pool,
		       const struct lmtp_settings **lmtp_set_r,
		       const struct lda_settings **lda_set_r);

#endif
