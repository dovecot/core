#ifndef LMTP_SETTINGS_H
#define LMTP_SETTINGS_H

struct lda_settings;
struct lmtp_settings;

/* <settings checks> */
enum lmtp_hdr_delivery_address {
	LMTP_HDR_DELIVERY_ADDRESS_NONE,
	LMTP_HDR_DELIVERY_ADDRESS_FINAL,
	LMTP_HDR_DELIVERY_ADDRESS_ORIGINAL
};
/* </settings checks> */

struct lmtp_settings {
	bool lmtp_proxy;
	bool lmtp_save_to_detail_mailbox;
	bool lmtp_rcpt_check_quota;
	bool lmtp_add_received_header;
	unsigned int lmtp_user_concurrency_limit;
	const char *lmtp_hdr_delivery_address;
	const char *lmtp_rawlog_dir;
	const char *lmtp_proxy_rawlog_dir;

	const char *login_greeting;
	const char *login_trusted_networks;

	const char *mail_plugins;
	const char *mail_plugin_dir;

	enum lmtp_hdr_delivery_address parsed_lmtp_hdr_delivery_address;
};

extern const struct setting_parser_info lmtp_setting_parser_info;

void lmtp_settings_dup(const struct setting_parser_context *set_parser,
		       pool_t pool,
		       struct lmtp_settings **lmtp_set_r,
		       struct lda_settings **lda_set_r);

#endif
