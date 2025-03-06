#ifndef LMTP_SETTINGS_H
#define LMTP_SETTINGS_H

struct mail_user_settings;
struct lda_settings;
struct lmtp_settings;

/* <settings checks> */
enum lmtp_hdr_delivery_address {
	LMTP_HDR_DELIVERY_ADDRESS_NONE,
	LMTP_HDR_DELIVERY_ADDRESS_FINAL,
	LMTP_HDR_DELIVERY_ADDRESS_ORIGINAL
};

enum lmtp_client_workarounds {
	LMTP_WORKAROUND_WHITESPACE_BEFORE_PATH	= BIT(0),
	LMTP_WORKAROUND_MAILBOX_FOR_PATH	= BIT(1),
};
/* </settings checks> */

struct lmtp_pre_mail_settings {
	pool_t pool;
	unsigned int mail_max_lock_timeout;
};

struct lmtp_settings {
	pool_t pool;
	bool lmtp_proxy;
	bool lmtp_save_to_detail_mailbox;
	bool lmtp_rcpt_check_quota;
	bool lmtp_add_received_header;
	bool lmtp_verbose_replies;
	bool mail_utf8_extensions;
	unsigned int lmtp_user_concurrency_limit;
	const char *lmtp_hdr_delivery_address;
	const char *lmtp_rawlog_dir;
	const char *lmtp_proxy_rawlog_dir;

	ARRAY_TYPE(const_string) lmtp_client_workarounds;

	const char *login_greeting;
	ARRAY_TYPE(const_string) login_trusted_networks;

	ARRAY_TYPE(const_string) mail_plugins;
	const char *mail_plugin_dir;

	enum lmtp_hdr_delivery_address parsed_lmtp_hdr_delivery_address;

	enum lmtp_client_workarounds parsed_workarounds;
};

extern const struct setting_parser_info lmtp_pre_mail_setting_parser_info;
extern const struct setting_parser_info lmtp_setting_parser_info;

#endif
