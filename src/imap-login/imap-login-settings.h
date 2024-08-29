#ifndef IMAP_LOGIN_SETTINGS_H
#define IMAP_LOGIN_SETTINGS_H

struct imap_login_settings {
	pool_t pool;
	ARRAY_TYPE(const_string) imap_capability;
	ARRAY_TYPE(const_string) imap_id_send;
	bool imap_literal_minus;
	bool imap_id_retain;
};

extern const struct setting_parser_info imap_login_setting_parser_info;

#endif
