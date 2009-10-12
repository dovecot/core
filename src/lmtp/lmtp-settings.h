#ifndef LMTP_SETTINGS_H
#define LMTP_SETTINGS_H

struct lmtp_settings {
	bool lmtp_proxy;
};

extern struct setting_parser_info lmtp_setting_parser_info;

#endif
