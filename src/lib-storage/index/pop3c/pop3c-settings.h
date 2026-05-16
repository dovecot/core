#ifndef POP3C_SETTINGS_H
#define POP3C_SETTINGS_H

struct pop3c_settings {
	pool_t pool;

	bool pop3c_quick_received_date;
};

extern const struct setting_parser_info pop3c_setting_parser_info;

#endif
