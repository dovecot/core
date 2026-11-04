#ifndef IMAP_HIBERNATE_SETTINGS_H
#define IMAP_HIBERNATE_SETTINGS_H

struct imap_hibernate_settings {
	pool_t pool;
	bool auth_debug_passwords;
};

extern const struct setting_parser_info imap_hibernate_setting_parser_info;

#endif
