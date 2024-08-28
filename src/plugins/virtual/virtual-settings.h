#ifndef VIRTUAL_SETTINGS_H
#define VIRTUAL_SETTINGS_H

struct virtual_settings {
	pool_t pool;

	unsigned int virtual_max_open_mailboxes;
};

extern const struct setting_parser_info virtual_setting_parser_info;

#endif
