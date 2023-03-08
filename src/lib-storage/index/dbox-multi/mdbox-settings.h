#ifndef MDBOX_SETTINGS_H
#define MDBOX_SETTINGS_H

struct mdbox_settings {
	pool_t pool;
	bool mdbox_preallocate_space;
	uoff_t mdbox_rotate_size;
	unsigned int mdbox_rotate_interval;
};

extern const struct setting_parser_info mdbox_setting_parser_info;

#endif
