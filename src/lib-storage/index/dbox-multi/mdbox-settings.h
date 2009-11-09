#ifndef MDBOX_SETTINGS_H
#define MDBOX_SETTINGS_H

struct mdbox_settings {
	uoff_t mdbox_rotate_size;
	uoff_t mdbox_rotate_min_size;
	unsigned int mdbox_rotate_days;
	unsigned int mdbox_max_open_files;
	unsigned int mdbox_purge_min_percentage;
};

const struct setting_parser_info *mdbox_get_setting_parser_info(void);

#endif
