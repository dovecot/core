#ifndef DBOX_SETTINGS_H
#define DBOX_SETTINGS_H

struct dbox_settings {
	unsigned int dbox_rotate_size;
	unsigned int dbox_rotate_min_size;
	unsigned int dbox_rotate_days;
	unsigned int dbox_max_open_files;
};

const struct setting_parser_info *dbox_get_setting_parser_info(void);

#endif
