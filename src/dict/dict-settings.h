#ifndef DICT_SETTINGS_H
#define DICT_SETTINGS_H

struct dict_settings {
	const char *base_dir;
	const char *dict_db_config;
	ARRAY_DEFINE(dicts, const char *);
};

extern struct setting_parser_info dict_setting_parser_info;
extern struct dict_settings *dict_settings;

#endif
