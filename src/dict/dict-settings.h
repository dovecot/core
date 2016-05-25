#ifndef DICT_SETTINGS_H
#define DICT_SETTINGS_H

struct dict_server_settings {
	const char *base_dir;
	bool verbose_proctitle;

	const char *dict_db_config;
	ARRAY(const char *) dicts;
};

extern const struct setting_parser_info dict_setting_parser_info;
extern const struct dict_server_settings *dict_settings;

#endif
