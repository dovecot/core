#ifndef DICT_SETTINGS_H
#define DICT_SETTINGS_H

struct dict_server_settings {
	pool_t pool;
	const char *base_dir;
	bool verbose_proctitle;
	ARRAY(const char *) dicts;
};

extern const struct setting_parser_info dict_server_setting_parser_info;
extern const struct dict_server_settings *dict_settings;

#endif
