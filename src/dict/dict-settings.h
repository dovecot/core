#ifndef DICT_SETTINGS_H
#define DICT_SETTINGS_H

struct dict_server_settings {
	pool_t pool;
	const char *base_dir;
	bool verbose_proctitle;
};

extern const struct setting_parser_info dict_server_setting_parser_info;
extern const struct dict_server_settings *server_settings;
extern const struct dict_settings *dict_settings;

extern struct event_category dict_server_event_category;

#endif
