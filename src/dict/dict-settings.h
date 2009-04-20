#ifndef DICT_SETTINGS_H
#define DICT_SETTINGS_H

struct dict_settings {
	const char *dict_db_config;
	ARRAY_DEFINE(dicts, const char *);
};

extern struct dict_settings *dict_settings;

struct dict_settings *dict_settings_read(void);

#endif
