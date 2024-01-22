#ifndef LANG_SETTINGS_H
#define LANG_SETTINGS_H

#include "array.h"

ARRAY_DEFINE_TYPE(lang_settings, struct lang_settings *);
struct lang_settings {
	pool_t pool;
};

struct langs_settings {
	pool_t pool;
};

extern const struct setting_parser_info langs_setting_parser_info;

#endif
