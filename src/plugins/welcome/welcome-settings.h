#ifndef WELCOME_SETTINGS_H
#define WELCOME_SETTINGS_H

#include "settings-parser.h"

struct welcome_settings {
	pool_t pool;
	bool welcome_wait;
};

extern const struct setting_parser_info welcome_setting_parser_info;

#endif
