/* Copyright (c) Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "pop3c-settings.h"

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct pop3c_settings)

static const struct setting_define pop3c_setting_defines[] = {
	DEF(BOOL, pop3c_quick_received_date),

	SETTING_DEFINE_LIST_END
};

static const struct pop3c_settings pop3c_default_settings = {
	.pop3c_quick_received_date = FALSE,
};

const struct setting_parser_info pop3c_setting_parser_info = {
	.name = "pop3c",

	.defines = pop3c_setting_defines,
	.defaults = &pop3c_default_settings,

	.struct_size = sizeof(struct pop3c_settings),
	.pool_offset1 = 1 + offsetof(struct pop3c_settings, pool),
};
