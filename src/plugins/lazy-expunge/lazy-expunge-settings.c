/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "lazy-expunge-plugin.h"

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct lazy_expunge_settings)

static struct setting_define lazy_expunge_setting_defines[] = {
	DEF(BOOL, lazy_expunge_only_last_instance),
	DEF(STR, lazy_expunge_mailbox),

	SETTING_DEFINE_LIST_END
};

static struct lazy_expunge_settings lazy_expunge_default_settings = {
	.lazy_expunge_only_last_instance = FALSE,
	.lazy_expunge_mailbox = "",
};

const struct setting_parser_info lazy_expunge_setting_parser_info = {
	.name = "lazy_expunge",
	.plugin_dependency = "lib02_lazy_expunge_plugin",

	.defines = lazy_expunge_setting_defines,
	.defaults = &lazy_expunge_default_settings,

	.struct_size = sizeof(struct lazy_expunge_settings),
	.pool_offset1 = 1 + offsetof(struct lazy_expunge_settings, pool),
};
