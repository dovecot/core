/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "settings.h"
#include "settings-parser.h"

#include "quota-clone-settings.h"

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("quota_clone_"#name, name, struct quota_clone_settings)

static const struct setting_define quota_clone_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "quota_clone", .required_setting = "dict" },
	DEF(BOOL, unset),
	SETTING_DEFINE_LIST_END
};

static const struct quota_clone_settings quota_clone_default_settings = {
	.unset = FALSE,
};

const struct setting_parser_info quota_clone_setting_parser_info = {
	.name = "quota_clone",
	.plugin_dependency = "lib20_quota_clone_plugin",
	.defines = quota_clone_setting_defines,
	.defaults = &quota_clone_default_settings,
	.struct_size = sizeof(struct quota_clone_settings),
	.pool_offset1 = 1 + offsetof(struct quota_clone_settings, pool),
};
