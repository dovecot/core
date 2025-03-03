/* Copyright (c) 2024 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "mail-storage-settings.h"
#include "mail-lua-settings.h"

static const struct setting_define mail_lua_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = MAIL_LUA_FILTER },
	SETTING_DEFINE_LIST_END
};

static const struct mail_lua_settings mail_lua_default_settings = {
};

const struct setting_parser_info mail_lua_setting_parser_info = {
	.name = "mail_lua",
	.plugin_dependency = "lib01_mail_lua_plugin",

	.defines = mail_lua_setting_defines,
	.defaults = &mail_lua_default_settings,

	.struct_size = sizeof(struct mail_lua_settings),
	.pool_offset1 = 1 + offsetof(struct mail_lua_settings, pool),
};
