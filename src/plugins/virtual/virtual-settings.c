/* Copyright (c) 2006-2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "mail-storage-settings.h"
#include "virtual-settings.h"

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct virtual_settings)
static const struct setting_define virtual_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "virtual" },
	DEF(UINT, virtual_max_open_mailboxes),

	SETTING_DEFINE_LIST_END
};

static const struct virtual_settings virtual_default_settings = {
	.virtual_max_open_mailboxes = 64,
};

static const struct setting_keyvalue virtual_default_settings_keyvalue[] = {
	{ "virtual/mailbox_subscriptions_filename", ".virtual-subscriptions" },
	{ NULL, NULL }
};

const struct setting_parser_info virtual_setting_parser_info = {
	.name = "virtual",
	.plugin_dependency = "lib20_virtual_plugin",

	.defines = virtual_setting_defines,
	.defaults = &virtual_default_settings,
	.default_settings = virtual_default_settings_keyvalue,

	.struct_size = sizeof(struct virtual_settings),
	.pool_offset1 = 1 + offsetof(struct virtual_settings, pool),
};
