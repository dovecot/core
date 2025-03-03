/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "mail-storage-settings.h"
#include "quota-status-settings.h"

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct quota_status_settings)

static const struct setting_define quota_status_setting_defines[] = {
	DEF(STR, recipient_delimiter),
	DEF(STR, quota_status_nouser),

	SETTING_DEFINE_LIST_END
};

static const struct quota_status_settings quota_status_default_settings = {
	.recipient_delimiter = "+",
	.quota_status_nouser = "REJECT Unknown user",
};

const struct setting_parser_info quota_status_setting_parser_info = {
	.name = "quota_status",
	.plugin_dependency = "lib10_quota_plugin",

	.defines = quota_status_setting_defines,
	.defaults = &quota_status_default_settings,

	.struct_size = sizeof(struct quota_status_settings),
	.pool_offset1 = 1 + offsetof(struct quota_status_settings, pool),
};
