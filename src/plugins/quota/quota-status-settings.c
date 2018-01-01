/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "mail-storage-settings.h"
#include "quota-status-settings.h"

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct quota_status_settings, name), NULL }

static const struct setting_define quota_status_setting_defines[] = {
	DEF(SET_STR, recipient_delimiter),

	SETTING_DEFINE_LIST_END
};

static const struct quota_status_settings quota_status_default_settings = {
	.recipient_delimiter = "+",
};

static const struct setting_parser_info *quota_status_setting_dependencies[] = {
	NULL
};

const struct setting_parser_info quota_status_setting_parser_info = {
	.module_name = "mail",
	.defines = quota_status_setting_defines,
	.defaults = &quota_status_default_settings,

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct quota_status_settings),

	.parent_offset = (size_t)-1,
	.dependencies = quota_status_setting_dependencies
};
