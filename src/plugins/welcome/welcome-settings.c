/* Copyright (c) 2015-2025 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "welcome-settings.h"
#include "service-settings.h"

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct welcome_settings)

static const struct setting_define welcome_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "welcome",
	  .required_setting = "execute", },
	DEF(BOOL, welcome_wait),

	SETTING_DEFINE_LIST_END
};

static const struct welcome_settings welcome_default_settings = {
	.welcome_wait = FALSE,
};

const struct setting_parser_info welcome_setting_parser_info = {
	.name = "welcome",
	.plugin_dependency = "lib99_welcome_plugin",
	.defines = welcome_setting_defines,
	.defaults = &welcome_default_settings,
	.struct_size = sizeof(struct welcome_settings),
	.pool_offset1 = 1 + offsetof(struct welcome_settings, pool),
};

struct service_settings welcome_service_settings = {
	.name = "welcome",
	.protocol = "",
	.type = "",
	.user = "$SET:default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = ARRAY_INIT,
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT,
};
