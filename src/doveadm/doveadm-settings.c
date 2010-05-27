/* Copyright (c) 2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "doveadm-settings.h"

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct doveadm_settings, name), NULL }

static const struct setting_define doveadm_setting_defines[] = {
	DEF(SET_STR, base_dir),
	DEF(SET_STR, mail_plugins),
	DEF(SET_STR, mail_plugin_dir),
	{ SET_STRLIST, "plugin", offsetof(struct doveadm_settings, plugin_envs), NULL },

	SETTING_DEFINE_LIST_END
};

const struct doveadm_settings doveadm_default_settings = {
	.base_dir = PKG_RUNDIR,
	.mail_plugins = "",
	.mail_plugin_dir = MODULEDIR,

	.plugin_envs = ARRAY_INIT
};

const struct setting_parser_info doveadm_setting_parser_info = {
	.module_name = "doveadm",
	.defines = doveadm_setting_defines,
	.defaults = &doveadm_default_settings,

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct doveadm_settings),

	.parent_offset = (size_t)-1
};

const struct doveadm_settings *doveadm_settings;
