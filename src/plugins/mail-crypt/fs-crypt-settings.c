/* Copyright (c) 2010-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "mail-storage-settings.h"
#include "fs-crypt-settings.h"

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct fs_crypt_settings, name), NULL }

static const struct setting_define fs_crypt_setting_defines[] = {
	{ SET_STRLIST, "plugin", offsetof(struct fs_crypt_settings, plugin_envs), NULL },

	SETTING_DEFINE_LIST_END
};

const struct fs_crypt_settings fs_crypt_default_settings = {
	.plugin_envs = ARRAY_INIT
};

static const struct setting_parser_info *fs_crypt_setting_dependencies[] = {
	NULL
};

const struct setting_parser_info fs_crypt_setting_parser_info = {
	.module_name = "fs-crypt",
	.defines = fs_crypt_setting_defines,
	.defaults = &fs_crypt_default_settings,

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct fs_crypt_settings),

	.parent_offset = (size_t)-1,
	.dependencies = fs_crypt_setting_dependencies
};
