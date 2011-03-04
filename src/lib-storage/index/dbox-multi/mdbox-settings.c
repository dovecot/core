/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "mail-storage-settings.h"
#include "mdbox-settings.h"

#include <stddef.h>

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct mdbox_settings, name), NULL }

static const struct setting_define mdbox_setting_defines[] = {
	DEF(SET_BOOL, mdbox_preallocate_space),
	DEF(SET_SIZE, mdbox_rotate_size),
	DEF(SET_TIME, mdbox_rotate_interval),

	SETTING_DEFINE_LIST_END
};

static const struct mdbox_settings mdbox_default_settings = {
	.mdbox_preallocate_space = FALSE,
	.mdbox_rotate_size = 2*1024*1024,
	.mdbox_rotate_interval = 0
};

static const struct setting_parser_info mdbox_setting_parser_info = {
	.module_name = "mdbox",
	.defines = mdbox_setting_defines,
	.defaults = &mdbox_default_settings,

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct mdbox_settings),

	.parent_offset = (size_t)-1,
	.parent = &mail_user_setting_parser_info
};

const struct setting_parser_info *mdbox_get_setting_parser_info(void)
{
	return &mdbox_setting_parser_info;
}
