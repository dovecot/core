/* Copyright (c) 2006-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "mail-storage-settings.h"
#include "mdbox-settings.h"

#include <stddef.h>

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct mdbox_settings, name), NULL }

static bool mdbox_settings_verify(void *_set, pool_t pool ATTR_UNUSED,
				  const char **error_r);

static const struct setting_define mdbox_setting_defines[] = {
	DEF(SET_SIZE, mdbox_rotate_size),
	DEF(SET_TIME, mdbox_rotate_interval),
	DEF(SET_TIME, mdbox_altmove),
	DEF(SET_UINT, mdbox_max_open_files),

	SETTING_DEFINE_LIST_END
};

static const struct mdbox_settings mdbox_default_settings = {
	.mdbox_rotate_size = 2*1024*1024,
	.mdbox_rotate_interval = 0,
	.mdbox_altmove = 3600*24*7,
	.mdbox_max_open_files = 64
};

static const struct setting_parser_info mdbox_setting_parser_info = {
	.module_name = "mdbox",
	.defines = mdbox_setting_defines,
	.defaults = &mdbox_default_settings,

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct mdbox_settings),

	.parent_offset = (size_t)-1,
	.parent = &mail_user_setting_parser_info,

	.check_func = mdbox_settings_verify
};

/* <settings checks> */
static bool mdbox_settings_verify(void *_set, pool_t pool ATTR_UNUSED,
				  const char **error_r)
{
	const struct mdbox_settings *set = _set;

	if (set->mdbox_max_open_files < 2) {
		*error_r = "mdbox_max_open_files must be at least 2";
		return FALSE;
	}
	return TRUE;
}
/* </settings checks> */

const struct setting_parser_info *mdbox_get_setting_parser_info(void)
{
	return &mdbox_setting_parser_info;
}
