/* Copyright (c) 2006-2009 Dovecot authors, see the included COPYING file */

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
	DEF(SET_UINT, mdbox_rotate_size),
	DEF(SET_UINT, mdbox_rotate_min_size),
	DEF(SET_UINT, mdbox_rotate_days),
	DEF(SET_UINT, mdbox_max_open_files),
	DEF(SET_UINT, mdbox_purge_min_percentage),

	SETTING_DEFINE_LIST_END
};

static const struct mdbox_settings mdbox_default_settings = {
	MEMBER(mdbox_rotate_size) 2048*1024,
	MEMBER(mdbox_rotate_min_size) 16*1024,
	MEMBER(mdbox_rotate_days) 0,
	MEMBER(mdbox_max_open_files) 64,
	MEMBER(mdbox_purge_min_percentage) 0
};

static const struct setting_parser_info mdbox_setting_parser_info = {
	MEMBER(module_name) "mdbox",
	MEMBER(defines) mdbox_setting_defines,
	MEMBER(defaults) &mdbox_default_settings,

	MEMBER(type_offset) (size_t)-1,
	MEMBER(struct_size) sizeof(struct mdbox_settings),

	MEMBER(parent_offset) (size_t)-1,
	MEMBER(parent) &mail_user_setting_parser_info,

	MEMBER(check_func) mdbox_settings_verify
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
