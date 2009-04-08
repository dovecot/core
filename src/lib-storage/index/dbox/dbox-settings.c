/* Copyright (c) 2006-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "mail-storage-settings.h"
#include "dbox-settings.h"

#include <stddef.h>

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct dbox_settings, name), NULL }

static struct setting_define dbox_setting_defines[] = {
	DEF(SET_UINT, dbox_rotate_size),
	DEF(SET_UINT, dbox_rotate_min_size),
	DEF(SET_UINT, dbox_rotate_days),
	DEF(SET_UINT, dbox_max_open_files),
	DEF(SET_UINT, dbox_purge_min_percentage),

	SETTING_DEFINE_LIST_END
};

static struct dbox_settings dbox_default_settings = {
	MEMBER(dbox_rotate_size) 2048*1024,
	MEMBER(dbox_rotate_min_size) 16*1024,
	MEMBER(dbox_rotate_days) 0,
	MEMBER(dbox_max_open_files) 64,
	MEMBER(dbox_purge_min_percentage) 0
};

static struct setting_parser_info dbox_setting_parser_info = {
	MEMBER(defines) dbox_setting_defines,
	MEMBER(defaults) &dbox_default_settings,

	MEMBER(parent) &mail_user_setting_parser_info,
	MEMBER(dynamic_parsers) NULL,

	MEMBER(parent_offset) (size_t)-1,
	MEMBER(type_offset) (size_t)-1,
	MEMBER(struct_size) sizeof(struct dbox_settings)
};

const struct setting_parser_info *dbox_get_setting_parser_info(void)
{
	return &dbox_setting_parser_info;
}
