/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "mail-storage-settings.h"
#include "maildir-settings.h"

#include <stddef.h>

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct maildir_settings, name), NULL }

static struct setting_define maildir_setting_defines[] = {
	DEF(SET_BOOL, maildir_stat_dirs),
	DEF(SET_BOOL, maildir_copy_with_hardlinks),
	DEF(SET_BOOL, maildir_copy_preserve_filename),
	DEF(SET_BOOL, maildir_very_dirty_syncs),

	SETTING_DEFINE_LIST_END
};

static struct maildir_settings maildir_default_settings = {
	MEMBER(maildir_stat_dirs) FALSE,
	MEMBER(maildir_copy_with_hardlinks) TRUE,
	MEMBER(maildir_copy_preserve_filename) FALSE,
	MEMBER(maildir_very_dirty_syncs) FALSE
};

static struct setting_parser_info maildir_setting_parser_info = {
	MEMBER(module_name) "maildir",
	MEMBER(defines) maildir_setting_defines,
	MEMBER(defaults) &maildir_default_settings,

	MEMBER(type_offset) (size_t)-1,
	MEMBER(struct_size) sizeof(struct maildir_settings),

	MEMBER(parent_offset) (size_t)-1,
	MEMBER(parent) &mail_user_setting_parser_info
};

const struct setting_parser_info *maildir_get_setting_parser_info(void)
{
	return &maildir_setting_parser_info;
}

