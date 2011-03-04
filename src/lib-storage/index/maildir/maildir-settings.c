/* Copyright (c) 2005-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "mail-storage-settings.h"
#include "maildir-settings.h"

#include <stddef.h>

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct maildir_settings, name), NULL }

static const struct setting_define maildir_setting_defines[] = {
	DEF(SET_BOOL, maildir_copy_with_hardlinks),
	DEF(SET_BOOL, maildir_very_dirty_syncs),

	SETTING_DEFINE_LIST_END
};

static const struct maildir_settings maildir_default_settings = {
	.maildir_copy_with_hardlinks = TRUE,
	.maildir_very_dirty_syncs = FALSE
};

static const struct setting_parser_info maildir_setting_parser_info = {
	.module_name = "maildir",
	.defines = maildir_setting_defines,
	.defaults = &maildir_default_settings,

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct maildir_settings),

	.parent_offset = (size_t)-1,
	.parent = &mail_user_setting_parser_info
};

const struct setting_parser_info *maildir_get_setting_parser_info(void)
{
	return &maildir_setting_parser_info;
}

