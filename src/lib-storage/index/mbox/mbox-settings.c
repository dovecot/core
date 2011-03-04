/* Copyright (c) 2005-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "mail-storage-settings.h"
#include "mbox-settings.h"

#include <stddef.h>

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct mbox_settings, name), NULL }

static const struct setting_define mbox_setting_defines[] = {
	DEF(SET_STR, mbox_read_locks),
	DEF(SET_STR, mbox_write_locks),
	DEF(SET_TIME, mbox_lock_timeout),
	DEF(SET_TIME, mbox_dotlock_change_timeout),
	DEF(SET_SIZE, mbox_min_index_size),
	DEF(SET_BOOL, mbox_dirty_syncs),
	DEF(SET_BOOL, mbox_very_dirty_syncs),
	DEF(SET_BOOL, mbox_lazy_writes),

	SETTING_DEFINE_LIST_END
};

static const struct mbox_settings mbox_default_settings = {
	.mbox_read_locks = "fcntl",
	.mbox_write_locks = "dotlock fcntl",
	.mbox_lock_timeout = 5*60,
	.mbox_dotlock_change_timeout = 2*60,
	.mbox_min_index_size = 0,
	.mbox_dirty_syncs = TRUE,
	.mbox_very_dirty_syncs = FALSE,
	.mbox_lazy_writes = TRUE
};

static const struct setting_parser_info mbox_setting_parser_info = {
	.module_name = "mbox",
	.defines = mbox_setting_defines,
	.defaults = &mbox_default_settings,

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct mbox_settings),

	.parent_offset = (size_t)-1,
	.parent = &mail_user_setting_parser_info
};

const struct setting_parser_info *mbox_get_setting_parser_info(void)
{
	return &mbox_setting_parser_info;
}
