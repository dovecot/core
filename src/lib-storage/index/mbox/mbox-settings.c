/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "mail-storage-settings.h"
#include "mbox-settings.h"

#include <stddef.h>

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct mbox_settings, name), NULL }

static struct setting_define mbox_setting_defines[] = {
	DEF(SET_STR, mbox_read_locks),
	DEF(SET_STR, mbox_write_locks),
	DEF(SET_UINT, mbox_lock_timeout),
	DEF(SET_UINT, mbox_dotlock_change_timeout),
	DEF(SET_UINT, mbox_min_index_size),
	DEF(SET_BOOL, mbox_dirty_syncs),
	DEF(SET_BOOL, mbox_very_dirty_syncs),
	DEF(SET_BOOL, mbox_lazy_writes),

	SETTING_DEFINE_LIST_END
};

static struct mbox_settings mbox_default_settings = {
	MEMBER(mbox_read_locks) "fcntl",
	MEMBER(mbox_write_locks) "dotlock fcntl",
	MEMBER(mbox_lock_timeout) 5*60,
	MEMBER(mbox_dotlock_change_timeout) 2*60,
	MEMBER(mbox_min_index_size) 0,
	MEMBER(mbox_dirty_syncs) TRUE,
	MEMBER(mbox_very_dirty_syncs) FALSE,
	MEMBER(mbox_lazy_writes) TRUE
};

static struct setting_parser_info mbox_setting_parser_info = {
	MEMBER(defines) mbox_setting_defines,
	MEMBER(defaults) &mbox_default_settings,

	MEMBER(type_offset) (size_t)-1,
	MEMBER(struct_size) sizeof(struct mbox_settings),

	MEMBER(parent_offset) (size_t)-1,
	MEMBER(parent) &mail_user_setting_parser_info
};

const struct setting_parser_info *mbox_get_setting_parser_info(void)
{
	return &mbox_setting_parser_info;
}
