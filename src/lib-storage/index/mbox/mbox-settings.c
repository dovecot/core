/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "mail-storage-settings.h"
#include "mbox-settings.h"

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct mbox_settings)

static const struct setting_define mbox_setting_defines[] = {
	DEF(STR, mbox_read_locks),
	DEF(STR, mbox_write_locks),
	DEF(TIME, mbox_lock_timeout),
	DEF(TIME, mbox_dotlock_change_timeout),
	DEF(SIZE, mbox_min_index_size),
	DEF(BOOL, mbox_dirty_syncs),
	DEF(BOOL, mbox_very_dirty_syncs),
	DEF(BOOL, mbox_lazy_writes),
	DEF(ENUM, mbox_md5),

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
	.mbox_lazy_writes = TRUE,
	.mbox_md5 = "apop3d:all"
};

const struct setting_parser_info mbox_setting_parser_info = {
	.name = "mbox",

	.defines = mbox_setting_defines,
	.defaults = &mbox_default_settings,

	.struct_size = sizeof(struct mbox_settings),
	.pool_offset1 = 1 + offsetof(struct mbox_settings, pool),
};
