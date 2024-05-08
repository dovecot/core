/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "mail-storage-settings.h"
#include "mbox-settings.h"

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct mbox_settings)

static const struct setting_define mbox_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "mbox" },
	DEF(BOOLLIST, mbox_read_locks),
	DEF(BOOLLIST, mbox_write_locks),
	DEF(TIME, mbox_lock_timeout),
	DEF(TIME, mbox_dotlock_change_timeout),
	DEF(SIZE_HIDDEN, mbox_min_index_size),
	DEF(BOOL, mbox_dirty_syncs),
	DEF(BOOL, mbox_very_dirty_syncs),
	DEF(BOOL, mbox_lazy_writes),
	DEF(ENUM_HIDDEN, mbox_md5),

	SETTING_DEFINE_LIST_END
};

static const struct mbox_settings mbox_default_settings = {
	.mbox_read_locks = ARRAY_INIT,
	.mbox_write_locks = ARRAY_INIT,
	.mbox_lock_timeout = 5*60,
	.mbox_dotlock_change_timeout = 2*60,
	.mbox_min_index_size = 0,
	.mbox_dirty_syncs = TRUE,
	.mbox_very_dirty_syncs = FALSE,
	.mbox_lazy_writes = TRUE,
	.mbox_md5 = "apop3d:all"
};

static const struct setting_keyvalue mbox_default_settings_keyvalue[] = {
	{ "mbox/mailbox_subscriptions_filename", ".subscriptions" },
	{ "mbox/mail_path", "%{home}/mail" },
	/* Use $mail_path/inbox as the INBOX, not $mail_path/INBOX */
	{ "mbox/layout_fs/mail_inbox_path", "inbox" },
	{ "mbox_read_locks", "fcntl" },
	{ "mbox_write_locks", "dotlock fcntl" },
	{ NULL, NULL }
};

const struct setting_parser_info mbox_setting_parser_info = {
	.name = "mbox",

	.defines = mbox_setting_defines,
	.defaults = &mbox_default_settings,
	.default_settings = mbox_default_settings_keyvalue,

	.struct_size = sizeof(struct mbox_settings),
	.pool_offset1 = 1 + offsetof(struct mbox_settings, pool),
};
