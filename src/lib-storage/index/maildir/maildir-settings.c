/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "mail-storage-settings.h"
#include "maildir-settings.h"

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct maildir_settings)

static const struct setting_define maildir_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "maildir" },
	DEF(BOOL, maildir_copy_with_hardlinks),
	DEF(BOOL, maildir_very_dirty_syncs),
	DEF(BOOL, maildir_broken_filename_sizes),
	DEF(BOOL, maildir_empty_new),

	SETTING_DEFINE_LIST_END
};

static const struct maildir_settings maildir_default_settings = {
	.maildir_copy_with_hardlinks = TRUE,
	.maildir_very_dirty_syncs = FALSE,
	.maildir_broken_filename_sizes = FALSE,
	.maildir_empty_new = FALSE
};

static const struct setting_keyvalue maildir_default_settings_keyvalue[] = {
	{ "maildir/mailbox_list_layout", "maildir++" },
	{ "maildir/mail_path", "%{home}/Maildir" },
	/* Use Maildir/ root as the INBOX, not Maildir/.INBOX/ */
	{ "maildir/layout_maildir++/mail_inbox_path", "." },
	{ "maildir/layout_fs/mail_inbox_path", "." },
	{ NULL, NULL }
};

const struct setting_parser_info maildir_setting_parser_info = {
	.name = "maildir",

	.defines = maildir_setting_defines,
	.defaults = &maildir_default_settings,
	.default_settings = maildir_default_settings_keyvalue,

	.struct_size = sizeof(struct maildir_settings),
	.pool_offset1 = 1 + offsetof(struct maildir_settings, pool),
};
