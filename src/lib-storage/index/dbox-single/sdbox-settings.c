/* Copyright (c) 2006-2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "mail-storage-settings.h"
#include "dbox-storage.h"
#include "sdbox-settings.h"

static const struct setting_define sdbox_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "sdbox" },
	SETTING_DEFINE_LIST_END
};

static const struct sdbox_settings sdbox_default_settings = {
};

static const struct setting_keyvalue sdbox_default_settings_keyvalue[] = {
	{ "sdbox/mailbox_root_directory_name", DBOX_MAILBOX_DIR_NAME },
	{ "sdbox/mailbox_directory_name", DBOX_MAILDIR_NAME },
	{ "sdbox/mail_path", "%{home}/sdbox" },
	{ NULL, NULL }
};

const struct setting_parser_info sdbox_setting_parser_info = {
	.name = "sdbox",

	.defines = sdbox_setting_defines,
	.defaults = &sdbox_default_settings,
	.default_settings = sdbox_default_settings_keyvalue,

	.struct_size = sizeof(struct sdbox_settings),
	.pool_offset1 = 1 + offsetof(struct sdbox_settings, pool),
};
