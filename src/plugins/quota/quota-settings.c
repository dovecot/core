/* Copyright (c) 2024 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "quota-settings.h"

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct quota_settings)
static const struct setting_define quota_setting_defines[] = {
	DEF(UINT, quota_mailbox_count),
	DEF(UINT, quota_mailbox_message_count),
	DEF(SIZE, quota_mail_size),
	DEF(STR, quota_exceeded_message),

	SETTING_DEFINE_LIST_END
};

static const struct quota_settings quota_default_settings = {
	.quota_mailbox_count = SET_UINT_UNLIMITED,
	.quota_mail_size = SET_SIZE_UNLIMITED,
	.quota_mailbox_message_count = SET_UINT_UNLIMITED,
	.quota_exceeded_message = "Quota exceeded (mailbox for user is full)",
};

const struct setting_parser_info quota_setting_parser_info = {
	.name = "quota",
	.defines = quota_setting_defines,
	.defaults = &quota_default_settings,
	.struct_size = sizeof(struct quota_settings),
	.pool_offset1 = 1 + offsetof(struct quota_settings, pool),
};

struct quota_settings *quota_get_unlimited_set(void)
{
	static struct quota_settings set;
	if (set.pool == NULL) {
		set = quota_default_settings;
		set.pool = null_pool;
	}
	return &set;
}
