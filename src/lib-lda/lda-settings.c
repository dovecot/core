/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hostpid.h"
#include "settings-parser.h"
#include "mail-storage-settings.h"
#include "smtp-submit-settings.h"
#include "lda-settings.h"

static bool lda_settings_check(void *_set, pool_t pool, const char **error_r);

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct lda_settings)

static const struct setting_define lda_setting_defines[] = {
	DEF(STR, hostname),
	DEF(STR, rejection_subject),
	DEF(STR, rejection_reason),
	DEF(STR, deliver_log_format),
	DEF(STR, recipient_delimiter),
	DEF(STR, lda_original_recipient_header),
	DEF(BOOL, quota_full_tempfail),
	DEF(BOOL, lda_mailbox_autocreate),
	DEF(BOOL, lda_mailbox_autosubscribe),

	SETTING_DEFINE_LIST_END
};

static const struct lda_settings lda_default_settings = {
	.hostname = "",
	.rejection_subject = "Rejected: %s",
	.rejection_reason =
		"Your message to <%t> was automatically rejected:%n%r",
	.deliver_log_format = "msgid=%m: %$",
	.recipient_delimiter = "+",
	.lda_original_recipient_header = "",
	.quota_full_tempfail = FALSE,
	.lda_mailbox_autocreate = FALSE,
	.lda_mailbox_autosubscribe = FALSE
};

const struct setting_parser_info lda_setting_parser_info = {
	.name = "lda",

	.defines = lda_setting_defines,
	.defaults = &lda_default_settings,

	.struct_size = sizeof(struct lda_settings),
	.pool_offset1 = 1 + offsetof(struct lda_settings, pool),
#ifndef CONFIG_BINARY
	.check_func = lda_settings_check,
#endif
};

static bool lda_settings_check(void *_set, pool_t pool,
	const char **error_r ATTR_UNUSED)
{
	struct lda_settings *set = _set;

	if (*set->hostname == '\0')
		set->hostname = p_strdup(pool, my_hostdomain());
	return TRUE;
}
