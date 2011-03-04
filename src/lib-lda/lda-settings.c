/* Copyright (c) 2005-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hostpid.h"
#include "settings-parser.h"
#include "mail-storage-settings.h"
#include "lda-settings.h"

#include <stddef.h>

static bool lda_settings_check(void *_set, pool_t pool, const char **error_r);

#undef DEF
#undef DEFLIST
#define DEF(type, name) \
	{ type, #name, offsetof(struct lda_settings, name), NULL }
#define DEFLIST(field, name, defines) \
	{ SET_DEFLIST, name, offsetof(struct lda_settings, field), defines }

static const struct setting_define lda_setting_defines[] = {
	DEF(SET_STR, postmaster_address),
	DEF(SET_STR, hostname),
	DEF(SET_STR, submission_host),
	DEF(SET_STR, sendmail_path),
	DEF(SET_STR, rejection_subject),
	DEF(SET_STR, rejection_reason),
	DEF(SET_STR, deliver_log_format),
	DEF(SET_STR, recipient_delimiter),
	DEF(SET_STR, lda_original_recipient_header),
	DEF(SET_BOOL, quota_full_tempfail),
	DEF(SET_BOOL, lda_mailbox_autocreate),
	DEF(SET_BOOL, lda_mailbox_autosubscribe),

	SETTING_DEFINE_LIST_END
};

static const struct lda_settings lda_default_settings = {
	.postmaster_address = "",
	.hostname = "",
	.submission_host = "",
	.sendmail_path = "/usr/sbin/sendmail",
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

static const struct setting_parser_info *lda_setting_dependencies[] = {
	&mail_user_setting_parser_info,
	NULL
};

const struct setting_parser_info lda_setting_parser_info = {
	.module_name = "lda",
	.defines = lda_setting_defines,
	.defaults = &lda_default_settings,

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct lda_settings),

	.parent_offset = (size_t)-1,

#ifndef CONFIG_BINARY
	.check_func = lda_settings_check,
#endif
	.dependencies = lda_setting_dependencies
};

static bool lda_settings_check(void *_set, pool_t pool, const char **error_r)
{
	struct lda_settings *set = _set;

	if (*set->hostname == '\0')
		set->hostname = p_strdup(pool, my_hostdomain());
	if (*set->postmaster_address == '\0') {
		/* check for valid looking fqdn in hostname */
		if (strchr(set->hostname, '.') == NULL) {
			*error_r = "postmaster_address setting not given";
			return FALSE;
		}
		set->postmaster_address = p_strconcat(pool, "postmaster@",
						      set->hostname, NULL);
	}
	return TRUE;
}
