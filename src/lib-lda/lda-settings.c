/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
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
	DEF(SET_STR, sendmail_path),
	DEF(SET_STR, rejection_subject),
	DEF(SET_STR, rejection_reason),
	DEF(SET_STR, deliver_log_format),
	DEF(SET_BOOL, quota_full_tempfail),
	DEF(SET_BOOL, lda_mailbox_autocreate),
	DEF(SET_BOOL, lda_mailbox_autosubscribe),

	SETTING_DEFINE_LIST_END
};

static const struct lda_settings lda_default_settings = {
	MEMBER(postmaster_address) "",
	MEMBER(hostname) "",
	MEMBER(sendmail_path) "/usr/lib/sendmail",
	MEMBER(rejection_subject) "Rejected: %s",
	MEMBER(rejection_reason)
		"Your message to <%t> was automatically rejected:%n%r",
	MEMBER(deliver_log_format) "msgid=%m: %$",
	MEMBER(quota_full_tempfail) FALSE,
	MEMBER(lda_mailbox_autocreate) FALSE,
	MEMBER(lda_mailbox_autosubscribe) FALSE
};

static const struct setting_parser_info *lda_setting_dependencies[] = {
	&mail_user_setting_parser_info,
	NULL
};

const struct setting_parser_info lda_setting_parser_info = {
	MEMBER(module_name) "lda",
	MEMBER(defines) lda_setting_defines,
	MEMBER(defaults) &lda_default_settings,

	MEMBER(type_offset) (size_t)-1,
	MEMBER(struct_size) sizeof(struct lda_settings),

	MEMBER(parent_offset) (size_t)-1,
	MEMBER(parent) NULL,

#ifdef CONFIG_BINARY
	MEMBER(check_func) NULL,
#else
	MEMBER(check_func) lda_settings_check,
#endif
	MEMBER(dependencies) lda_setting_dependencies
};

static bool lda_settings_check(void *_set, pool_t pool ATTR_UNUSED,
			       const char **error_r)
{
	struct lda_settings *set = _set;

	if (*set->postmaster_address == '\0') {
		*error_r = "postmaster_address setting not given";
		return FALSE;
	}
	return TRUE;
}
