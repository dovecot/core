/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hostpid.h"
#include "settings-parser.h"
#include "smtp-submit-settings.h"

#include <stddef.h>

static bool smtp_submit_settings_check(void *_set, pool_t pool, const char **error_r);

#undef DEF
#undef DEFLIST
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct smtp_submit_settings)
#define DEFLIST(field, name, defines) \
	{ SET_DEFLIST, name, offsetof(struct smtp_submit_settings, field), defines }

static const struct setting_define smtp_submit_setting_defines[] = {
	DEF(STR, hostname),
	DEF(BOOL, mail_debug),

	DEF(STR_VARS, submission_host),
	DEF(STR_VARS, sendmail_path),
	DEF(TIME, submission_timeout),

	DEF(ENUM, submission_ssl),

	SETTING_DEFINE_LIST_END
};

static const struct smtp_submit_settings smtp_submit_default_settings = {
	.hostname = "",
	.mail_debug = FALSE,

	.submission_host = "",
	.sendmail_path = "/usr/sbin/sendmail",
	.submission_timeout = 30,

	.submission_ssl = "no:smtps:submissions:starttls",
};

const struct setting_parser_info smtp_submit_setting_parser_info = {
	.module_name = "smtp-submit",
	.defines = smtp_submit_setting_defines,
	.defaults = &smtp_submit_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct smtp_submit_settings),

	.parent_offset = SIZE_MAX,

#ifndef CONFIG_BINARY
	.check_func = smtp_submit_settings_check,
#endif
};

static bool
smtp_submit_settings_check(void *_set, pool_t pool,
	const char **error_r ATTR_UNUSED)
{
	struct smtp_submit_settings *set = _set;

	if (*set->hostname == '\0')
		set->hostname = p_strdup(pool, my_hostdomain());
	return TRUE;
}
