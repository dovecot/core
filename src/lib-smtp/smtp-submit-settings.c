/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "hostpid.h"
#include "settings-parser.h"
#include "smtp-submit-settings.h"

static bool smtp_submit_settings_check(void *_set, pool_t pool, const char **error_r);

#undef DEF_NOPREFIX
#define DEF_NOPREFIX(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct smtp_submit_settings)
#undef DEF_MSECS
#define DEF_MSECS(type, name) \
	SETTING_DEFINE_STRUCT_##type("mail_submit_"#name, name##_msecs, struct smtp_submit_settings)

static const struct setting_define smtp_submit_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = SMTP_SUBMIT_SETTINGS_FILTER },

	DEF_NOPREFIX(BOOL, mail_debug),
	DEF_MSECS(TIME_MSECS, timeout),

	/* deprecated */
	DEF_NOPREFIX(STR_HIDDEN, submission_host),
	DEF_NOPREFIX(STR_HIDDEN, sendmail_path),

	SETTING_DEFINE_LIST_END
};

static const struct smtp_submit_settings smtp_submit_default_settings = {
	.mail_debug = FALSE,
	.timeout_msecs = 30 * 1000,

	/* deprecated */
	.submission_host = "",
	.sendmail_path = "",
};

static const struct setting_keyvalue smtp_submit_default_settings_keyvalue[] = {
	{ "mail_submit/execute", "sendmail" },
	{ "mail_submit/execute/sendmail/execute_name", "sendmail" },
	{ "mail_submit/execute/sendmail/execute_driver", "fork" },
	{ "mail_submit/execute/sendmail/execute_fork_path", "/usr/sbin/sendmail" },

	{ "mail_submit/smtp_client_port", "25" },
	{ "mail_submit/smtp_client_ssl", "no" },
	{ NULL, NULL }
};

const struct setting_parser_info smtp_submit_setting_parser_info = {
	.name = "smtp_submit",

	.defines = smtp_submit_setting_defines,
	.defaults = &smtp_submit_default_settings,
	.default_settings = smtp_submit_default_settings_keyvalue,

	.struct_size = sizeof(struct smtp_submit_settings),
	.pool_offset1 = 1 + offsetof(struct smtp_submit_settings, pool),

	.check_func = smtp_submit_settings_check,
};

static bool
smtp_submit_settings_check(void *_set, pool_t pool ATTR_UNUSED,
			   const char **error_r)
{
	struct smtp_submit_settings *set = _set;
	const char *host;
	in_port_t port;

	if (net_str2hostport(set->submission_host, 25, &host, &port) < 0) {
		*error_r = t_strdup_printf(
			"submission_host: Invalid host:port: %s",
			set->submission_host);
		return FALSE;
	}
	return TRUE;
}
