/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hostpid.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "mail-storage-settings.h"
#include "submission-settings.h"

#include <stddef.h>
#include <unistd.h>

static bool submission_settings_verify(void *_set, pool_t pool,
				       const char **error_r);

/* <settings checks> */
static struct file_listener_settings submission_unix_listeners_array[] = {
	{ "login/submission", 0666, "", "" },
	{ "srv.submission/%{pid}", 0600, "", "" },
};
static struct file_listener_settings *submission_unix_listeners[] = {
	&submission_unix_listeners_array[0],
	&submission_unix_listeners_array[1],
};
static buffer_t submission_unix_listeners_buf = {
	{ { submission_unix_listeners, sizeof(submission_unix_listeners) } }
};
/* </settings checks> */

struct service_settings submission_service_settings = {
	.name = "submission",
	.protocol = "submission",
	.type = "",
	.executable = "submission",
	.user = "",
	.group = "",
	.privileged_group = "",
	.extra_groups = "$default_internal_group",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 1024,
	.client_limit = 1,
	.service_count = 1,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = { { &submission_unix_listeners_buf,
			      sizeof(submission_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct submission_settings)

static const struct setting_define submission_setting_defines[] = {
	DEF(BOOL, verbose_proctitle),
	DEF(STR_VARS, rawlog_dir),

	DEF(STR, hostname),

	DEF(STR, login_greeting),
	DEF(STR, login_trusted_networks),

	DEF(STR, recipient_delimiter),

	DEF(SIZE, submission_max_mail_size),
	DEF(UINT, submission_max_recipients),
	DEF(STR, submission_client_workarounds),
	DEF(STR, submission_logout_format),
	DEF(BOOL, submission_add_received_header),

	DEF(STR, submission_backend_capabilities),

	DEF(STR, submission_relay_host),
	DEF(IN_PORT, submission_relay_port),
	DEF(BOOL, submission_relay_trusted),

	DEF(STR, submission_relay_user),
	DEF(STR, submission_relay_master_user),
	DEF(STR, submission_relay_password),

	DEF(ENUM, submission_relay_ssl),
	DEF(BOOL, submission_relay_ssl_verify),

	DEF(STR_VARS, submission_relay_rawlog_dir),
	DEF(TIME, submission_relay_max_idle_time),

	DEF(TIME_MSECS, submission_relay_connect_timeout),
	DEF(TIME_MSECS, submission_relay_command_timeout),

	DEF(STR, imap_urlauth_host),
	DEF(IN_PORT, imap_urlauth_port),

	SETTING_DEFINE_LIST_END
};

static const struct submission_settings submission_default_settings = {
	.verbose_proctitle = FALSE,
	.rawlog_dir = "",

	.hostname = "",

	.login_greeting = PACKAGE_NAME" ready.",
	.login_trusted_networks = "",

	.recipient_delimiter = "+",

	.submission_max_mail_size = 40*1024*1024,
	.submission_max_recipients = 0,
	.submission_client_workarounds = "",
	.submission_logout_format = "in=%i out=%o",
	.submission_add_received_header = TRUE,

	.submission_backend_capabilities = NULL,

	.submission_relay_host = "",
	.submission_relay_port = 25,
	.submission_relay_trusted = FALSE,

	.submission_relay_user = "",
	.submission_relay_master_user = "",
	.submission_relay_password = "",

	.submission_relay_ssl = "no:smtps:starttls",
	.submission_relay_ssl_verify = TRUE,

	.submission_relay_rawlog_dir = "",
	.submission_relay_max_idle_time = 60*29,

	.submission_relay_connect_timeout = 30*1000,
	.submission_relay_command_timeout = 60*5*1000,

	.imap_urlauth_host = "",
	.imap_urlauth_port = 143,
};

static const struct setting_parser_info *submission_setting_dependencies[] = {
	&mail_user_setting_parser_info,
	NULL
};

const struct setting_parser_info submission_setting_parser_info = {
	.module_name = "submission",
	.defines = submission_setting_defines,
	.defaults = &submission_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct submission_settings),

	.parent_offset = SIZE_MAX,

	.check_func = submission_settings_verify,
	.dependencies = submission_setting_dependencies
};

/* <settings checks> */
struct submission_client_workaround_list {
	const char *name;
	enum submission_client_workarounds num;
};

/* These definitions need to be kept in sync with equivalent definitions present
   in src/submission-login/submission-login-settings.c. Workarounds that are not
   relevant to the submission service are defined as 0 here to prevent "Unknown
   workaround" errors below. */
static const struct submission_client_workaround_list
submission_client_workaround_list[] = {
	{ "whitespace-before-path",
	  SUBMISSION_WORKAROUND_WHITESPACE_BEFORE_PATH },
	{ "mailbox-for-path",
	  SUBMISSION_WORKAROUND_MAILBOX_FOR_PATH },
	{ "implicit-auth-external", 0 },
	{ "exotic-backend", 0 },
	{ NULL, 0 }
};

static int
submission_settings_parse_workarounds(struct submission_settings *set,
				const char **error_r)
{
	enum submission_client_workarounds client_workarounds = 0;
        const struct submission_client_workaround_list *list;
	const char *const *str;

        str = t_strsplit_spaces(set->submission_client_workarounds, " ,");
	for (; *str != NULL; str++) {
		list = submission_client_workaround_list;
		for (; list->name != NULL; list++) {
			if (strcasecmp(*str, list->name) == 0) {
				client_workarounds |= list->num;
				break;
			}
		}
		if (list->name == NULL) {
			*error_r = t_strdup_printf(
				"submission_client_workarounds: "
				"Unknown workaround: %s", *str);
			return -1;
		}
	}
	set->parsed_workarounds = client_workarounds;
	return 0;
}

static bool
submission_settings_verify(void *_set, pool_t pool ATTR_UNUSED, const char **error_r)
{
	struct submission_settings *set = _set;

	if (submission_settings_parse_workarounds(set, error_r) < 0)
		return FALSE;

#ifndef CONFIG_BINARY
	if (set->submission_relay_max_idle_time == 0) {
		*error_r = "submission_relay_max_idle_time must not be 0";
		return FALSE;
	}
	if (*set->hostname == '\0')
		set->hostname = p_strdup(pool, my_hostdomain());
#endif
	return TRUE;
}
/* </settings checks> */
