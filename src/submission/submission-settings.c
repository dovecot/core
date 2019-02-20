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
	{ "login/submission", 0666, "", "" }
};
static struct file_listener_settings *submission_unix_listeners[] = {
	&submission_unix_listeners_array[0]
};
static buffer_t submission_unix_listeners_buf = {
	submission_unix_listeners, sizeof(submission_unix_listeners), { 0, }
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
	.vsz_limit = (uoff_t)-1,

	.unix_listeners = { { &submission_unix_listeners_buf,
			      sizeof(submission_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct submission_settings, name), NULL }

static const struct setting_define submission_setting_defines[] = {
	DEF(SET_BOOL, verbose_proctitle),
	DEF(SET_STR_VARS, rawlog_dir),

	DEF(SET_STR, hostname),

	DEF(SET_STR, login_greeting),
	DEF(SET_STR, login_trusted_networks),

	DEF(SET_SIZE, submission_max_mail_size),
	DEF(SET_UINT, submission_max_recipients),
	DEF(SET_STR, submission_client_workarounds),
	DEF(SET_STR, submission_logout_format),

	DEF(SET_STR, submission_backend_capabilities),

	DEF(SET_STR, submission_relay_host),
	DEF(SET_IN_PORT, submission_relay_port),
	DEF(SET_BOOL, submission_relay_trusted),

	DEF(SET_STR, submission_relay_user),
	DEF(SET_STR, submission_relay_master_user),
	DEF(SET_STR, submission_relay_password),

	DEF(SET_ENUM, submission_relay_ssl),
	DEF(SET_BOOL, submission_relay_ssl_verify),

	DEF(SET_STR_VARS, submission_relay_rawlog_dir),
	DEF(SET_TIME, submission_relay_max_idle_time),

	DEF(SET_TIME_MSECS, submission_relay_connect_timeout),
	DEF(SET_TIME_MSECS, submission_relay_command_timeout),

	DEF(SET_STR, imap_urlauth_host),
	DEF(SET_IN_PORT, imap_urlauth_port),

	SETTING_DEFINE_LIST_END
};

static const struct submission_settings submission_default_settings = {
	.verbose_proctitle = FALSE,
	.rawlog_dir = "",

	.hostname = "",

	.login_greeting = PACKAGE_NAME" ready.",
	.login_trusted_networks = "",

	.submission_max_mail_size = 40*1024*1024,
	.submission_max_recipients = 0,
	.submission_client_workarounds = "",
	.submission_logout_format = "in=%i out=%o",

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

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct submission_settings),

	.parent_offset = (size_t)-1,

	.check_func = submission_settings_verify,
	.dependencies = submission_setting_dependencies
};

/* <settings checks> */
struct submission_client_workaround_list {
	const char *name;
	enum submission_client_workarounds num;
};

static const struct submission_client_workaround_list
submission_client_workaround_list[] = {
	{ "whitespace-before-path", WORKAROUND_WHITESPACE_BEFORE_PATH },
	{ "mailbox-for-path", WORKAROUND_MAILBOX_FOR_PATH },
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
