/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hostpid.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "login-settings.h"
#include "submission-login-settings.h"

#include <stddef.h>

static bool
submission_login_settings_check(void *_set, pool_t pool, const char **error_r);

/* <settings checks> */
static struct file_listener_settings submission_login_unix_listeners_array[] = {
	{ "srv.submission-login/%{pid}", 0600, "", "" },
};
static struct file_listener_settings *submission_login_unix_listeners[] = {
	&submission_login_unix_listeners_array[0],
};
static buffer_t submission_login_unix_listeners_buf = {
	{ { submission_login_unix_listeners,
	    sizeof(submission_login_unix_listeners) } }
};

static struct inet_listener_settings submission_login_inet_listeners_array[] = {
	{ .name = "submission", .address = "", .port = 587  },
	{ .name = "submissions", .address = "", .port = 465, .ssl = TRUE }
};
static struct inet_listener_settings *submission_login_inet_listeners[] = {
	&submission_login_inet_listeners_array[0]
};
static buffer_t submission_login_inet_listeners_buf = {
	{ { submission_login_inet_listeners,
	    sizeof(submission_login_inet_listeners) } }
};

/* </settings checks> */
struct service_settings submission_login_service_settings = {
	.name = "submission-login",
	.protocol = "submission",
	.type = "login",
	.executable = "submission-login",
	.user = "$default_login_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "login",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 0,
	.client_limit = 0,
	.service_count = 1,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = { { &submission_login_unix_listeners_buf,
			      sizeof(submission_login_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = { { &submission_login_inet_listeners_buf,
			      sizeof(submission_login_inet_listeners[0]) } }
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct submission_login_settings)

static const struct setting_define submission_login_setting_defines[] = {
	DEF(STR, hostname),

	DEF(SIZE, submission_max_mail_size),
	DEF(STR, submission_client_workarounds),
	DEF(STR, submission_backend_capabilities),

	SETTING_DEFINE_LIST_END
};

static const struct submission_login_settings submission_login_default_settings = {
	.hostname = "",

	.submission_max_mail_size = 0,
	.submission_client_workarounds = "",
	.submission_backend_capabilities = NULL
};

static const struct setting_parser_info *submission_login_setting_dependencies[] = {
	&login_setting_parser_info,
	NULL
};

const struct setting_parser_info submission_login_setting_parser_info = {
	.module_name = "submission-login",
	.defines = submission_login_setting_defines,
	.defaults = &submission_login_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct submission_login_settings),
	.parent_offset = SIZE_MAX,

	.check_func = submission_login_settings_check,
	.dependencies = submission_login_setting_dependencies
};

const struct setting_parser_info *submission_login_setting_roots[] = {
	&login_setting_parser_info,
	&submission_login_setting_parser_info,
	NULL
};

/* <settings checks> */
struct submission_login_client_workaround_list {
	const char *name;
	enum submission_login_client_workarounds num;
};

/* These definitions need to be kept in sync with equivalent definitions present
   in src/submission/submission-settings.c. Workarounds that are not relevant
   to the submission-login service are defined as 0 here to prevent "Unknown
   workaround" errors below. */
static const struct submission_login_client_workaround_list
submission_login_client_workaround_list[] = {
	{ "whitespace-before-path", 0},
	{ "mailbox-for-path", 0 },
	{ "implicit-auth-external",
	  SUBMISSION_LOGIN_WORKAROUND_IMPLICIT_AUTH_EXTERNAL },
	{ "exotic-backend",
	  SUBMISSION_LOGIN_WORKAROUND_EXOTIC_BACKEND },
	{ NULL, 0 }
};

static int
submission_login_settings_parse_workarounds(
	struct submission_login_settings *set, const char **error_r)
{
	enum submission_login_client_workarounds client_workarounds = 0;
        const struct submission_login_client_workaround_list *list;
	const char *const *str;

        str = t_strsplit_spaces(set->submission_client_workarounds, " ,");
	for (; *str != NULL; str++) {
		list = submission_login_client_workaround_list;
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
submission_login_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				const char **error_r)
{
	struct submission_login_settings *set = _set;

	if (submission_login_settings_parse_workarounds(set, error_r) < 0)
		return FALSE;

#ifndef CONFIG_BINARY
	if (*set->hostname == '\0')
		set->hostname = p_strdup(pool, my_hostdomain());
#endif
	return TRUE;
}
/* </settings checks> */
