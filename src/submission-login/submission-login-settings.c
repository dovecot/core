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
static struct inet_listener_settings submission_login_inet_listeners_array[] = {
	{ .name = "submission", .address = "", .port = 587  },
	{ .name = "submissions", .address = "", .port = 465, .ssl = TRUE }
};
static struct inet_listener_settings *submission_login_inet_listeners[] = {
	&submission_login_inet_listeners_array[0]
};
static buffer_t submission_login_inet_listeners_buf = {
	submission_login_inet_listeners, sizeof(submission_login_inet_listeners), { 0, }
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
	.vsz_limit = (uoff_t)-1,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = { { &submission_login_inet_listeners_buf,
			      sizeof(submission_login_inet_listeners[0]) } }
};

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct submission_login_settings, name), NULL }

static const struct setting_define submission_login_setting_defines[] = {
	DEF(SET_STR, hostname),

	DEF(SET_SIZE, submission_max_mail_size),
	DEF(SET_STR, submission_backend_capabilities),

	SETTING_DEFINE_LIST_END
};

static const struct submission_login_settings submission_login_default_settings = {
	.hostname = "",

	.submission_max_mail_size = 0,
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

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct submission_login_settings),
	.parent_offset = (size_t)-1,

#ifndef CONFIG_BINARY
	.check_func = submission_login_settings_check,
#endif
	.dependencies = submission_login_setting_dependencies
};

const struct setting_parser_info *submission_login_setting_roots[] = {
	&login_setting_parser_info,
	&submission_login_setting_parser_info,
	NULL
};

static bool
submission_login_settings_check(void *_set, pool_t pool,
			const char **error_r ATTR_UNUSED)
{
	struct submission_login_settings *set = _set;

	if (*set->hostname == '\0')
		set->hostname = p_strdup(pool, my_hostdomain());
	return TRUE;
}
