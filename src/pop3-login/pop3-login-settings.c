/* Copyright (c) 2005-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "login-settings.h"
#include "pop3-login-settings.h"

#include <stddef.h>

/* <settings checks> */
static struct inet_listener_settings pop3_login_inet_listeners_array[] = {
	{ "pop3", "", 110, FALSE },
	{ "pop3s", "", 995, TRUE }
};
static struct inet_listener_settings *pop3_login_inet_listeners[] = {
	&pop3_login_inet_listeners_array[0],
	&pop3_login_inet_listeners_array[1]
};
static buffer_t pop3_login_inet_listeners_buf = {
	pop3_login_inet_listeners, sizeof(pop3_login_inet_listeners), { 0, }
};

/* </settings checks> */
struct service_settings pop3_login_service_settings = {
	.name = "pop3-login",
	.protocol = "pop3",
	.type = "login",
	.executable = "pop3-login",
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
	.inet_listeners = { { &pop3_login_inet_listeners_buf,
			      sizeof(pop3_login_inet_listeners[0]) } }
};

static const struct setting_define pop3_login_setting_defines[] = {
	SETTING_DEFINE_LIST_END
};

static const struct setting_parser_info *pop3_login_setting_dependencies[] = {
	&login_setting_parser_info,
	NULL
};

const struct setting_parser_info pop3_login_setting_parser_info = {
	.module_name = "pop3-login",
	.defines = pop3_login_setting_defines,

	.type_offset = (size_t)-1,
	.parent_offset = (size_t)-1,

	.dependencies = pop3_login_setting_dependencies
};

const struct setting_parser_info *pop3_login_setting_roots[] = {
	&login_setting_parser_info,
	&pop3_login_setting_parser_info,
	NULL
};
