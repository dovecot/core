/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "login-settings.h"
#include "pop3-login-settings.h"

#include <stddef.h>

struct service_settings pop3_login_service_settings = {
	.name = "pop3-login",
	.protocol = "pop3",
	.type = "login",
	.executable = "pop3-login",
	.user = "dovecot",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "login",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 0,
	.client_limit = 0,
	.service_count = 1,
	.vsz_limit = 64,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
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
