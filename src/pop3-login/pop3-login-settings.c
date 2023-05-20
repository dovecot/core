/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "login-settings.h"
#include "pop3-protocol.h"

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
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT,
};

const struct setting_keyvalue pop3_login_service_settings_defaults[] = {
	{ "unix_listener", "srv.pop3-login\\s%{pid}" },

	{ "unix_listener/srv.pop3-login\\s%{pid}/path", "srv.pop3-login/%{pid}" },
	{ "unix_listener/srv.pop3-login\\s%{pid}/type", "admin" },
	{ "unix_listener/srv.pop3-login\\s%{pid}/mode", "0600" },

	{ "inet_listener", "pop3 pop3s" },

	{ "inet_listener/pop3/name", "pop3" },
	{ "inet_listener/pop3/port", "110" },

	{ "inet_listener/pop3s/name", "pop3s" },
	{ "inet_listener/pop3s/port", "995" },
	{ "inet_listener/pop3s/ssl", "yes" },

	{ NULL, NULL }
};

static const struct setting_define pop3_login_setting_defines[] = {
	SETTING_DEFINE_LIST_END
};

const struct setting_parser_info pop3_login_setting_parser_info = {
	.name = "pop3_login",

	.defines = pop3_login_setting_defines,
};
