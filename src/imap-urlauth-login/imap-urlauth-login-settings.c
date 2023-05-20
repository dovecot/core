/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "login-settings.h"

struct service_settings imap_urlauth_login_service_settings = {
	.name = "imap-urlauth-login",
	.protocol = "imap",
	.type = "login",
	.executable = "imap-urlauth-login",
	.user = "$default_login_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "token-login",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 0,
	.client_limit = 0,
	.service_count = 1,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

const struct setting_keyvalue imap_urlauth_login_service_settings_defaults[] = {
	{ "unix_listener", "imap-urlauth" },

	{ "unix_listener/imap-urlauth/path", "imap-urlauth" },
	{ "unix_listener/imap-urlauth/mode", "0666" },

	{ NULL, NULL }
};

static const struct setting_define imap_urlauth_login_setting_defines[] = {
	SETTING_DEFINE_LIST_END
};

const struct setting_parser_info imap_urlauth_login_setting_parser_info = {
	.name = "imap_urlauth_login",

	.defines = imap_urlauth_login_setting_defines,
};
