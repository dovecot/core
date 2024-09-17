/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"

struct service_settings config_service_settings = {
	.name = "config",
	.protocol = "",
	.type = "config",
	.executable = "config",
	.user = "",
	.group = "",
	.privileged_group = "",
	.extra_groups = ARRAY_INIT,
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.idle_kill_interval = SET_TIME_INFINITE,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

const struct setting_keyvalue config_service_settings_defaults[] = {
	{ "unix_listener", "config" },

	{ "unix_listener/config/path", "config" },
	{ "unix_listener/config/mode", "0600" },

	{ NULL, NULL }
};
