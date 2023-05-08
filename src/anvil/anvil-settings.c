/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"

struct service_settings anvil_service_settings = {
	.name = "anvil",
	.protocol = "",
	.type = "anvil",
	.executable = "anvil",
	.user = "",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 1,
	.process_limit = 1,
	.client_limit = 0,
	.service_count = 0,
	.idle_kill = UINT_MAX,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT,

	.process_limit_1 = TRUE
};

const struct setting_keyvalue anvil_service_settings_defaults[] = {
	{ "unix_listener", "anvil anvil-auth-penalty" },

	{ "unix_listener/anvil/path", "anvil" },
	{ "unix_listener/anvil/mode", "0600" },

	{ "unix_listener/anvil-auth-penalty/path", "anvil-auth-penalty" },
	{ "unix_listener/anvil-auth-penalty/mode", "0600" },

	{ NULL, NULL }
};
