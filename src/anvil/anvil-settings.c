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
	.extra_groups = ARRAY_INIT,
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 1,
	.process_limit = 1,
	.idle_kill_interval = SET_TIME_INFINITE,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT,

	.process_limit_1 = TRUE
};

const struct setting_keyvalue anvil_service_settings_defaults[] = {
	{ "unix_listener", "anvil anvil-auth-penalty anvil-connect-limit" },

	{ "unix_listener/anvil/path", "anvil" },
	{ "unix_listener/anvil/mode", "0660" },
	{ "unix_listener/anvil/group", "$SET:default_internal_group" },

	{ "unix_listener/anvil-auth-penalty/path", "anvil-auth-penalty" },
	{ "unix_listener/anvil-auth-penalty/type", "penalty" },
#ifdef DOVECOT_PRO_EDITION
	/* Should use OX Abuse Shield instead */
	{ "unix_listener/anvil-auth-penalty/mode", "0" },
#else
	{ "unix_listener/anvil-auth-penalty/mode", "0660" },
#endif
	{ "unix_listener/anvil-auth-penalty/group", "$SET:default_internal_group" },

	{ "unix_listener/anvil-connect-limit/path", "anvil-connect-limit" },
	{ "unix_listener/anvil-connect-limit/type", "connect-limit" },
	{ "unix_listener/anvil-connect-limit/mode", "0660" },
	{ "unix_listener/anvil-connect-limit/group", "$SET:default_internal_group" },

	{ NULL, NULL }
};
