/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"

struct service_settings indexer_service_settings = {
	.name = "indexer",
	.protocol = "",
	.type = "",
	.executable = "indexer",
	.user = "$default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 1,
	.client_limit = 0,
	.service_count = 0,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT,

	.process_limit_1 = TRUE
};

const struct setting_keyvalue indexer_service_settings_defaults[] = {
	{ "unix_listener", "indexer" },

	{ "unix_listener/indexer/path", "indexer" },
	{ "unix_listener/indexer/mode", "0666" },

	{ NULL, NULL }
};
