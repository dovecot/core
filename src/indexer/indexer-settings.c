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
	.user = "$SET:default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = ARRAY_INIT,
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_limit = 1,

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
