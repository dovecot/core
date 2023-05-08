/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"

struct service_settings indexer_worker_service_settings = {
	.name = "indexer-worker",
	.protocol = "",
	.type = "worker",
	.executable = "indexer-worker",
	.user = "",
	.group = "",
	.privileged_group = "",
	.extra_groups = "$default_internal_group",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 10,
	.client_limit = 1,
	.service_count = 0,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

const struct setting_keyvalue indexer_worker_service_settings_defaults[] = {
	{ "unix_listener", "indexer-worker srv.indexer-worker\\s%{pid}" },

	{ "unix_listener/indexer-worker/path", "indexer-worker" },
	{ "unix_listener/indexer-worker/mode", "0600" },
	{ "unix_listener/indexer-worker/user", "$default_internal_user" },

	{ "unix_listener/srv.indexer-worker\\s%{pid}/path", "srv.indexer-worker/%{pid}" },
	{ "unix_listener/srv.indexer-worker\\s%{pid}/type", "admin" },
	{ "unix_listener/srv.indexer-worker\\s%{pid}/mode", "0600" },

	{ NULL, NULL }
};
