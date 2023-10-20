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
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_limit = 10,
	.client_limit = 1,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

const struct setting_keyvalue indexer_worker_service_settings_defaults[] = {
	{ "unix_listener", "indexer-worker srv.indexer-worker\\s%{pid}" },

	{ "unix_listener/indexer-worker/path", "indexer-worker" },
	{ "unix_listener/indexer-worker/mode", "0600" },
	{ "unix_listener/indexer-worker/user", "$SET:default_internal_user" },

	{ "unix_listener/srv.indexer-worker\\s%{pid}/path", "srv.indexer-worker/%{pid}" },
	{ "unix_listener/srv.indexer-worker\\s%{pid}/type", "admin" },
	{ "unix_listener/srv.indexer-worker\\s%{pid}/mode", "0600" },

	{ "service_extra_groups", "$SET:default_internal_group" },

	{ NULL, NULL }
};
