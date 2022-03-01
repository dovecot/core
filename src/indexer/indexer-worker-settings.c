/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"

#include <stddef.h>

/* <settings checks> */
static struct file_listener_settings indexer_worker_unix_listeners_array[] = {
	{ "indexer-worker", 0600, "$default_internal_user", "" },
	{ "srv.indexer-worker/%{pid}", 0600, "", "" },
};
static struct file_listener_settings *indexer_worker_unix_listeners[] = {
	&indexer_worker_unix_listeners_array[0],
	&indexer_worker_unix_listeners_array[1],
};
static buffer_t indexer_worker_unix_listeners_buf = {
	{ { indexer_worker_unix_listeners, sizeof(indexer_worker_unix_listeners) } }
};
/* </settings checks> */

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

	.unix_listeners = { { &indexer_worker_unix_listeners_buf,
			      sizeof(indexer_worker_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
