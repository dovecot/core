/* Copyright (c) 2011-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"

#include <stddef.h>

/* <settings checks> */
static struct file_listener_settings indexer_worker_unix_listeners_array[] = {
	{ "indexer-worker", 0600, "$default_internal_user", "" }
};
static struct file_listener_settings *indexer_worker_unix_listeners[] = {
	&indexer_worker_unix_listeners_array[0]
};
static buffer_t indexer_worker_unix_listeners_buf = {
	indexer_worker_unix_listeners, sizeof(indexer_worker_unix_listeners), { 0, }
};
/* </settings checks> */

struct service_settings indexer_worker_service_settings = {
	.name = "indexer-worker",
	.protocol = "",
	.type = "",
	.executable = "indexer-worker",
	.user = "",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 10,
	.client_limit = 1,
	.service_count = 0,
	.idle_kill = 0,
	.vsz_limit = (uoff_t)-1,

	.unix_listeners = { { &indexer_worker_unix_listeners_buf,
			      sizeof(indexer_worker_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
