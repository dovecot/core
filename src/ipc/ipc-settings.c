/* Copyright (c) 2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"

#include <stddef.h>

/* <settings checks> */
static struct file_listener_settings ipc_unix_listeners_array[] = {
	{ "ipc", 0600, "", "" },
	{ "login/ipc-proxy", 0600, "$default_login_user", "" }
};
static struct file_listener_settings *ipc_unix_listeners[] = {
	&ipc_unix_listeners_array[0],
	&ipc_unix_listeners_array[1]
};
static buffer_t ipc_unix_listeners_buf = {
	ipc_unix_listeners, sizeof(ipc_unix_listeners), { 0, }
};
/* </settings checks> */

struct service_settings ipc_service_settings = {
	.name = "ipc",
	.protocol = "",
	.type = "",
	.executable = "ipc",
	.user = "$default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "empty",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 1,
	.client_limit = 0,
	.service_count = 0,
	.idle_kill = 0,
	.vsz_limit = (uoff_t)-1,

	.unix_listeners = { { &ipc_unix_listeners_buf,
			      sizeof(ipc_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
