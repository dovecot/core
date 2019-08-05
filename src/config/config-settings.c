/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"

#include <stddef.h>

/* <settings checks> */
static struct file_listener_settings config_unix_listeners_array[] = {
	{
		.path = "config",
		.mode = 0600,
		.user = "",
		.group = "",
	},
};
static struct file_listener_settings *config_unix_listeners[] = {
	&config_unix_listeners_array[0]
};
static buffer_t config_unix_listeners_buf = {
	{ { config_unix_listeners, sizeof(config_unix_listeners) } }
};
/* </settings checks> */

struct service_settings config_service_settings = {
	.name = "config",
	.protocol = "",
	.type = "config",
	.executable = "config",
	.user = "",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 0,
	.client_limit = 0,
	.service_count = 0,
	.idle_kill = UINT_MAX,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = { { &config_unix_listeners_buf,
			      sizeof(config_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
