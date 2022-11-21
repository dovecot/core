/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"

#include <stddef.h>
#include <unistd.h>

/* <settings checks> */
static struct file_listener_settings imap_hibernate_unix_listeners_array[] = {
	{
		.path = "imap-hibernate",
		.mode = 0660,
		.user = "",
		.group = "$default_internal_group",
	},
	{
		.path = "srv.imap-hibernate/%{pid}",
		.type = "admin",
		.mode = 0600,
		.user = "",
		.group = "",
	},
};
static struct file_listener_settings *imap_hibernate_unix_listeners[] = {
	&imap_hibernate_unix_listeners_array[0],
	&imap_hibernate_unix_listeners_array[1],
};
static buffer_t imap_hibernate_unix_listeners_buf = {
	{ { imap_hibernate_unix_listeners, sizeof(imap_hibernate_unix_listeners) } }
};
/* </settings checks> */

struct service_settings imap_hibernate_service_settings = {
	.name = "imap-hibernate",
	.protocol = "imap",
	.type = "",
	.executable = "imap-hibernate",
	.user = "$default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 0,
	.client_limit = 0,
	.service_count = 0,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = { { &imap_hibernate_unix_listeners_buf,
			      sizeof(imap_hibernate_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
