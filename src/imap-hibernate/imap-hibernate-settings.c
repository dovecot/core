/* Copyright (c) 2014-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"

#include <stddef.h>
#include <unistd.h>

/* <settings checks> */
static struct file_listener_settings imap_hibernate_unix_listeners_array[] = {
	{ "imap-hibernate", 0600, "", "" }
};
static struct file_listener_settings *imap_hibernate_unix_listeners[] = {
	&imap_hibernate_unix_listeners_array[0]
};
static buffer_t imap_hibernate_unix_listeners_buf = {
	imap_hibernate_unix_listeners, sizeof(imap_hibernate_unix_listeners), { NULL, }
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
	.vsz_limit = (uoff_t)-1,

	.unix_listeners = { { &imap_hibernate_unix_listeners_buf,
			      sizeof(imap_hibernate_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
