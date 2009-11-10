/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"

#include <stddef.h>

/* <settings checks> */
static struct file_listener_settings anvil_unix_listeners_array[] = {
	{ "anvil", 0600, "", "" },
	{ "anvil-auth-penalty", 0600, "", "" }
};
static struct file_listener_settings *anvil_unix_listeners[] = {
	&anvil_unix_listeners_array[0],
	&anvil_unix_listeners_array[1]
};
static buffer_t anvil_unix_listeners_buf = {
	anvil_unix_listeners, sizeof(anvil_unix_listeners), { 0, }
};
/* </settings checks> */

struct service_settings anvil_service_settings = {
	MEMBER(name) "anvil",
	MEMBER(protocol) "",
	MEMBER(type) "anvil",
	MEMBER(executable) "anvil",
	MEMBER(user) "dovecot",
	MEMBER(group) "",
	MEMBER(privileged_group) "",
	MEMBER(extra_groups) "",
	MEMBER(chroot) "empty",

	MEMBER(drop_priv_before_exec) FALSE,

	MEMBER(process_min_avail) 1,
	MEMBER(process_limit) 1,
	MEMBER(client_limit) 0,
	MEMBER(service_count) 0,
	MEMBER(vsz_limit) -1U,

	MEMBER(unix_listeners) { { &anvil_unix_listeners_buf,
				   sizeof(anvil_unix_listeners[0]) } },
	MEMBER(fifo_listeners) ARRAY_INIT,
	MEMBER(inet_listeners) ARRAY_INIT
};
