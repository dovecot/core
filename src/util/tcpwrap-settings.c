/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"

#include <stddef.h>

#ifdef HAVE_LIBWRAP
struct service_settings tcpwrap_service_settings = {
	.name = "tcpwrap",
	.protocol = "",
	.type = "",
	.executable = "tcpwrap",
	.user = "$default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 0,
	.client_limit = 1,
	.service_count = 0,
	.idle_kill = 0,
	.vsz_limit = (uoff_t)-1,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
#endif
