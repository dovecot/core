/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "service-settings.h"

#include <stddef.h>

struct service_settings log_service_settings = {
	.name = "log",
	.protocol = "",
	.type = "log",
	.executable = "log",
	.user = "",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 1,
	.client_limit = 0,
	.service_count = 0,
	.idle_kill = 0,
	.vsz_limit = (uoff_t)-1,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT,

	.process_limit_1 = TRUE
};

