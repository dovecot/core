/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "mail-storage-settings.h"
#include "imap-urlauth-worker-common.h"
#include "imap-urlauth-worker-settings.h"

#include <stddef.h>
#include <unistd.h>

/* <settings checks> */
static struct file_listener_settings imap_urlauth_worker_unix_listeners_array[] = {
	{
		.path = IMAP_URLAUTH_WORKER_SOCKET,
		.mode = 0600,
		.user = "$default_internal_user",
		.group = "",
	},
};
static struct file_listener_settings *imap_urlauth_worker_unix_listeners[] = {
	&imap_urlauth_worker_unix_listeners_array[0]
};
static buffer_t imap_urlauth_worker_unix_listeners_buf = {
	{ { imap_urlauth_worker_unix_listeners,
	    sizeof(imap_urlauth_worker_unix_listeners) } }
};
/* </settings checks> */

struct service_settings imap_urlauth_worker_service_settings = {
	.name = "imap-urlauth-worker",
	.protocol = "imap",
	.type = "",
	.executable = "imap-urlauth-worker",
	.user = "",
	.group = "",
	.privileged_group = "",
	.extra_groups = "$default_internal_group",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 1024,
	.client_limit = 1,
	.service_count = 1,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = { { &imap_urlauth_worker_unix_listeners_buf,
			      sizeof(imap_urlauth_worker_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct imap_urlauth_worker_settings)

static const struct setting_define imap_urlauth_worker_setting_defines[] = {
	DEF(BOOL, verbose_proctitle),

	DEF(STR, imap_urlauth_host),
	DEF(IN_PORT, imap_urlauth_port),

	SETTING_DEFINE_LIST_END
};

const struct imap_urlauth_worker_settings imap_urlauth_worker_default_settings = {
	.verbose_proctitle = FALSE,

	.imap_urlauth_host = "",
	.imap_urlauth_port = 143
};

static const struct setting_parser_info *imap_urlauth_worker_setting_dependencies[] = {
	&mail_user_setting_parser_info,
	NULL
};

const struct setting_parser_info imap_urlauth_worker_setting_parser_info = {
	.module_name = "imap-urlauth-worker",
	.defines = imap_urlauth_worker_setting_defines,
	.defaults = &imap_urlauth_worker_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct imap_urlauth_worker_settings),

	.parent_offset = SIZE_MAX,

	.dependencies = imap_urlauth_worker_setting_dependencies
};
