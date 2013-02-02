/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "mail-storage-settings.h"
#include "imap-urlauth-worker-settings.h"

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

/* <settings checks> */
static struct file_listener_settings imap_urlauth_worker_unix_listeners_array[] = {
	{ "imap-urlauth-worker", 0600, "$default_internal_user", "" }
};
static struct file_listener_settings *imap_urlauth_worker_unix_listeners[] = {
	&imap_urlauth_worker_unix_listeners_array[0]
};
static buffer_t imap_urlauth_worker_unix_listeners_buf = {
	imap_urlauth_worker_unix_listeners, sizeof(imap_urlauth_worker_unix_listeners), { 0, }
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
	.extra_groups = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 1024,
	.client_limit = 1,
	.service_count = 1,
	.idle_kill = 0,
	.vsz_limit = (uoff_t)-1,

	.unix_listeners = { { &imap_urlauth_worker_unix_listeners_buf,
			      sizeof(imap_urlauth_worker_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct imap_urlauth_worker_settings, name), NULL }

static const struct setting_define imap_urlauth_worker_setting_defines[] = {
	DEF(SET_BOOL, verbose_proctitle),

	DEF(SET_STR, imap_urlauth_host),
	DEF(SET_UINT, imap_urlauth_port),

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

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct imap_urlauth_worker_settings),

	.parent_offset = (size_t)-1,

	.dependencies = imap_urlauth_worker_setting_dependencies
};
