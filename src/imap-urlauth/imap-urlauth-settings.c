/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "imap-urlauth-settings.h"

#include <stddef.h>
#include <unistd.h>

/* <settings checks> */
static struct file_listener_settings imap_urlauth_unix_listeners_array[] = {
	{
		.path = "token-login/imap-urlauth",
		.mode = 0666,
		.user = "",
		.group = "",
	},
};
static struct file_listener_settings *imap_urlauth_unix_listeners[] = {
	&imap_urlauth_unix_listeners_array[0]
};
static buffer_t imap_urlauth_unix_listeners_buf = {
	{ { imap_urlauth_unix_listeners, sizeof(imap_urlauth_unix_listeners) } }
};
/* </settings checks> */

struct service_settings imap_urlauth_service_settings = {
	.name = "imap-urlauth",
	.protocol = "imap",
	.type = "",
	.executable = "imap-urlauth",
	.user = "$default_internal_user",
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
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = { { &imap_urlauth_unix_listeners_buf,
			      sizeof(imap_urlauth_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct imap_urlauth_settings)

static const struct setting_define imap_urlauth_setting_defines[] = {
	DEF(STR, base_dir),

	DEF(BOOL, mail_debug),

	DEF(BOOL, verbose_proctitle),

	DEF(STR, imap_urlauth_logout_format),
	DEF(STR, imap_urlauth_submit_user),
	DEF(STR, imap_urlauth_stream_user),

	SETTING_DEFINE_LIST_END
};

const struct imap_urlauth_settings imap_urlauth_default_settings = {
	.base_dir = PKG_RUNDIR,
  .mail_debug = FALSE,

	.verbose_proctitle = FALSE,

	.imap_urlauth_logout_format = "in=%i out=%o",
	.imap_urlauth_submit_user = NULL,
	.imap_urlauth_stream_user = NULL
};

static const struct setting_parser_info *imap_urlauth_setting_dependencies[] = {
	NULL
};

const struct setting_parser_info imap_urlauth_setting_parser_info = {
	.module_name = "imap-urlauth",
	.defines = imap_urlauth_setting_defines,
	.defaults = &imap_urlauth_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct imap_urlauth_settings),

	.parent_offset = SIZE_MAX,

	.dependencies = imap_urlauth_setting_dependencies
};
