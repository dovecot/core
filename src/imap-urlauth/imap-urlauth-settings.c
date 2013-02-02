/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "imap-urlauth-settings.h"

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

/* <settings checks> */
static struct file_listener_settings imap_urlauth_unix_listeners_array[] = {
	{ "token-login/imap-urlauth", 0666, "", "" }
};
static struct file_listener_settings *imap_urlauth_unix_listeners[] = {
	&imap_urlauth_unix_listeners_array[0]
};
static buffer_t imap_urlauth_unix_listeners_buf = {
	imap_urlauth_unix_listeners, sizeof(imap_urlauth_unix_listeners), { 0, }
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
	.vsz_limit = (uoff_t)-1,

	.unix_listeners = { { &imap_urlauth_unix_listeners_buf,
			      sizeof(imap_urlauth_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct imap_urlauth_settings, name), NULL }

static const struct setting_define imap_urlauth_setting_defines[] = {
	DEF(SET_STR, base_dir),

	DEF(SET_BOOL, mail_debug),

	DEF(SET_BOOL, verbose_proctitle),

	DEF(SET_STR, imap_urlauth_logout_format),
	DEF(SET_STR, imap_urlauth_submit_user),
	DEF(SET_STR, imap_urlauth_stream_user),

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

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct imap_urlauth_settings),

	.parent_offset = (size_t)-1,

	.dependencies = imap_urlauth_setting_dependencies
};
