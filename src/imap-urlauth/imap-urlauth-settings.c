/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "master-service-settings.h"
#include "service-settings.h"
#include "imap-urlauth-settings.h"

#include <unistd.h>

struct service_settings imap_urlauth_service_settings = {
	.name = "imap-urlauth",
	.protocol = "imap",
	.type = "",
	.executable = "imap-urlauth",
	.user = "$SET:default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = ARRAY_INIT,
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_limit = 1024,
	.client_limit = 1,
	.restart_request_count = 1,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

const struct setting_keyvalue imap_urlauth_service_settings_defaults[] = {
	{ "unix_listener", "token-login\\simap-urlauth" },

	{ "unix_listener/token-login\\simap-urlauth/path", "token-login/imap-urlauth" },
	{ "unix_listener/token-login\\simap-urlauth/mode", "0666" },

	{ NULL, NULL }
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct imap_urlauth_settings)

static const struct setting_define imap_urlauth_setting_defines[] = {
	DEF(STR_HIDDEN, base_dir),

	DEF(BOOL, mail_debug),

	DEF(BOOL, verbose_proctitle),

	DEF(STR_NOVARS, imap_urlauth_logout_format),
	DEF(STR, imap_urlauth_submit_user),
	DEF(STR, imap_urlauth_stream_user),

	SETTING_DEFINE_LIST_END
};

const struct imap_urlauth_settings imap_urlauth_default_settings = {
	.base_dir = PKG_RUNDIR,
  .mail_debug = FALSE,

	.verbose_proctitle = VERBOSE_PROCTITLE_DEFAULT,

	.imap_urlauth_logout_format = "in=%{input} out=%{output}",
	.imap_urlauth_submit_user = "",
	.imap_urlauth_stream_user = "",
};

const struct setting_parser_info imap_urlauth_setting_parser_info = {
	.name = "imap_urlauth",

	.defines = imap_urlauth_setting_defines,
	.defaults = &imap_urlauth_default_settings,

	.struct_size = sizeof(struct imap_urlauth_settings),
	.pool_offset1 = 1 + offsetof(struct imap_urlauth_settings, pool),
};
