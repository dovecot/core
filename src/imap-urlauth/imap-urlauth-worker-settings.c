/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "master-service-settings.h"
#include "service-settings.h"
#include "mail-storage-settings.h"
#include "imap-urlauth-worker-common.h"
#include "imap-urlauth-worker-settings.h"

#include <unistd.h>

struct service_settings imap_urlauth_worker_service_settings = {
	.name = "imap-urlauth-worker",
	.protocol = "imap",
	.type = "",
	.executable = "imap-urlauth-worker",
	.user = "",
	.group = "",
	.privileged_group = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_limit = 1024,
	.client_limit = 1,
	.restart_request_count = 1,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

const struct setting_keyvalue imap_urlauth_worker_service_settings_defaults[] = {
	{ "unix_listener", IMAP_URLAUTH_WORKER_SOCKET },

	{ "unix_listener/"IMAP_URLAUTH_WORKER_SOCKET"/path", IMAP_URLAUTH_WORKER_SOCKET },
	{ "unix_listener/"IMAP_URLAUTH_WORKER_SOCKET"/mode", "0600" },
	{ "unix_listener/"IMAP_URLAUTH_WORKER_SOCKET"/user", "$SET:default_internal_user" },

	{ "service_extra_groups", "$SET:default_internal_group" },

	{ NULL, NULL }
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
	.verbose_proctitle = VERBOSE_PROCTITLE_DEFAULT,

	.imap_urlauth_host = "",
	.imap_urlauth_port = 143
};

const struct setting_parser_info imap_urlauth_worker_setting_parser_info = {
	.name = "imap_urlauth_worker",

	.defines = imap_urlauth_worker_setting_defines,
	.defaults = &imap_urlauth_worker_default_settings,

	.struct_size = sizeof(struct imap_urlauth_worker_settings),
	.pool_offset1 = 1 + offsetof(struct imap_urlauth_worker_settings, pool),
};
