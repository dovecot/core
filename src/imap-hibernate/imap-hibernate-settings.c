/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "imap-hibernate-settings.h"

#include <unistd.h>

#ifdef BUILD_IMAP_HIBERNATE
struct service_settings imap_hibernate_service_settings = {
	.name = "imap-hibernate",
	.protocol = "imap",
	.type = "client",
	.executable = "imap-hibernate",
	.user = "$SET:default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = ARRAY_INIT,
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

const struct setting_keyvalue imap_hibernate_service_settings_defaults[] = {
	{ "unix_listener", "imap-hibernate srv.imap-hibernate\\s%{pid}" },

	{ "unix_listener/imap-hibernate/path", "imap-hibernate" },
	{ "unix_listener/imap-hibernate/mode", "0660" },
	{ "unix_listener/imap-hibernate/group", "$SET:default_internal_group" },

	{ "unix_listener/srv.imap-hibernate\\s%{pid}/path", "srv.imap-hibernate/%{pid}" },
	{ "unix_listener/srv.imap-hibernate\\s%{pid}/type", "admin" },
	{ "unix_listener/srv.imap-hibernate\\s%{pid}/mode", "0600" },

	{ NULL, NULL }
};
#endif

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct imap_hibernate_settings)

static const struct setting_define imap_hibernate_setting_defines[] = {
	DEF(BOOL, auth_debug_passwords),

	SETTING_DEFINE_LIST_END
};

static const struct imap_hibernate_settings imap_hibernate_default_settings = {
	.auth_debug_passwords = FALSE,
};

const struct setting_parser_info imap_hibernate_setting_parser_info = {
	.name = "imap_hibernate",

	.defines = imap_hibernate_setting_defines,
	.defaults = &imap_hibernate_default_settings,

	.struct_size = sizeof(struct imap_hibernate_settings),
	.pool_offset1 = 1 + offsetof(struct imap_hibernate_settings, pool),
};
