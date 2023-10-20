/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"

#include <unistd.h>

struct service_settings imap_hibernate_service_settings = {
	.name = "imap-hibernate",
	.protocol = "imap",
	.type = "",
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
