/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "login-settings.h"
#include "imap-login-settings.h"

struct service_settings imap_login_service_settings = {
	.name = "imap-login",
	.protocol = "imap",
	.type = "login",
	.executable = "imap-login",
	.user = "$SET:default_login_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = ARRAY_INIT,
	.chroot = "login",

	.drop_priv_before_exec = FALSE,

#ifndef DOVECOT_PRO_EDITION
	.restart_request_count = 1,
#endif

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT,
};

const struct setting_keyvalue imap_login_service_settings_defaults[] = {
	{ "unix_listener", "srv.imap-login\\s%{pid}" },

	{ "unix_listener/srv.imap-login\\s%{pid}/path", "srv.imap-login/%{pid}" },
	{ "unix_listener/srv.imap-login\\s%{pid}/type", "admin" },
	{ "unix_listener/srv.imap-login\\s%{pid}/mode", "0600" },

	{ "inet_listener", "imap imaps" },

	{ "inet_listener/imap/name", "imap" },
	{ "inet_listener/imap/port", "143" },

	{ "inet_listener/imaps/name", "imaps" },
	{ "inet_listener/imaps/port", "993" },
	{ "inet_listener/imaps/ssl", "yes" },

	{ NULL, NULL }
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct imap_login_settings)

static const struct setting_define imap_login_setting_defines[] = {
	DEF(BOOLLIST, imap_capability),
	DEF(BOOL, imap_literal_minus),
	DEF(BOOL, imap_id_retain),

	{ .type = SET_STRLIST, .key = "imap_id_send",
	  .offset = offsetof(struct imap_login_settings, imap_id_send) },

	SETTING_DEFINE_LIST_END
};

static const struct imap_login_settings imap_login_default_settings = {
	.imap_capability = ARRAY_INIT,
	.imap_id_send = ARRAY_INIT,
	.imap_literal_minus = FALSE,
	.imap_id_retain = FALSE,
};

static const struct setting_keyvalue imap_login_default_settings_keyvalue[] = {
	{"service/imap-login/imap_capability/IMAP4rev1", "yes"},
	{"service/imap-login/imap_capability/LOGIN-REFERRALS", "yes"},
	{"service/imap-login/imap_capability/ID", "yes"},
	{"service/imap-login/imap_capability/ENABLE", "yes"},
	/* IDLE doesn't really belong to banner. It's there just to make
	   Blackberries happy, because otherwise BIS server disables push email. */
	{ "service/imap-login/imap_capability/IDLE", "yes" },
	{ "service/imap-login/imap_capability/SASL-IR", "yes" },
	{ "service/imap-login/imap_capability/LITERAL+", "yes" },
	{ "service/imap-login/imap_capability/LITERAL-", "yes" },
	{ "imap_id_send/name", DOVECOT_NAME },
#ifdef DOVECOT_PRO_EDITION
	{ "service/imap-login/service_process_limit", "%{system:cpu_count}" },
	{ "service/imap-login/service_process_min_avail", "%{system:cpu_count}" },
#endif
	{ NULL, NULL },
};

const struct setting_parser_info imap_login_setting_parser_info = {
	.name = "imap_login",

	.defines = imap_login_setting_defines,
	.defaults = &imap_login_default_settings,
	.default_settings = imap_login_default_settings_keyvalue,

	.struct_size = sizeof(struct imap_login_settings),
	.pool_offset1 = 1 + offsetof(struct imap_login_settings, pool),
};
