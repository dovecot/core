/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "login-settings.h"
#include "imap-login-settings.h"

#include <stddef.h>

struct service_settings imap_login_service_settings = {
	.name = "imap-login",
	.protocol = "imap",
	.type = "login",
	.executable = "imap-login",
	.user = "dovecot",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "login",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 0,
	.client_limit = 0,
	.service_count = 1,
	.vsz_limit = 64,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct imap_login_settings, name), NULL }

static const struct setting_define imap_login_setting_defines[] = {
	DEF(SET_STR, imap_capability),

	SETTING_DEFINE_LIST_END
};

static const struct imap_login_settings imap_login_default_settings = {
	.imap_capability = ""
};

static const struct setting_parser_info *imap_login_setting_dependencies[] = {
	&login_setting_parser_info,
	NULL
};

static const struct setting_parser_info imap_login_setting_parser_info = {
	.module_name = "imap-login",
	.defines = imap_login_setting_defines,
	.defaults = &imap_login_default_settings,

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct imap_login_settings),

	.parent_offset = (size_t)-1,
	.dependencies = imap_login_setting_dependencies
};

const struct setting_parser_info *imap_login_setting_roots[] = {
	&login_setting_parser_info,
	&imap_login_setting_parser_info,
	NULL
};
