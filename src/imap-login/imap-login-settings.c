/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "login-settings.h"
#include "imap-login-settings.h"

#include <stddef.h>

struct service_settings imap_login_service_settings = {
	MEMBER(name) "imap-login",
	MEMBER(protocol) "imap",
	MEMBER(type) "login",
	MEMBER(executable) "imap-login",
	MEMBER(user) "dovecot",
	MEMBER(group) "",
	MEMBER(privileged_group) "",
	MEMBER(extra_groups) "",
	MEMBER(chroot) "login",

	MEMBER(drop_priv_before_exec) FALSE,

	MEMBER(process_min_avail) 0,
	MEMBER(process_limit) 0,
	MEMBER(client_limit) 0,
	MEMBER(service_count) 1,
	MEMBER(vsz_limit) 64,

	MEMBER(unix_listeners) ARRAY_INIT,
	MEMBER(fifo_listeners) ARRAY_INIT,
	MEMBER(inet_listeners) ARRAY_INIT
};

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct imap_login_settings, name), NULL }

static const struct setting_define imap_login_setting_defines[] = {
	DEF(SET_STR, imap_capability),

	SETTING_DEFINE_LIST_END
};

static const struct imap_login_settings imap_login_default_settings = {
	MEMBER(imap_capability) ""
};

static const struct setting_parser_info *imap_login_setting_dependencies[] = {
	&login_setting_parser_info,
	NULL
};

static const struct setting_parser_info imap_login_setting_parser_info = {
	MEMBER(module_name) "imap-login",
	MEMBER(defines) imap_login_setting_defines,
	MEMBER(defaults) &imap_login_default_settings,

	MEMBER(type_offset) (size_t)-1,
	MEMBER(struct_size) sizeof(struct imap_login_settings),

	MEMBER(parent_offset) (size_t)-1,
	MEMBER(parent) NULL,

	MEMBER(check_func) NULL,
	MEMBER(dependencies) imap_login_setting_dependencies
};

const struct setting_parser_info *imap_login_setting_roots[] = {
	&login_setting_parser_info,
	&imap_login_setting_parser_info,
	NULL
};
