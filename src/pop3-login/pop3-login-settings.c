/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "login-settings.h"
#include "pop3-login-settings.h"

#include <stddef.h>

static const struct setting_define pop3_login_setting_defines[] = {
	SETTING_DEFINE_LIST_END
};

static const struct setting_parser_info *pop3_login_setting_dependencies[] = {
	&login_setting_parser_info,
	NULL
};

const struct setting_parser_info pop3_login_setting_parser_info = {
	MEMBER(module_name) "pop3-login",
	MEMBER(defines) pop3_login_setting_defines,
	MEMBER(defaults) NULL,

	MEMBER(type_offset) (size_t)-1,
	MEMBER(struct_size) 0,

	MEMBER(parent_offset) (size_t)-1,
	MEMBER(parent) NULL,

	MEMBER(check_func) NULL,
	MEMBER(dependencies) pop3_login_setting_dependencies
};

const struct setting_parser_info *pop3_login_setting_roots[] = {
	&login_setting_parser_info,
	&pop3_login_setting_parser_info,
	NULL
};
