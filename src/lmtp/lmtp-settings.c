/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "master-service-settings.h"
#include "lda-settings.h"
#include "lmtp-settings.h"

#include <stddef.h>
#include <unistd.h>

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct lmtp_settings, name), NULL }

static struct setting_define lmtp_setting_defines[] = {
	DEF(SET_BOOL, lmtp_proxy),

	SETTING_DEFINE_LIST_END
};

static struct lmtp_settings lmtp_default_settings = {
	MEMBER(lmtp_proxy) FALSE
};

static struct setting_parser_info *lmtp_setting_dependencies[] = {
	&lda_setting_parser_info,
	NULL
};

struct setting_parser_info lmtp_setting_parser_info = {
	MEMBER(module_name) "lmtp",
	MEMBER(defines) lmtp_setting_defines,
	MEMBER(defaults) &lmtp_default_settings,

	MEMBER(type_offset) (size_t)-1,
	MEMBER(struct_size) sizeof(struct lmtp_settings),

	MEMBER(parent_offset) (size_t)-1,
	MEMBER(parent) NULL,

	MEMBER(check_func) NULL,
	MEMBER(dependencies) lmtp_setting_dependencies
};
