/* Copyright (c) 2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "mail-storage-settings.h"
#include "imapc-settings.h"

#include <stddef.h>

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct imapc_settings, name), NULL }

static bool imapc_settings_check(void *_set, pool_t pool, const char **error_r);

static const struct setting_define imapc_setting_defines[] = {
	DEF(SET_STR, imapc_host),
	DEF(SET_UINT, imapc_port),

	DEF(SET_STR_VARS, imapc_user),
	DEF(SET_STR, imapc_password),

	DEF(SET_ENUM, imapc_ssl),
	DEF(SET_STR, imapc_ssl_ca_dir),
	DEF(SET_BOOL, imapc_ssl_verify),

	DEF(SET_STR, imapc_rawlog_dir),

	SETTING_DEFINE_LIST_END
};

static const struct imapc_settings imapc_default_settings = {
	.imapc_host = "",
	.imapc_port = 143,

	.imapc_user = "%u",
	.imapc_password = "",

	.imapc_ssl = "no:imaps:starttls",
	.imapc_ssl_ca_dir = "",
	.imapc_ssl_verify = TRUE,

	.imapc_rawlog_dir = ""
};

static const struct setting_parser_info imapc_setting_parser_info = {
	.module_name = "imapc",
	.defines = imapc_setting_defines,
	.defaults = &imapc_default_settings,

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct imapc_settings),

	.parent_offset = (size_t)-1,
	.parent = &mail_user_setting_parser_info,

	.check_func = imapc_settings_check
};

const struct setting_parser_info *imapc_get_setting_parser_info(void)
{
	return &imapc_setting_parser_info;
}

/* <settings checks> */
static bool imapc_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				 const char **error_r)
{
	struct imapc_settings *set = _set;

	if (set->imapc_port == 0 || set->imapc_port > 65535) {
		*error_r = "invalid imapc_port";
		return FALSE;
	}
#ifndef CONFIG_BINARY
	if (*set->imapc_ssl_ca_dir != '\0' &&
	    access(set->imapc_ssl_ca_dir, X_OK) < 0) {
		*error_r = t_strdup_printf(
			"imapc_ssl_ca_dir: access(%s) failed: %m",
			set->imapc_ssl_ca_dir);
		return FALSE;
	}
#endif
	return TRUE;
}
