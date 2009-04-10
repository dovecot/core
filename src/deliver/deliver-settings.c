/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "deliver.h"
#include "array.h"
#include "hostpid.h"
#include "istream.h"
#include "settings-parser.h"
#include "mail-storage-settings.h"
#include "deliver-settings.h"

#include <stddef.h>
#include <stdlib.h>

static bool deliver_settings_check(void *_set, pool_t pool, const char **error_r);

#undef DEF
#undef DEFLIST
#define DEF(type, name) \
	{ type, #name, offsetof(struct deliver_settings, name), NULL }
#define DEFLIST(field, name, defines) \
	{ SET_DEFLIST, name, offsetof(struct deliver_settings, field), defines }

static struct setting_define deliver_setting_defines[] = {
	DEF(SET_STR, postmaster_address),
	DEF(SET_STR, hostname),
	DEF(SET_STR, sendmail_path),
	DEF(SET_STR, rejection_subject),
	DEF(SET_STR, rejection_reason),
	DEF(SET_STR, deliver_log_format),
	DEF(SET_BOOL, quota_full_tempfail),

	{ SET_STRLIST, "plugin", offsetof(struct deliver_settings, plugin_envs), NULL },

	SETTING_DEFINE_LIST_END
};

static struct deliver_settings deliver_default_settings = {
	MEMBER(postmaster_address) "",
	MEMBER(hostname) "",
	MEMBER(sendmail_path) "/usr/lib/sendmail",
	MEMBER(rejection_subject) "Rejected: %s",
	MEMBER(rejection_reason)
		"Your message to <%t> was automatically rejected:%n%r",
	MEMBER(deliver_log_format) "msgid=%m: %$",
	MEMBER(quota_full_tempfail) FALSE
};

struct setting_parser_info deliver_setting_parser_info = {
	MEMBER(defines) deliver_setting_defines,
	MEMBER(defaults) &deliver_default_settings,

	MEMBER(parent) NULL,
	MEMBER(dynamic_parsers) NULL,

	MEMBER(parent_offset) (size_t)-1,
	MEMBER(type_offset) (size_t)-1,
	MEMBER(struct_size) sizeof(struct deliver_settings),
#ifdef CONFIG_BINARY
	MEMBER(check_func) NULL
#else
	MEMBER(check_func) deliver_settings_check
#endif
};

static bool deliver_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				   const char **error_r)
{
	struct deliver_settings *set = _set;

	if (*set->postmaster_address == '\0') {
		*error_r = "postmaster_address setting not given";
		return FALSE;
	}
	return TRUE;
}
