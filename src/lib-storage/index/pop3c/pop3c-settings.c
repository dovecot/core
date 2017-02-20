/* Copyright (c) 2011-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "mail-storage-settings.h"
#include "pop3c-settings.h"

#include <stddef.h>

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct pop3c_settings, name), NULL }

static const struct setting_define pop3c_setting_defines[] = {
	DEF(SET_STR, pop3c_host),
	DEF(SET_IN_PORT, pop3c_port),

	DEF(SET_STR_VARS, pop3c_user),
	DEF(SET_STR_VARS, pop3c_master_user),
	DEF(SET_STR, pop3c_password),

	DEF(SET_ENUM, pop3c_ssl),
	DEF(SET_BOOL, pop3c_ssl_verify),

	DEF(SET_STR, pop3c_rawlog_dir),
	DEF(SET_BOOL, pop3c_quick_received_date),

	DEF(SET_STR, pop3c_features),

	SETTING_DEFINE_LIST_END
};

static const struct pop3c_settings pop3c_default_settings = {
	.pop3c_host = "",
	.pop3c_port = 110,

	.pop3c_user = "%u",
	.pop3c_master_user = "",
	.pop3c_password = "",

	.pop3c_ssl = "no:pop3s:starttls",
	.pop3c_ssl_verify = TRUE,

	.pop3c_rawlog_dir = "",
	.pop3c_quick_received_date = FALSE,

	.pop3c_features = ""
};

/* <settings checks> */
struct pop3c_feature_list {
	const char *name;
	enum pop3c_features num;
};

static const struct pop3c_feature_list pop3c_feature_list[] = {
	{ "no-pipelining", POP3C_FEATURE_NO_PIPELINING },
	{ NULL, 0 }
};

static int
pop3c_settings_parse_features(struct pop3c_settings *set,
			      const char **error_r)
{
	enum pop3c_features features = 0;
	const struct pop3c_feature_list *list;
	const char *const *str;

	str = t_strsplit_spaces(set->pop3c_features, " ,");
	for (; *str != NULL; str++) {
		list = pop3c_feature_list;
		for (; list->name != NULL; list++) {
			if (strcasecmp(*str, list->name) == 0) {
				features |= list->num;
				break;
			}
		}
		if (list->name == NULL) {
			*error_r = t_strdup_printf("pop3c_features: "
				"Unknown feature: %s", *str);
			return -1;
		}
	}
	set->parsed_features = features;
	return 0;
}

static bool pop3c_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				 const char **error_r)
{
	struct pop3c_settings *set = _set;

	if (pop3c_settings_parse_features(set, error_r) < 0)
		return FALSE;
	return TRUE;
}
/* </settings checks> */

static const struct setting_parser_info pop3c_setting_parser_info = {
	.module_name = "pop3c",
	.defines = pop3c_setting_defines,
	.defaults = &pop3c_default_settings,

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct pop3c_settings),

	.parent_offset = (size_t)-1,
	.parent = &mail_user_setting_parser_info,

        .check_func = pop3c_settings_check
};

const struct setting_parser_info *pop3c_get_setting_parser_info(void)
{
	return &pop3c_setting_parser_info;
}
