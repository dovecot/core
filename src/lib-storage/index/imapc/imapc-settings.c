/* Copyright (c) 2011-2016 Dovecot authors, see the included COPYING file */

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
	DEF(SET_IN_PORT, imapc_port),

	DEF(SET_STR_VARS, imapc_user),
	DEF(SET_STR_VARS, imapc_master_user),
	DEF(SET_STR, imapc_password),
	DEF(SET_STR, imapc_sasl_mechanisms),

	DEF(SET_ENUM, imapc_ssl),
	DEF(SET_BOOL, imapc_ssl_verify),

	DEF(SET_STR, imapc_features),
	DEF(SET_STR, imapc_rawlog_dir),
	DEF(SET_STR, imapc_list_prefix),
	DEF(SET_TIME, imapc_cmd_timeout),
	DEF(SET_TIME, imapc_max_idle_time),
	DEF(SET_SIZE, imapc_max_line_length),

	DEF(SET_STR, pop3_deleted_flag),

	SETTING_DEFINE_LIST_END
};

static const struct imapc_settings imapc_default_settings = {
	.imapc_host = "",
	.imapc_port = 143,

	.imapc_user = "",
	.imapc_master_user = "",
	.imapc_password = "",
	.imapc_sasl_mechanisms = "",

	.imapc_ssl = "no:imaps:starttls",
	.imapc_ssl_verify = TRUE,

	.imapc_features = "",
	.imapc_rawlog_dir = "",
	.imapc_list_prefix = "",
	.imapc_cmd_timeout = 5*60,
	.imapc_max_idle_time = 60*29,
	.imapc_max_line_length = 0,

	.pop3_deleted_flag = ""
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
struct imapc_feature_list {
	const char *name;
	enum imapc_features num;
};

static const struct imapc_feature_list imapc_feature_list[] = {
	{ "rfc822.size", IMAPC_FEATURE_RFC822_SIZE },
	{ "guid-forced", IMAPC_FEATURE_GUID_FORCED },
	{ "fetch-headers", IMAPC_FEATURE_FETCH_HEADERS },
	{ "gmail-migration", IMAPC_FEATURE_GMAIL_MIGRATION },
	{ "search", IMAPC_FEATURE_SEARCH },
	{ "zimbra-workarounds", IMAPC_FEATURE_ZIMBRA_WORKAROUNDS },
	{ "no-examine", IMAPC_FEATURE_NO_EXAMINE },
	{ "proxyauth", IMAPC_FEATURE_PROXYAUTH },
	{ "fetch-msn-workarounds", IMAPC_FEATURE_FETCH_MSN_WORKAROUNDS },
	{ "fetch-fix-broken-mails", IMAPC_FEATURE_FETCH_FIX_BROKEN_MAILS },
	{ "modseq", IMAPC_FEATURE_MODSEQ },
	{ NULL, 0 }
};

static int
imapc_settings_parse_throttle(struct imapc_settings *set,
			      const char *throttle_str, const char **error_r)
{
	const char *const *tmp;

	tmp = t_strsplit(throttle_str, ":");
	if (str_array_length(tmp) != 3 ||
	    str_to_uint(tmp[0], &set->throttle_init_msecs) < 0 ||
	    str_to_uint(tmp[1], &set->throttle_max_msecs) < 0 ||
	    str_to_uint(tmp[2], &set->throttle_shrink_min_msecs) < 0) {
		*error_r = "imapc_features: Invalid throttle settings";
		return -1;
	}
	return 0;
}

static int
imapc_settings_parse_features(struct imapc_settings *set,
			      const char **error_r)
{
        enum imapc_features features = 0;
        const struct imapc_feature_list *list;
	const char *const *str;

        str = t_strsplit_spaces(set->imapc_features, " ,");
	for (; *str != NULL; str++) {
		list = imapc_feature_list;
		for (; list->name != NULL; list++) {
			if (strcasecmp(*str, list->name) == 0) {
				features |= list->num;
				break;
			}
		}
		if (strncasecmp(*str, "throttle:", 9) == 0) {
			if (imapc_settings_parse_throttle(set, *str + 9, error_r) < 0)
				return -1;
			continue;
		}
		if (list->name == NULL) {
			*error_r = t_strdup_printf("imapc_features: "
				"Unknown feature: %s", *str);
			return -1;
		}
	}
	set->parsed_features = features;
	return 0;
}

static bool imapc_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				 const char **error_r)
{
	struct imapc_settings *set = _set;

	if (set->imapc_max_idle_time == 0) {
		*error_r = "imapc_max_idle_time must not be 0";
		return FALSE;
	}
	if (imapc_settings_parse_features(set, error_r) < 0)
		return FALSE;
	return TRUE;
}
