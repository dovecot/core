/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "imapc-settings.h"

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct imapc_settings)

#undef DEF_MSECS
#define DEF_MSECS(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name##_msecs, struct imapc_settings)

#undef DEF_SECS
#define DEF_SECS(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name##_secs, struct imapc_settings)

static bool imapc_settings_check(void *_set, pool_t pool, const char **error_r);

static const struct setting_define imapc_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "imapc" },
	{ .type = SET_FILTER_NAME, .key = "layout_imapc" },
	DEF(STR, imapc_host),
	DEF(IN_PORT, imapc_port),

	DEF(STR, imapc_user),
	DEF(STR, imapc_master_user),
	DEF(STR, imapc_password),
	DEF(BOOLLIST, imapc_sasl_mechanisms),

	DEF(ENUM, imapc_ssl),

	DEF(BOOLLIST, imapc_features),
	DEF(STR, imapc_rawlog_dir),
	DEF(STR, imapc_list_prefix),
	DEF_SECS(TIME, imapc_cmd_timeout),
	DEF_SECS(TIME, imapc_max_idle_time),
	DEF_MSECS(TIME_MSECS, imapc_connection_timeout_interval),
	DEF(UINT, imapc_connection_retry_count),
	DEF_MSECS(TIME_MSECS, imapc_connection_retry_interval),
	DEF(SIZE, imapc_max_line_length),

	DEF(STR, pop3_deleted_flag),

	SETTING_DEFINE_LIST_END
};

static const struct imapc_settings imapc_default_settings = {
	.imapc_host = "",
	.imapc_port = 143,

	.imapc_user = "%{owner_user}",
	.imapc_master_user = "",
	.imapc_password = "",
	.imapc_sasl_mechanisms = ARRAY_INIT,

	.imapc_ssl = "no:imaps:starttls",

	.imapc_features = ARRAY_INIT,
	.imapc_rawlog_dir = "",
	.imapc_list_prefix = "",
	.imapc_cmd_timeout_secs = 5*60,
	.imapc_max_idle_time_secs = IMAPC_DEFAULT_MAX_IDLE_TIME,
	.imapc_connection_timeout_interval_msecs = 1000*30,
	.imapc_connection_retry_count = 1,
	.imapc_connection_retry_interval_msecs = 1000,
	.imapc_max_line_length = SET_SIZE_UNLIMITED,

	.pop3_deleted_flag = "",
};

static const struct setting_keyvalue imapc_default_settings_keyvalue[] = {
	{ "imapc/mailbox_list_layout", "imapc" },
	/* We want to have all imapc mailboxes accessible, so escape them if
	   necessary. */
	{ "layout_imapc/mailbox_list_visible_escape_char", "~" },
	{ "layout_imapc/mailbox_list_storage_escape_char", "%" },
	{ NULL, NULL }
};

const struct setting_parser_info imapc_setting_parser_info = {
	.name = "imapc",

	.defines = imapc_setting_defines,
	.defaults = &imapc_default_settings,
	.default_settings = imapc_default_settings_keyvalue,

	.struct_size = sizeof(struct imapc_settings),
	.pool_offset1 = 1 + offsetof(struct imapc_settings, pool),

	.check_func = imapc_settings_check
};

/* <settings checks> */
const struct imapc_capability_name imapc_capability_names[] = {
	{ "SASL-IR", IMAPC_CAPABILITY_SASL_IR },
	{ "LITERAL+", IMAPC_CAPABILITY_LITERALPLUS },
	{ "QRESYNC", IMAPC_CAPABILITY_QRESYNC },
	{ "IDLE", IMAPC_CAPABILITY_IDLE },
	{ "UIDPLUS", IMAPC_CAPABILITY_UIDPLUS },
	{ "AUTH=PLAIN", IMAPC_CAPABILITY_AUTH_PLAIN },
	{ "STARTTLS", IMAPC_CAPABILITY_STARTTLS },
	{ "X-GM-EXT-1", IMAPC_CAPABILITY_X_GM_EXT_1 },
	{ "CONDSTORE", IMAPC_CAPABILITY_CONDSTORE },
	{ "NAMESPACE", IMAPC_CAPABILITY_NAMESPACE },
	{ "UNSELECT", IMAPC_CAPABILITY_UNSELECT },
	{ "ESEARCH", IMAPC_CAPABILITY_ESEARCH },
	{ "WITHIN", IMAPC_CAPABILITY_WITHIN },
	{ "QUOTA", IMAPC_CAPABILITY_QUOTA },
	{ "ID", IMAPC_CAPABILITY_ID },
	{ "SAVEDATE", IMAPC_CAPABILITY_SAVEDATE },
	{ "METADATA", IMAPC_CAPABILITY_METADATA },
	{ "SORT", IMAPC_CAPABILITY_SORT },
	{ "ESORT", IMAPC_CAPABILITY_ESORT },
	{ "SORT=DISPLAY", IMAPC_CAPABILITY_SORT_DISPLAY },

	{ "IMAP4REV1", IMAPC_CAPABILITY_IMAP4REV1 },
	{ "IMAP4REV2", IMAPC_CAPABILITY_IMAP4REV2 },
	{ NULL, 0 }
};

enum imapc_capability imapc_capability_lookup(const char *str)
{
	for (unsigned int i = 0; imapc_capability_names[i].name != NULL; i++) {
		if (strcasecmp(imapc_capability_names[i].name, str) == 0)
			return imapc_capability_names[i].capability;
	}
	return 0;
}

struct imapc_feature_list {
	const char *name;
	enum imapc_features num;
};

static const struct imapc_feature_list imapc_feature_list[] = {
	{ "no-fetch-size", IMAPC_FEATURE_NO_FETCH_SIZE },
	{ "guid-forced", IMAPC_FEATURE_GUID_FORCED },
	{ "no-fetch-headers", IMAPC_FEATURE_NO_FETCH_HEADERS },
	{ "gmail-migration", IMAPC_FEATURE_GMAIL_MIGRATION },
	{ "no-search", IMAPC_FEATURE_NO_SEARCH },
	{ "zimbra-workarounds", IMAPC_FEATURE_ZIMBRA_WORKAROUNDS },
	{ "no-examine", IMAPC_FEATURE_NO_EXAMINE },
	{ "proxyauth", IMAPC_FEATURE_PROXYAUTH },
	{ "fetch-msn-workarounds", IMAPC_FEATURE_FETCH_MSN_WORKAROUNDS },
	{ "fetch-fix-broken-mails", IMAPC_FEATURE_FETCH_FIX_BROKEN_MAILS },
	{ "no-modseq", IMAPC_FEATURE_NO_MODSEQ },
	{ "no-delay-login", IMAPC_FEATURE_NO_DELAY_LOGIN },
	{ "no-fetch-bodystructure", IMAPC_FEATURE_NO_FETCH_BODYSTRUCTURE },
	{ "send-id", IMAPC_FEATURE_SEND_ID },
	{ "fetch-empty-is-expunged", IMAPC_FEATURE_FETCH_EMPTY_IS_EXPUNGED },
	{ "no-msn-updates", IMAPC_FEATURE_NO_MSN_UPDATES },
	{ "no-acl", IMAPC_FEATURE_NO_ACL },
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
	const char *const *str, *value;

	str = settings_boollist_get(&set->imapc_features);
	for (; *str != NULL; str++) {
		list = imapc_feature_list;
		for (; list->name != NULL; list++) {
			if (strcmp(*str, list->name) == 0) {
				features |= list->num;
				break;
			}
		}
		if (str_begins(*str, "throttle:", &value)) {
			if (imapc_settings_parse_throttle(set, value, error_r) < 0)
				return -1;
			continue;
		}
		if (str_begins(*str, "no-", &value)) {
			enum imapc_capability capa =
				imapc_capability_lookup(value);
			if (capa != 0) {
				set->parsed_disabled_capabilities |= capa;
				continue;
			}
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

	if (set->imapc_max_idle_time_secs == 0) {
		*error_r = "imapc_max_idle_time must not be 0";
		return FALSE;
	}
	if (set->imapc_max_line_length == 0) {
		*error_r = "imapc_max_line_length must not be 0";
		return FALSE;
	}
	if (imapc_settings_parse_features(set, error_r) < 0)
		return FALSE;
	return TRUE;
}
