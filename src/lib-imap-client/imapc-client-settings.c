/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "imapc-client-settings.h"

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct imapc_client_settings)

#undef DEF_MSECS
#define DEF_MSECS(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name##_msecs, struct imapc_client_settings)

#undef DEF_SECS
#define DEF_SECS(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name##_secs, struct imapc_client_settings)

static bool imapc_client_settings_check(void *_set, pool_t pool, const char **error_r);

static const struct setting_define imapc_client_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = IMAPC_SETTINGS_FILTER },
	DEF(STR, imapc_host),
	DEF(IN_PORT, imapc_port),
	DEF(ENUM, imapc_ssl),

	DEF(BOOLLIST, imapc_features),
	DEF(PATH_DIR, imapc_rawlog_dir),
	DEF_SECS(TIME, imapc_cmd_timeout),
	DEF_SECS(TIME, imapc_max_idle_time),
	DEF_MSECS(TIME_MSECS, imapc_connection_timeout_interval),
	DEF(UINT, imapc_connection_retry_count),
	DEF_MSECS(TIME_MSECS, imapc_connection_retry_interval),
	DEF(SIZE, imapc_max_line_length),

	/* deprecated: */
	DEF(BOOLLIST_HIDDEN, imapc_sasl_mechanisms),

	SETTING_DEFINE_LIST_END
};

static const struct imapc_client_settings imapc_client_default_settings = {
	.imapc_host = "",
	.imapc_port = 143,
	.imapc_ssl = "no:imaps:starttls",

	.imapc_features = ARRAY_INIT,
	.imapc_rawlog_dir = "",
	.imapc_cmd_timeout_secs = 5*60,
	.imapc_max_idle_time_secs = IMAPC_DEFAULT_MAX_IDLE_TIME,
	.imapc_connection_timeout_interval_msecs = 1000*30,
	.imapc_connection_retry_count = 1,
	.imapc_connection_retry_interval_msecs = 1000,
	.imapc_max_line_length = SET_SIZE_UNLIMITED,

	/* deprecated: */
	.imapc_sasl_mechanisms = ARRAY_INIT,
};

static const struct setting_keyvalue imapc_client_default_settings_keyvalue[] = {
	{ "imapc/client_auth_authzid", "%{owner_user}" },
	{ NULL, NULL }
};

const struct setting_parser_info imapc_client_setting_parser_info = {
	.name = "imapc-client",

	.defines = imapc_client_setting_defines,
	.defaults = &imapc_client_default_settings,
	.default_settings = imapc_client_default_settings_keyvalue,

	.struct_size = sizeof(struct imapc_client_settings),
	.pool_offset1 = 1 + offsetof(struct imapc_client_settings, pool),

	.check_func = imapc_client_settings_check
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
	{ "SEARCH=MIMEPART", IMAPC_CAPABILITY_SEARCH_MIMEPART },
	{ "SEARCH=X-MIMEPART", IMAPC_CAPABILITY_SEARCH_MIMEPART },

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

struct imapc_client_feature_list {
	const char *name;
	enum imapc_client_features num;
};

/* Only the features implemented by the low-level imap client are listed here.
   The rest of the features are implemented by lib-storage's imapc, which also
   does the validation for all of them - see imapc_client_feature_lookup(). */
static const struct imapc_client_feature_list imapc_client_feature_list[] = {
	{ "proxyauth", IMAPC_FEATURE_PROXYAUTH },
	{ NULL, 0 }
};

bool imapc_client_feature_lookup(const char *name,
				 enum imapc_client_features *features_r)
{
	const struct imapc_client_feature_list *list;

	for (list = imapc_client_feature_list; list->name != NULL; list++) {
		if (strcmp(name, list->name) == 0) {
			*features_r = list->num;
			return TRUE;
		}
	}
	return FALSE;
}

static int
imapc_client_settings_parse_throttle(struct imapc_client_settings *set,
				     const char *throttle_str,
				     const char **error_r)
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
imapc_client_settings_parse_features(struct imapc_client_settings *set,
				     const char **error_r)
{
	enum imapc_client_features features = 0;
	const char *const *str, *value;

	str = settings_boollist_get(&set->imapc_features);
	for (; *str != NULL; str++) {
		enum imapc_client_features feature;

		if (imapc_client_feature_lookup(*str, &feature)) {
			features |= feature;
			continue;
		}
		if (str_begins(*str, "throttle:", &value)) {
			if (imapc_client_settings_parse_throttle(set, value,
								 error_r) < 0)
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
		/* The feature is either implemented by lib-storage's imapc or
		   it is unknown. Either way it is not handled here.
		   imapc_settings_parse_features() reports unknown features. */
	}
	set->parsed_features = features;
	return 0;
}

static bool
imapc_client_settings_check(void *_set, pool_t pool ATTR_UNUSED,
			    const char **error_r)
{
	struct imapc_client_settings *set = _set;

	if (set->imapc_max_idle_time_secs == 0) {
		*error_r = "imapc_max_idle_time must not be 0";
		return FALSE;
	}
	if (set->imapc_max_line_length == 0) {
		*error_r = "imapc_max_line_length must not be 0";
		return FALSE;
	}
	if (imapc_client_settings_parse_features(set, error_r) < 0)
		return FALSE;
	return TRUE;
}
