/* Copyright (c) Dovecot authors, see top-level COPYING file */

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
	{ .type = SET_FILTER_NAME, .key = IMAPC_SETTINGS_FILTER },
	{ .type = SET_FILTER_NAME, .key = "layout_imapc" },

	DEF(BOOLLIST, imapc_features),
	DEF(STR, imapc_list_prefix),
	DEF(STR, pop3_deleted_flag),

	SETTING_DEFINE_LIST_END
};

static const struct imapc_settings imapc_default_settings = {
	.imapc_features = ARRAY_INIT,
	.imapc_list_prefix = "",
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
struct imapc_feature_list {
	const char *name;
	enum imapc_features num;
};

/* Only the features implemented by lib-storage's imapc are listed here. The
   rest of the features are implemented by lib-imap-client, which doesn't
   report unknown features at all, so they are all validated here. */
static const struct imapc_feature_list imapc_feature_list[] = {
	{ "no-fetch-size", IMAPC_FEATURE_NO_FETCH_SIZE },
	{ "guid-forced", IMAPC_FEATURE_GUID_FORCED },
	{ "no-fetch-headers", IMAPC_FEATURE_NO_FETCH_HEADERS },
	{ "gmail-migration", IMAPC_FEATURE_GMAIL_MIGRATION },
	{ "no-search", IMAPC_FEATURE_NO_SEARCH },
	{ "zimbra-workarounds", IMAPC_FEATURE_ZIMBRA_WORKAROUNDS },
	{ "no-examine", IMAPC_FEATURE_NO_EXAMINE },
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

static bool imapc_feature_lookup(const char *name, enum imapc_features *num_r)
{
	const struct imapc_feature_list *list;

	for (list = imapc_feature_list; list->name != NULL; list++) {
		if (strcmp(name, list->name) == 0) {
			*num_r = list->num;
			return TRUE;
		}
	}
	return FALSE;
}

/* Returns TRUE if the feature is known, but implemented by lib-imap-client
   instead of here. */
static bool imapc_client_feature_exists(const char *name)
{
	enum imapc_client_features client_feature;
	const char *value;

	if (imapc_client_feature_lookup(name, &client_feature))
		return TRUE;
	if (str_begins(name, "throttle:", &value))
		return TRUE;
	if (str_begins(name, "no-", &value))
		return imapc_capability_lookup(value) != 0;
	return FALSE;
}

static int
imapc_settings_parse_features(struct imapc_settings *set, const char **error_r)
{
	enum imapc_features features = 0;
	enum imapc_features feature;
	const char *const *str;

	str = settings_boollist_get(&set->imapc_features);
	for (; *str != NULL; str++) {
		if (imapc_feature_lookup(*str, &feature)) {
			features |= feature;
			continue;
		}
		if (!imapc_client_feature_exists(*str)) {
			*error_r = t_strdup_printf("imapc_features: "
				"Unknown feature: %s", *str);
			return -1;
		}
	}
	set->parsed_features = features;
	return 0;
}

static bool
imapc_settings_check(void *_set, pool_t pool ATTR_UNUSED, const char **error_r)
{
	struct imapc_settings *set = _set;

	if (imapc_settings_parse_features(set, error_r) < 0)
		return FALSE;
	return TRUE;
}
