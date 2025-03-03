/* Copyright (c) 2024 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "quota-private.h"
#include "quota-settings.h"

static bool quota_root_settings_check(void *_set, pool_t pool, const char **error_r);

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct quota_settings)
static const struct setting_define quota_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "quota_count" },
	{ .type = SET_FILTER_NAME, .key = "quota_maildir" },

	{ .type = SET_FILTER_ARRAY, .key = "quota",
	  .offset = offsetof(struct quota_settings, quota_roots),
	  .filter_array_field_name = "quota_name", },

	DEF(UINT, quota_mailbox_count),
	DEF(UINT, quota_mailbox_message_count),
	DEF(SIZE, quota_mail_size),
	DEF(STR, quota_exceeded_message),

	SETTING_DEFINE_LIST_END
};

static const struct quota_settings quota_default_settings = {
	.quota_roots = ARRAY_INIT,

	.quota_mailbox_count = SET_UINT_UNLIMITED,
	.quota_mail_size = SET_SIZE_UNLIMITED,
	.quota_mailbox_message_count = SET_UINT_UNLIMITED,
	.quota_exceeded_message = "Quota exceeded (mailbox for user is full)",
};

const struct setting_parser_info quota_setting_parser_info = {
	.name = "quota",
	.plugin_dependency = "lib10_quota_plugin",
	.defines = quota_setting_defines,
	.defaults = &quota_default_settings,
	.struct_size = sizeof(struct quota_settings),
	.pool_offset1 = 1 + offsetof(struct quota_settings, pool),
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct quota_root_settings)
static const struct setting_define quota_root_setting_defines[] = {
	{ .type = SET_FILTER_ARRAY, .key = "quota_warning",
	  .offset = offsetof(struct quota_root_settings, quota_warnings),
	  .filter_array_field_name = "quota_warning_name",
	  .required_setting = "execute", },

	DEF(STR, quota_name),
	DEF(STR, quota_driver),
	DEF(BOOL, quota_ignore),
	DEF(BOOL, quota_ignore_unlimited),
	DEF(BOOL, quota_enforce),
	DEF(BOOL, quota_hidden),
	DEF(SIZE, quota_storage_size),
	DEF(UINT, quota_storage_percentage),
	DEF(SIZE, quota_storage_extra),
	DEF(SIZE, quota_storage_grace),
	DEF(UINT, quota_message_count),
	DEF(UINT, quota_message_percentage),

	DEF(STR, quota_warning_name),
	DEF(ENUM, quota_warning_resource),
	DEF(ENUM, quota_warning_threshold),

	{ .type = SET_FILTER_NAME, .key = "quota_over_status",
	  .required_setting = "execute", },
	DEF(BOOL, quota_over_status_lazy_check),
	DEF(STR, quota_over_status_current),
	DEF(STR, quota_over_status_mask),

	SETTING_DEFINE_LIST_END
};

static const struct quota_root_settings quota_root_default_settings = {
	.quota_warnings = ARRAY_INIT,

	.quota_name = "",
	.quota_driver = "count",
	.quota_ignore = FALSE,
	.quota_ignore_unlimited = FALSE,
	.quota_enforce = TRUE,
	.quota_hidden = FALSE,
	.quota_storage_size = SET_SIZE_UNLIMITED,
	.quota_storage_percentage = 100,
	.quota_storage_extra = 0,
	.quota_storage_grace = 1024 * 1024 * 10,
	.quota_message_count = SET_UINT_UNLIMITED,
	.quota_message_percentage = 100,

	.quota_warning_name = "",
	.quota_warning_resource = QUOTA_WARNING_RESOURCE_STORAGE":"
		QUOTA_WARNING_RESOURCE_MESSAGE,
	.quota_warning_threshold = QUOTA_WARNING_THRESHOLD_OVER":"
		QUOTA_WARNING_THRESHOLD_UNDER,

	.quota_over_status_lazy_check = FALSE,
	.quota_over_status_current = "",
	.quota_over_status_mask = "",
};

const struct setting_parser_info quota_root_setting_parser_info = {
	.name = "quota_root",
	.plugin_dependency = "lib10_quota_plugin",
	.defines = quota_root_setting_defines,
	.defaults = &quota_root_default_settings,
	.struct_size = sizeof(struct quota_root_settings),
#ifndef CONFIG_BINARY
	.check_func = quota_root_settings_check,
#endif
	.pool_offset1 = 1 + offsetof(struct quota_root_settings, pool),
};

#ifndef CONFIG_BINARY
static bool quota_root_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				      const char **error_r)
{
	struct quota_root_settings *set = _set;

	set->backend = quota_backend_find(set->quota_driver);
	if (set->backend == NULL) {
		*error_r = t_strdup_printf("Unknown quota_driver: %s",
					   set->quota_driver);
		return FALSE;
	}
	if (set->quota_storage_percentage == 0) {
		*error_r = "quota_storage_percentage must not be 0";
		return FALSE;
	}
	if (set->quota_message_percentage == 0) {
		*error_r = "quota_message_percentage must not be 0";
		return FALSE;
	}
	/* Change "unlimited" settings to 0 for easier handling. We accept 0
	   as unlimited anyway because that's commonly used in userdbs. */
	if (set->quota_message_count == SET_UINT_UNLIMITED)
		set->quota_message_count = 0;
	if (set->quota_storage_size == SET_SIZE_UNLIMITED)
		set->quota_storage_size = 0;
	return TRUE;
}
#endif

struct quota_settings *quota_get_unlimited_set(void)
{
	static struct quota_settings set;
	if (set.pool == NULL) {
		set = quota_default_settings;
		set.pool = null_pool;
	}
	return &set;
}
