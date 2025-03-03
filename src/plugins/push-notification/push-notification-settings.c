/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include <unistd.h>

#include "lib.h"
#include "array.h"
#include "settings.h"
#include "settings-parser.h"

#include "push-notification-settings.h"

/* <settings checks> */
#include "http-url.h"
/* </settings checks> */

#define PUSH_NOTIFICATION_DRIVER_OX_DEFAULT_CACHE_TTL_MSECS (60 * 1000)

static bool push_notification_settings_check(void *, pool_t, const char **);
static bool push_notification_ox_settings_check(void *, pool_t, const char **);

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("push_notification_ox_"#name, name, struct push_notification_ox_settings)

static const struct setting_define push_notification_ox_setting_defines[] = {
	DEF(STR, url),
	DEF(TIME_MSECS, cache_ttl),
	DEF(BOOL, user_from_metadata),

	SETTING_DEFINE_LIST_END,
};

static const struct push_notification_ox_settings push_notification_ox_default_settings = {
	.url = "",
	.cache_ttl = PUSH_NOTIFICATION_DRIVER_OX_DEFAULT_CACHE_TTL_MSECS,
	.user_from_metadata = FALSE,
};

const struct setting_parser_info push_notification_ox_setting_parser_info = {
	.name = "push_notification_ox",
	.plugin_dependency = "lib20_push_notification_plugin",

	.defines = push_notification_ox_setting_defines,
	.defaults = &push_notification_ox_default_settings,

	.struct_size = sizeof(struct push_notification_ox_settings),
	.pool_offset1 = 1 + offsetof(struct push_notification_ox_settings, pool),
	.check_func = push_notification_ox_settings_check,
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("push_notification_"#name, name, struct push_notification_settings)

static const struct setting_define push_notification_setting_defines[] = {
	DEF(STR, name),
	DEF(STR, driver),
	{
		.type = SET_FILTER_ARRAY,
		.key = PUSH_NOTIFICATION_SETTINGS_FILTER_NAME,
		.offset = offsetof(struct push_notification_settings, push_notifications),
		.filter_array_field_name = "push_notification_name",
	},

	SETTING_DEFINE_LIST_END,
};

static const struct push_notification_settings push_notification_default_settings = {
	.name = "",
	.driver = "",
	.push_notifications = ARRAY_INIT,
};

const struct setting_parser_info push_notification_setting_parser_info = {
	.name = "push_notification",
	.plugin_dependency = "lib20_push_notification_plugin",

	.defines = push_notification_setting_defines,
	.defaults = &push_notification_default_settings,

	.struct_size = sizeof(struct push_notification_settings),
	.pool_offset1 = 1 + offsetof(struct push_notification_settings, pool),

	.check_func = push_notification_settings_check,
};

/* <settings checks> */
static bool
push_notification_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				 const char **error_r ATTR_UNUSED)
{
	struct push_notification_settings *set = _set;

	if (set->driver[0] == '\0')
		set->driver = set->name;
	return TRUE;
}

static bool
push_notification_ox_settings_check(void *_set, pool_t pool,
				    const char **error_r)
{
	struct push_notification_ox_settings *set = _set;
	const char *error;

	if (set->url[0] != '\0') {
		if (http_url_parse(set->url, NULL, HTTP_URL_ALLOW_USERINFO_PART,
				   pool, &set->parsed_url, &error) < 0) {
			*error_r = t_strdup_printf(
				"Invalid push_notification_ox_url '%s': %s",
				set->url, error);
			return FALSE;
		}
	} else
		set->parsed_url = NULL;

	if (set->cache_ttl == 0) {
		*error_r = "push_notification_ox_cache_ttl must not be 0";
		return FALSE;
	}

	return TRUE;
}
/* </settings checks> */
