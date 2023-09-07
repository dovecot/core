#ifndef PUSH_NOTIFICATION_SETTINGS_H
#define PUSH_NOTIFICATION_SETTINGS_H

/* <settings checks> */
#define PUSH_NOTIFICATION_SETTINGS_FILTER_NAME "push_notification"
/* </settings checks> */

struct push_notification_lua_settings {
	pool_t pool;

	const char *path;
};

struct push_notification_ox_settings {
	pool_t pool;

	const char *url;
	unsigned int cache_ttl;
	bool user_from_metadata;

	/* Generated: */
	struct http_url *parsed_url;
};

struct push_notification_settings {
	pool_t pool;
	const char *name;
	const char *driver;

	ARRAY_TYPE(const_string) push_notifications;
};

extern const struct setting_parser_info push_notification_lua_setting_parser_info;
extern const struct setting_parser_info push_notification_ox_setting_parser_info;
extern const struct setting_parser_info push_notification_setting_parser_info;

#endif
