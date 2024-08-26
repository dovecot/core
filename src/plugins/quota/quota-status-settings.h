#ifndef QUOTA_STATUS_SETTINGS_H
#define QUOTA_STATUS_SETTINGS_H 1

struct quota_status_settings {
	pool_t pool;
	const char *recipient_delimiter;
	const char *quota_status_nouser;
};

extern const struct setting_parser_info quota_status_setting_parser_info;

#endif
