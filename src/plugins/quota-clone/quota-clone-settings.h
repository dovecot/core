#ifndef QUOTA_CLONE_SETTINGS_H
#define QUOTA_CLONE_SETTINGS_H

extern const struct setting_parser_info quota_clone_setting_parser_info;
struct quota_clone_settings {
	pool_t      pool;
	bool        unset;
};

#endif
