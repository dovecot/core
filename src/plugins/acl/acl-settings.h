#ifndef ACL_SETTINGS_H
#define ACL_SETTINGS_H

#define ACL_DEFAULT_CACHE_TTL_SECS 30

struct acl_rights_settings {
	pool_t pool;
	const char *id;
	const char *rights;

	struct acl_rights *parsed;
};

ARRAY_DEFINE_TYPE(acl_rights_setting, struct acl_rights_settings);

struct acl_settings {
	pool_t pool;
	const char *acl_user;
	ARRAY_TYPE(const_string) acl_groups;
	ARRAY_TYPE(const_string) acl_rights;
	const char *acl_driver;
	const char *acl_global_path;
	unsigned int acl_cache_ttl;
	bool acl_globals_only;
	bool acl_defaults_from_inbox;
	bool acl_ignore;
};

extern const struct setting_parser_info acl_rights_setting_parser_info;
extern const struct setting_parser_info acl_setting_parser_info;

#endif
