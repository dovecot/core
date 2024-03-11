#ifndef AUTH_SETTINGS_H
#define AUTH_SETTINGS_H

struct master_service;
struct master_service_settings_output;

struct auth_passdb_pre_settings {
	pool_t pool;
	ARRAY_TYPE(const_string) default_fields;
};

struct auth_passdb_post_settings {
	pool_t pool;
	ARRAY_TYPE(const_string) fields;
	ARRAY_TYPE(const_string) override_fields;
};

struct auth_passdb_settings {
	pool_t pool;
	const char *name;
	const char *driver;
	const char *args;
	bool fields_import_all;
	ARRAY_TYPE(const_string) mechanisms;
	const char *username_filter;

	const char *default_password_scheme;

	const char *skip;
	const char *result_success;
	const char *result_failure;
	const char *result_internalfail;
	bool deny;
	bool master;
	bool use_cache;
	bool use_worker;
};

struct auth_userdb_pre_settings {
	pool_t pool;
	ARRAY_TYPE(const_string) default_fields;
};

struct auth_userdb_post_settings {
	pool_t pool;
	ARRAY_TYPE(const_string) fields;
	ARRAY_TYPE(const_string) override_fields;
};

struct auth_userdb_settings {
	pool_t pool;
	const char *name;
	const char *driver;
	const char *args;
	bool fields_import_all;

	const char *skip;
	const char *result_success;
	const char *result_failure;
	const char *result_internalfail;

	bool use_cache;
	bool use_worker;
};

struct auth_settings {
	pool_t pool;
	ARRAY_TYPE(const_string) mechanisms;
	const char *oauth2_config_file;
	const char *realms;
	const char *default_domain;
	uoff_t cache_size;
	unsigned int cache_ttl;
	unsigned int cache_negative_ttl;
	bool cache_verify_password_with_worker;
	const char *username_chars;
	const char *username_translation;
	const char *username_format;
	const char *master_user_separator;
	const char *anonymous_username;
	const char *krb5_keytab;
	const char *gssapi_hostname;
	const char *winbind_helper_path;
	const char *proxy_self;
	unsigned int failure_delay;
	unsigned int internal_failure_delay;

	const char *policy_server_url;
	const char *policy_server_api_header;
	const char *policy_hash_mech;
	const char *policy_hash_nonce;
	const char *policy_request_attributes;
	bool policy_reject_on_fail;
	bool policy_check_before_auth;
	bool policy_check_after_auth;
	bool policy_report_after_auth;
	bool policy_log_only;
	unsigned int policy_hash_truncate;

	bool verbose, debug, debug_passwords;
	bool allow_weak_schemes;
	const char *verbose_passwords;
	bool ssl_require_client_cert;
	bool ssl_username_from_cert;
	bool use_winbind;

	/* settings that don't have auth_ prefix: */
	ARRAY_TYPE(const_string) passdbs;
	ARRAY_TYPE(const_string) userdbs;

	const char *base_dir;

	bool verbose_proctitle;
	unsigned int first_valid_uid;
	unsigned int last_valid_uid;
	unsigned int first_valid_gid;
	unsigned int last_valid_gid;

	/* generated: */
	ARRAY(const struct auth_passdb_settings *) parsed_passdbs;
	ARRAY(const struct auth_userdb_settings *) parsed_userdbs;
	char username_chars_map[256];
	char username_translation_map[256];
	const char *const *realms_arr;
	const struct ip_addr *proxy_self_ips;
};

extern const struct setting_parser_info auth_setting_parser_info;
extern const struct setting_parser_info auth_passdb_setting_parser_info;
extern const struct setting_parser_info auth_passdb_pre_setting_parser_info;
extern const struct setting_parser_info auth_passdb_post_setting_parser_info;
extern const struct setting_parser_info auth_userdb_setting_parser_info;
extern const struct setting_parser_info auth_userdb_pre_setting_parser_info;
extern const struct setting_parser_info auth_userdb_post_setting_parser_info;
extern const struct auth_settings *global_auth_settings;

void auth_settings_read(struct master_service_settings_output *output_r);
const struct auth_settings *auth_settings_get(const char *protocol);

#endif
