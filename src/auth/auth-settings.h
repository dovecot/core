#ifndef AUTH_SETTINGS_H
#define AUTH_SETTINGS_H

struct master_service;
struct master_service_settings_output;

struct auth_passdb_settings {
	const char *name;
	const char *driver;
	const char *args;
	const char *default_fields;
	const char *override_fields;
	const char *mechanisms;
	const char *username_filter;

	const char *skip;
	const char *result_success;
	const char *result_failure;
	const char *result_internalfail;
	bool deny;
	bool pass; /* deprecated, use result_success=continue instead */
	bool master;
	const char *auth_verbose;
};

struct auth_userdb_settings {
	const char *name;
	const char *driver;
	const char *args;
	const char *default_fields;
	const char *override_fields;

	const char *skip;
	const char *result_success;
	const char *result_failure;
	const char *result_internalfail;
	const char *auth_verbose;
};

struct auth_settings {
	const char *mechanisms;
	const char *realms;
	const char *default_realm;
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

	const char *policy_server_url;
	const char *policy_server_api_header;
	unsigned int policy_server_timeout_msecs;
	const char *policy_hash_mech;
	const char *policy_hash_nonce;
	const char *policy_request_attributes;
	bool policy_reject_on_fail;
	bool policy_check_before_auth;
	bool policy_check_after_auth;
	bool policy_report_after_auth;
	bool policy_log_only;
	unsigned int policy_hash_truncate;

	bool stats;
	bool verbose, debug, debug_passwords;
	const char *verbose_passwords;
	bool ssl_require_client_cert;
	bool ssl_username_from_cert;
	bool use_winbind;

	unsigned int worker_max_count;

	/* settings that don't have auth_ prefix: */
	ARRAY(struct auth_passdb_settings *) passdbs;
	ARRAY(struct auth_userdb_settings *) userdbs;

	const char *base_dir;
	const char *ssl_client_ca_dir;
	const char *ssl_client_ca_file;

	bool verbose_proctitle;
	unsigned int first_valid_uid;
	unsigned int last_valid_uid;
	unsigned int first_valid_gid;
	unsigned int last_valid_gid;

	/* generated: */
	char username_chars_map[256];
	char username_translation_map[256];
	const char *const *realms_arr;
	const struct ip_addr *proxy_self_ips;
};

extern const struct setting_parser_info auth_setting_parser_info;
extern struct auth_settings *global_auth_settings;

struct auth_settings *
auth_settings_read(const char *service, pool_t pool,
		   struct master_service_settings_output *output_r)
	ATTR_NULL(1);

#endif
