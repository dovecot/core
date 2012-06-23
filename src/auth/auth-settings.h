#ifndef AUTH_SETTINGS_H
#define AUTH_SETTINGS_H

struct master_service;
struct master_service_settings_output;

struct auth_passdb_settings {
	const char *driver;
	const char *args;
	const char *default_fields;
	const char *override_fields;
	bool deny;
	bool pass;
	bool master;
};

struct auth_userdb_settings {
	const char *driver;
	const char *args;
	const char *default_fields;
	const char *override_fields;
};

struct auth_settings {
	const char *mechanisms;
	const char *realms;
	const char *default_realm;
	uoff_t cache_size;
	unsigned int cache_ttl;
	unsigned int cache_negative_ttl;
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
	unsigned int first_valid_uid;
	unsigned int last_valid_uid;

	bool verbose, debug, debug_passwords;
	const char *verbose_passwords;
	bool ssl_require_client_cert;
	bool ssl_username_from_cert;
	bool use_winbind;

	unsigned int worker_max_count;

	ARRAY_DEFINE(passdbs, struct auth_passdb_settings *);
	ARRAY_DEFINE(userdbs, struct auth_userdb_settings *);

	const char *base_dir;
	bool verbose_proctitle;

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
