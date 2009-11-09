#ifndef AUTH_SETTINGS_H
#define AUTH_SETTINGS_H

struct master_service;

struct auth_passdb_settings {
	const char *driver;
	const char *args;
	bool deny;
	bool pass;
	bool master;
};

struct auth_userdb_settings {
	const char *driver;
	const char *args;
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
	unsigned int failure_delay;

	bool verbose, debug, debug_passwords;
	bool ssl_require_client_cert;
	bool ssl_username_from_cert;
	bool use_winbind;

	unsigned int worker_max_count;

	ARRAY_DEFINE(passdbs, struct auth_passdb_settings *);
	ARRAY_DEFINE(userdbs, struct auth_userdb_settings *);
};

struct auth_settings *auth_settings_read(struct master_service *service);

#endif
