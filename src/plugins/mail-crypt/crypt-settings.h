#ifndef CRYPT_SETTINGS_H
#define CRYPT_SETTINGS_H

struct crypt_private_key_settings {
	pool_t pool;

	const char *crypt_private_key_name;
	const char *crypt_private_key;
	const char *crypt_private_key_password;
};

struct crypt_settings {
	pool_t pool;

	const char *crypt_global_public_key;
	ARRAY_TYPE(const_string) crypt_global_private_keys;

	const char *crypt_write_algorithm;
	unsigned int crypt_write_version;
	bool crypt_plain_fallback;

	/* for user-specific keys: */
	ARRAY_TYPE(const_string) crypt_user_key_encryption_keys;
	const char *crypt_user_key_password;
	const char *crypt_user_key_curve; /* for generating new user keys */
	bool crypt_user_private_key_require_encrypted;
};

extern const struct setting_parser_info crypt_setting_parser_info;
extern const struct setting_parser_info crypt_private_key_setting_parser_info;

#endif
