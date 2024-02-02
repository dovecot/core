#ifndef CRYPT_SETTINGS_H
#define CRYPT_SETTINGS_H

struct crypt_private_key_settings {
	pool_t pool;

	const char *crypt_private_key_name;
	const char *crypt_private_key_file;
	const char *crypt_private_key_password;
};

struct crypt_settings {
	pool_t pool;

	bool fs_crypt_read_plain_fallback;

	const char *crypt_global_public_key_file;
	ARRAY_TYPE(const_string) crypt_global_private_keys;

	const char *crypt_write_algorithm;

	/* for user-specific keys: */
	ARRAY_TYPE(const_string) crypt_user_key_encryption_keys;
	const char *crypt_user_key_password;
	const char *crypt_user_key_curve; /* for generating new user keys */
	bool crypt_user_key_require_encrypted;
};

struct crypt_acl_settings {
	pool_t pool;
	bool crypt_acl_require_secure_key_sharing;
};

extern const struct setting_parser_info crypt_setting_parser_info;
extern const struct setting_parser_info crypt_private_key_setting_parser_info;
extern const struct setting_parser_info crypt_acl_setting_parser_info;

#endif
