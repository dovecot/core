/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "crypt-settings.h"

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct crypt_private_key_settings)
static const struct setting_define crypt_private_key_setting_defines[] = {
	DEF(STR, crypt_private_key_name),
	DEF(STR, crypt_private_key),
	DEF(STR, crypt_private_key_password),

	SETTING_DEFINE_LIST_END
};

static const struct crypt_private_key_settings crypt_private_key_default_settings = {
	.crypt_private_key_name = "",
	.crypt_private_key = "",
	.crypt_private_key_password = "",
};

const struct setting_parser_info crypt_private_key_setting_parser_info = {
	.name = "crypt_private_key",

	.defines = crypt_private_key_setting_defines,
	.defaults = &crypt_private_key_default_settings,

	.struct_size = sizeof(struct crypt_private_key_settings),
	.pool_offset1 = 1 + offsetof(struct crypt_private_key_settings, pool),
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct crypt_settings)
static const struct setting_define crypt_setting_defines[] = {
	DEF(STR, crypt_global_public_key),
	{ .type = SET_FILTER_ARRAY, .key = "crypt_global_private_key",
	   .offset = offsetof(struct crypt_settings, crypt_global_private_keys),
	   .filter_array_field_name = "crypt_private_key_name" },

	DEF(STR, crypt_write_algorithm),
	DEF(UINT, crypt_write_version),
	DEF(BOOL, crypt_plain_fallback),

	{ .type = SET_FILTER_ARRAY, .key = "crypt_user_key_encryption_key",
	   .offset = offsetof(struct crypt_settings, crypt_user_key_encryption_keys),
	   .filter_array_field_name = "crypt_private_key_name" },
	DEF(STR, crypt_user_key_password),
	DEF(STR, crypt_user_key_curve),
	DEF(BOOL, crypt_user_key_require_encrypted),

	SETTING_DEFINE_LIST_END
};

static const struct crypt_settings crypt_default_settings = {
	.crypt_global_public_key = "",
	.crypt_global_private_keys = ARRAY_INIT,

	.crypt_write_algorithm = "aes-256-gcm-sha256",
	.crypt_write_version = UINT_MAX,
	.crypt_plain_fallback = FALSE,

	.crypt_user_key_encryption_keys = ARRAY_INIT,
	.crypt_user_key_password = "",
	.crypt_user_key_curve = "",
	.crypt_user_key_require_encrypted = FALSE,
};

const struct setting_parser_info crypt_setting_parser_info = {
	.name = "crypt",

	.defines = crypt_setting_defines,
	.defaults = &crypt_default_settings,

	.struct_size = sizeof(struct crypt_settings),
	.pool_offset1 = 1 + offsetof(struct crypt_settings, pool),
};
