/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "crypt-settings.h"

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct crypt_private_key_settings)
static const struct setting_define crypt_private_key_setting_defines[] = {
	DEF(STR, crypt_private_key_name),
	DEF(FILE, crypt_private_key_file),
	DEF(STR, crypt_private_key_password),

	SETTING_DEFINE_LIST_END
};

static const struct crypt_private_key_settings crypt_private_key_default_settings = {
	.crypt_private_key_name = "",
	.crypt_private_key_file = "",
	.crypt_private_key_password = "",
};

const struct setting_parser_info crypt_private_key_setting_parser_info = {
	.name = "crypt_private_key",
	.plugin_dependency = "lib10_mail_crypt_plugin",

	.defines = crypt_private_key_setting_defines,
	.defaults = &crypt_private_key_default_settings,

	.struct_size = sizeof(struct crypt_private_key_settings),
	.pool_offset1 = 1 + offsetof(struct crypt_private_key_settings, pool),
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct crypt_settings)
static const struct setting_define crypt_setting_defines[] = {
	DEF(BOOL, fs_crypt_read_plain_fallback),

	DEF(FILE, crypt_global_public_key_file),
	{ .type = SET_FILTER_ARRAY, .key = "crypt_global_private_key",
	   .offset = offsetof(struct crypt_settings, crypt_global_private_keys),
	   .filter_array_field_name = "crypt_private_key_name" },

	DEF(STR, crypt_write_algorithm),

	{ .type = SET_FILTER_ARRAY, .key = "crypt_user_key_encryption_key",
	   .offset = offsetof(struct crypt_settings, crypt_user_key_encryption_keys),
	   .filter_array_field_name = "crypt_private_key_name" },
	DEF(STR, crypt_user_key_password),
	DEF(STR, crypt_user_key_curve),
	DEF(BOOL, crypt_user_key_require_encrypted),

	SETTING_DEFINE_LIST_END
};

static const struct crypt_settings crypt_default_settings = {
	.fs_crypt_read_plain_fallback = FALSE,

	.crypt_global_public_key_file = "",
	.crypt_global_private_keys = ARRAY_INIT,

	.crypt_write_algorithm = "aes-256-gcm-sha256",

	.crypt_user_key_encryption_keys = ARRAY_INIT,
	.crypt_user_key_password = "",
	.crypt_user_key_curve = "",
	.crypt_user_key_require_encrypted = FALSE,
};

const struct setting_parser_info crypt_setting_parser_info = {
	.name = "crypt",
	.plugin_dependency = "lib10_mail_crypt_plugin",

	.defines = crypt_setting_defines,
	.defaults = &crypt_default_settings,

	.struct_size = sizeof(struct crypt_settings),
	.pool_offset1 = 1 + offsetof(struct crypt_settings, pool),
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct crypt_acl_settings)
static const struct setting_define crypt_acl_setting_defines[] = {
	DEF(BOOL, crypt_acl_require_secure_key_sharing),

	SETTING_DEFINE_LIST_END
};

static const struct crypt_acl_settings crypt_acl_default_settings = {
	.crypt_acl_require_secure_key_sharing = FALSE,
};

const struct setting_parser_info crypt_acl_setting_parser_info = {
	.name = "crypt_acl",
	.plugin_dependency = "lib05_mail_crypt_acl_plugin",

	.defines = crypt_acl_setting_defines,
	.defaults = &crypt_acl_default_settings,

	.struct_size = sizeof(struct crypt_acl_settings),
	.pool_offset1 = 1 + offsetof(struct crypt_acl_settings, pool),
};
