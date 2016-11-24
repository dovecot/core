#ifndef FS_CRYPT_SETTINGS_H
#define FS_CRYPT_SETTINGS_H

struct fs_crypt_settings {
	ARRAY(const char *) plugin_envs;
};

extern const struct setting_parser_info fs_crypt_setting_parser_info;

#endif

