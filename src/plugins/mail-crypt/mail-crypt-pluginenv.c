/* Copyright (c) 2015-2016 Dovecot authors, see the included COPYING file */
#include "lib.h"
#include "str.h"
#include "array.h"
#include "settings-parser.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "mail-crypt-common.h"
#include "mail-crypt-key.h"
#include "fs-crypt-settings.h"

static const struct fs_crypt_settings *
fs_crypt_load_settings(void)
{
	static const struct setting_parser_info *set_roots[] = {
		&fs_crypt_setting_parser_info,
		NULL
	};
	struct master_service_settings_input input;
	struct master_service_settings_output output;
	const char *error;

	i_zero(&input);
	input.roots = set_roots;
	input.module = "fs-crypt";
	input.service = "fs-crypt";
	if (master_service_settings_read(master_service, &input,
					 &output, &error) < 0)
		i_fatal("Error reading configuration: %s", error);

	return master_service_settings_get_others(master_service)[0];
}

static
const char *mail_crypt_plugin_getenv(const struct fs_crypt_settings *set,
				     const char *name)
{
	const char *const *envs;
	unsigned int i, count;

	if (set == NULL)
		return NULL;

	if (!array_is_created(&set->plugin_envs))
		return NULL;

	envs = array_get(&set->plugin_envs, &count);
	for (i = 0; i < count; i += 2) {
		if (strcmp(envs[i], name) == 0)
			return envs[i+1];
	}
	return NULL;
}

static int
mail_crypt_load_global_private_keys(const struct fs_crypt_settings *set,
				    const char *set_prefix,
				    struct mail_crypt_global_keys *global_keys,
				    const char **error_r)
{
	string_t *set_key = t_str_new(64);
	str_append(set_key, set_prefix);
	str_append(set_key, "_private_key");
	size_t prefix_len = str_len(set_key);

	unsigned int i = 1;
	const char *key_data;
	while ((key_data = mail_crypt_plugin_getenv(set, str_c(set_key))) != NULL) {
		const char *set_pw = t_strconcat(str_c(set_key), "_password", NULL);
		const char *password = mail_crypt_plugin_getenv(set, set_pw);
		if (mail_crypt_load_global_private_key(str_c(set_key), key_data,
							set_pw, password,
							global_keys, error_r) < 0)
			return -1;
		str_truncate(set_key, prefix_len);
		str_printfa(set_key, "%u", ++i);
	}
	return 0;
}

int mail_crypt_global_keys_load_pluginenv(const char *set_prefix,
				struct mail_crypt_global_keys *global_keys_r,
				const char **error_r)
{
	const struct fs_crypt_settings *set = fs_crypt_load_settings();

	const char *set_key = t_strconcat(set_prefix, "_public_key", NULL);
	const char *key_data = mail_crypt_plugin_getenv(set, set_key);
	int ret = 0;

	mail_crypt_global_keys_init(global_keys_r);
	if (key_data != NULL) {
		if (mail_crypt_load_global_public_key(set_key, key_data,
						      global_keys_r, error_r) < 0)
			ret = -1;
	}

	if (ret == 0 &&
	    mail_crypt_load_global_private_keys(set, set_prefix, global_keys_r,
						error_r) < 0)
		ret = -1;

	mail_crypt_global_keys_free(global_keys_r);
	return ret;
}
