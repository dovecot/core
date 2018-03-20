/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */
#include "lib.h"
#include "str.h"
#include "mail-user.h"
#include "mail-crypt-common.h"
#include "mail-crypt-key.h"

static int
mail_crypt_load_global_private_keys(struct mail_user *user,
				    const char *set_prefix,
				    struct mail_crypt_global_keys *global_keys,
				    bool ignore_errors,
				    const char **error_r)
{
	string_t *set_key = t_str_new(64);
	str_append(set_key, set_prefix);
	str_append(set_key, "_private_key");
	size_t prefix_len = str_len(set_key);

	unsigned int i = 1;
	const char *key_data;
	while ((key_data = mail_user_plugin_getenv(user, str_c(set_key))) != NULL) {
		const char *set_pw = t_strconcat(str_c(set_key), "_password", NULL);
		const char *password = mail_user_plugin_getenv(user, set_pw);
		if (mail_crypt_load_global_private_key(str_c(set_key), key_data,
							set_pw, password,
							global_keys,
							error_r) < 0) {
			/* skip this key */
			if (ignore_errors) {
				e_debug(user->event, "mail-crypt-plugin: "
					"mail_crypt_load_global_private_key failed: %s",
					*error_r);
				*error_r = NULL;
				continue;
			}
			return -1;
		}
		str_truncate(set_key, prefix_len);
		str_printfa(set_key, "%u", ++i);
	}
	return 0;
}

int mail_crypt_global_keys_load(struct mail_user *user, const char *set_prefix,
				struct mail_crypt_global_keys *global_keys_r,
				bool ignore_privkey_errors,
				const char **error_r)
{
	const char *set_key = t_strconcat(set_prefix, "_public_key", NULL);
	const char *key_data = mail_user_plugin_getenv(user, set_key);

	mail_crypt_global_keys_init(global_keys_r);
	if (key_data != NULL) {
		if (mail_crypt_load_global_public_key(set_key,
						      key_data,
						      global_keys_r,
						      error_r) < 0)
			return -1;
	}
	if (mail_crypt_load_global_private_keys(user, set_prefix, global_keys_r,
						ignore_privkey_errors,
						error_r) < 0)
		return -1;
	return 0;
}
