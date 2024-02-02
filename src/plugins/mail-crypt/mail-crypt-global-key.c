/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "hex-binary.h"
#include "base64.h"
#include "settings.h"
#include "mail-user.h"
#include "mail-crypt-common.h"
#include "mail-crypt-key.h"
#include "mail-crypt-plugin.h"

int mail_crypt_load_global_public_key(const char *set_key,
				      const struct settings_file *file,
				      struct mail_crypt_global_keys *global_keys,
				      const char **error_r)
{
	const char *error, *key_data = file->content;
	enum dcrypt_key_format format;
	enum dcrypt_key_kind kind;
	if (!dcrypt_key_string_get_info(key_data, &format, NULL,
					&kind, NULL, NULL, NULL, &error)) {
		key_data = str_c(t_base64_decode_str(key_data));
		if (!dcrypt_key_string_get_info(key_data, &format, NULL,
						&kind, NULL, NULL, NULL, &error)) {
			*error_r = t_strdup_printf("%s: Couldn't parse public key file %s: %s",
						   set_key, file->path, error);
			return -1;
		}
	}
	if (kind != DCRYPT_KEY_KIND_PUBLIC) {
		*error_r = t_strdup_printf("%s: key file %s is not public",
					   set_key, file->path);
		return -1;
	}
	if (!dcrypt_key_load_public(&global_keys->public_key, key_data, &error)) {
		*error_r = t_strdup_printf("%s: Couldn't load public key file %s: %s",
					   set_key, file->path, error);
		return -1;
	}
	return 0;
}

static int
mail_crypt_key_get_ids(struct dcrypt_private_key *key,
			const char **key_id_r, const char **key_id_old_r,
			const char **error_r)
{
	const char *error;
	buffer_t *key_id;

	*key_id_r = NULL;
	*key_id_old_r = NULL;

	/* new key ID */
	key_id = t_buffer_create(MAIL_CRYPT_HASH_BUF_SIZE);
	if (!dcrypt_key_id_private(key, MAIL_CRYPT_KEY_ID_ALGORITHM, key_id, &error)) {
		*error_r = t_strdup_printf("Failed to get private key ID: %s", error);
		return -1;
	}
	*key_id_r = binary_to_hex(key_id->data, key_id->used);

	buffer_set_used_size(key_id, 0);

	/* old key ID */
	if (dcrypt_key_type_private(key) != DCRYPT_KEY_EC)
		return 0;

	if (!dcrypt_key_id_private_old(key, key_id, &error)) {
		*error_r = t_strdup_printf("Failed to get private key old ID: %s",
					   error);
		return -1;
	}
	*key_id_old_r = binary_to_hex(key_id->data, key_id->used);
	return 0;
}

int mail_crypt_load_global_private_key(const char *set_key,
				       const struct settings_file *file,
				       const char *key_password,
				       struct mail_crypt_global_keys *global_keys,
				       const char **error_r)
{
	const char *key_data = file->content;
	enum dcrypt_key_format format;
	enum dcrypt_key_kind kind;
	enum dcrypt_key_encryption_type enc_type;
	const char *error;

	if (!dcrypt_key_string_get_info(key_data, &format, NULL, &kind,
				&enc_type, NULL, NULL, &error)) {
		key_data = str_c(t_base64_decode_str(key_data));
		if (!dcrypt_key_string_get_info(key_data, &format, NULL, &kind,
					&enc_type, NULL, NULL, &error)) {
			*error_r = t_strdup_printf(
				"%s: Couldn't parse private key %s: %s",
				set_key, file->path, error);
			return -1;
		}
	}
	if (kind != DCRYPT_KEY_KIND_PRIVATE) {
		*error_r = t_strdup_printf(
			"%s: file %s is not a private key",
			set_key, file->path);
		return -1;
	}

	if (enc_type == DCRYPT_KEY_ENCRYPTION_TYPE_PASSWORD) {
		/* Fail here if password is not set since openssl will prompt
		 * for it otherwise */
		if (key_password[0] == '\0') {
			*error_r = t_strdup_printf(
				"%s: crypt_private_key_password unset, no password to decrypt the key file %s",
				set_key, file->path);
			return -1;
		}
	}

	struct dcrypt_private_key *key = NULL;
	if (!dcrypt_key_load_private(&key, key_data, key_password, NULL, &error)) {
		*error_r = t_strdup_printf(
			"%s: Couldn't load private key file %s: %s",
			set_key, file->path, error);
		return -1;
	}

	const char *key_id, *key_id_old;
	if (mail_crypt_key_get_ids(key, &key_id, &key_id_old, error_r) < 0) {
		dcrypt_key_unref_private(&key);
		return -1;
	}

	struct mail_crypt_global_private_key *priv_key =
		array_append_space(&global_keys->private_keys);
	priv_key->key = key;
	priv_key->key_id = i_strdup(key_id);
	priv_key->key_id_old = i_strdup(key_id_old);
	return 0;
}

int mail_crypt_global_keys_load(struct event *event,
				const struct crypt_settings *set,
				struct mail_crypt_global_keys *global_keys_r,
				const char **error_r)
{
	const struct crypt_private_key_settings *key_set;
	struct settings_file file;
	const char *key_name, *error;

	mail_crypt_global_keys_init(global_keys_r);
	if (set->crypt_global_public_key_file[0] != '\0') {
		settings_file_get(set->crypt_global_public_key_file,
				  unsafe_data_stack_pool, &file);
		if (mail_crypt_load_global_public_key(
				"crypt_global_public_key", &file, global_keys_r,
				error_r) < 0)
			return -1;
	}

	if (!array_is_created(&set->crypt_global_private_keys))
		return 0;
	array_foreach_elem(&set->crypt_global_private_keys, key_name) {
		if (settings_get_filter(event, "crypt_global_private_key",
					key_name,
					&crypt_private_key_setting_parser_info,
					0, &key_set, &error) < 0) {
			*error_r = t_strdup_printf(
				"Failed to get crypt_private_key %s: %s",
				key_name, error);
			return -1;
		}
		settings_file_get(key_set->crypt_private_key_file,
				  unsafe_data_stack_pool, &file);
		if (mail_crypt_load_global_private_key(
				key_name, &file,
				key_set->crypt_private_key_password,
				global_keys_r, error_r) < 0) {
			settings_free(key_set);
			return -1;
		}
		settings_free(key_set);
	}
	return 0;
}

void mail_crypt_global_keys_init(struct mail_crypt_global_keys *global_keys_r)
{
	i_zero(global_keys_r);
	i_array_init(&global_keys_r->private_keys, 4);
}

void mail_crypt_global_keys_free(struct mail_crypt_global_keys *global_keys)
{
	struct mail_crypt_global_private_key *priv_key;

	if (global_keys->public_key != NULL)
		dcrypt_key_unref_public(&global_keys->public_key);

	if (!array_is_created(&global_keys->private_keys))
		return;
	array_foreach_modifiable(&global_keys->private_keys, priv_key) {
		dcrypt_key_unref_private(&priv_key->key);
		i_free(priv_key->key_id);
		i_free(priv_key->key_id_old);
	}
	array_free(&global_keys->private_keys);
}

struct dcrypt_private_key *
mail_crypt_global_key_find(struct mail_crypt_global_keys *global_keys,
			   const char *pubkey_digest)
{
	const struct mail_crypt_global_private_key *priv_key;

	if (!array_is_created(&global_keys->private_keys))
		return NULL;

	array_foreach(&global_keys->private_keys, priv_key) {
		if (strcmp(priv_key->key_id, pubkey_digest) == 0)
			return priv_key->key;
		if (priv_key->key_id_old != NULL &&
		    strcmp(priv_key->key_id_old, pubkey_digest) == 0)
			return priv_key->key;
	}
	return NULL;
}
