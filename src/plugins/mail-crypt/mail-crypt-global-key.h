#ifndef MAIL_CRYPT_GLOBAL_KEY_H
#define MAIL_CRYPT_GLOBAL_KEY_H

struct settings_file;
struct crypt_settings;

struct mail_crypt_global_private_key {
	struct dcrypt_private_key *key;
	char *key_id, *key_id_old;
};

struct mail_crypt_global_keys {
	struct dcrypt_public_key *public_key;
	ARRAY(struct mail_crypt_global_private_key) private_keys;
};

struct mail_user;

int mail_crypt_global_keys_load(struct event *event,
				const struct crypt_settings *set,
				struct mail_crypt_global_keys *global_keys_r,
				const char **error_r);

int mail_crypt_global_keys_load_from_user(struct mail_user *user,
					  const char *set_prefix,
					  struct mail_crypt_global_keys *global_keys_r,
					  bool ignore_privkey_errors,
					  const char **error_r);
void mail_crypt_global_keys_init(struct mail_crypt_global_keys *global_keys_r);
void mail_crypt_global_keys_free(struct mail_crypt_global_keys *global_keys);

int mail_crypt_load_global_public_key(const char *set_key,
				      const struct settings_file *file,
				      struct mail_crypt_global_keys *global_keys,
				      const char **error_r);
int mail_crypt_load_global_private_key(const char *set_key,
				       const struct settings_file *file,
					const char *key_password,
					struct mail_crypt_global_keys *global_keys,
					const char **error_r);

struct dcrypt_private_key *
mail_crypt_global_key_find(struct mail_crypt_global_keys *global_keys,
			   const char *pubkey_digest);

#endif
