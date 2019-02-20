/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "dict.h"
#include "array.h"
#include "var-expand.h"
#include "mail-storage.h"
#include "mailbox-attribute.h"
#include "mail-crypt-common.h"
#include "mail-crypt-key.h"
#include "mail-crypt-plugin.h"
#include "mail-user.h"
#include "hex-binary.h"
#include "safe-memset.h"
#include "base64.h"
#include "sha2.h"

struct mail_crypt_key_cache_entry {
	struct mail_crypt_key_cache_entry *next;

	char *pubid;
	/* this is lazily initialized */
	struct dcrypt_keypair pair;
};

static
int mail_crypt_get_key_cache(struct mail_crypt_key_cache_entry *cache,
			     const char *pubid,
			     struct dcrypt_private_key **privkey_r,
			     struct dcrypt_public_key **pubkey_r)
{
	for(struct mail_crypt_key_cache_entry *ent = cache;
	    ent != NULL; ent = ent->next)
	{
		if (strcmp(pubid, ent->pubid) == 0) {
			if (privkey_r != NULL && ent->pair.priv != NULL) {
				dcrypt_key_ref_private(ent->pair.priv);
				*privkey_r = ent->pair.priv;
				return 1;
			} else if (pubkey_r != NULL && ent->pair.pub != NULL) {
				dcrypt_key_ref_public(ent->pair.pub);
				*pubkey_r = ent->pair.pub;
				return 1;
			} else if ((privkey_r == NULL && pubkey_r == NULL) ||
				   (ent->pair.priv == NULL &&
				   ent->pair.pub == NULL)) {
				i_unreached();
			}
		}
	}
	return 0;
}

static
void mail_crypt_put_key_cache(struct mail_crypt_key_cache_entry **cache,
			      const char *pubid,
			      struct dcrypt_private_key *privkey,
			      struct dcrypt_public_key *pubkey)
{
	for(struct mail_crypt_key_cache_entry *ent = *cache;
	    ent != NULL; ent = ent->next)
	{
		if (strcmp(pubid, ent->pubid) == 0) {
			if (privkey != NULL) {
				if (ent->pair.priv == NULL) {
					ent->pair.priv = privkey;
					dcrypt_key_ref_private(ent->pair.priv);
				}
			} else if (pubkey != NULL) {
				if (ent->pair.pub == NULL) {
					ent->pair.pub = pubkey;
					dcrypt_key_ref_public(ent->pair.pub);
				}
			} else
				i_unreached();
			return;
		}
	}

	/* not found */
	struct mail_crypt_key_cache_entry *ent =
		i_new(struct mail_crypt_key_cache_entry, 1);
	ent->pubid = i_strdup(pubid);
	ent->pair.priv = privkey;
	ent->pair.pub = pubkey;
	if (ent->pair.priv != NULL)
		dcrypt_key_ref_private(ent->pair.priv);
	if (ent->pair.pub != NULL)
		dcrypt_key_ref_public(ent->pair.pub);

	if (*cache == NULL) {
		*cache = ent;
	} else {
		ent->next = *cache;
		*cache = ent;
	}
}

void mail_crypt_key_cache_destroy(struct mail_crypt_key_cache_entry **cache)
{
	struct mail_crypt_key_cache_entry *next, *cur = *cache;

	*cache = NULL;

	while(cur != NULL) {
		next = cur->next;
		i_free(cur->pubid);
		if (cur->pair.priv != NULL)
			dcrypt_key_unref_private(&cur->pair.priv);
		if (cur->pair.pub != NULL)
			dcrypt_key_unref_public(&cur->pair.pub);
		i_free(cur);
		cur = next;
	}
}

int mail_crypt_private_key_id_match(struct dcrypt_private_key *key,
				     const char *pubid, const char **error_r)
{
	i_assert(key != NULL);
	buffer_t *key_id = t_str_new(MAIL_CRYPT_HASH_BUF_SIZE);
	if (!dcrypt_key_id_private(key, MAIL_CRYPT_KEY_ID_ALGORITHM, key_id,
				   error_r))
		return -1;
	const char *hash = binary_to_hex(key_id->data, key_id->used);
	if (strcmp(pubid, hash) == 0) return 1;

	buffer_set_used_size(key_id, 0);
	if (!dcrypt_key_id_private_old(key, key_id, error_r)) {
		return -1;
	}
	hash = binary_to_hex(key_id->data, key_id->used);

	if (strcmp(pubid, hash) != 0) {
		*error_r = t_strdup_printf("Key %s does not match given ID %s",
					   hash, pubid);
		return 0;
	}
	return 1;		
}

int mail_crypt_public_key_id_match(struct dcrypt_public_key *key,
				   const char *pubid, const char **error_r)
{
	i_assert(key != NULL);
	buffer_t *key_id = t_str_new(MAIL_CRYPT_HASH_BUF_SIZE);
	if (!dcrypt_key_id_public(key, MAIL_CRYPT_KEY_ID_ALGORITHM, key_id,
				  error_r))
		return -1;
	const char *hash = binary_to_hex(key_id->data, key_id->used);
	if (strcmp(pubid, hash) == 0) return 1;

	buffer_set_used_size(key_id, 0);
	if (!dcrypt_key_id_public_old(key, key_id, error_r)) {
		return -1;
	}
	hash = binary_to_hex(key_id->data, key_id->used);

	if (strcmp(pubid, hash) != 0) {
		*error_r = t_strdup_printf("Key %s does not match given ID %s",
					   hash, pubid);
		return 0;
	}
	return 1;
}

static
int mail_crypt_env_get_private_key(struct mail_user *user, const char *pubid,
				   struct dcrypt_private_key **key_r,
				   const char **error_r)
{
	struct mail_crypt_global_keys global_keys;
	int ret = 0;
	if (mail_crypt_global_keys_load(user, "mail_crypt", &global_keys,
					TRUE, error_r) < 0) {
		mail_crypt_global_keys_free(&global_keys);
		return -1;
	}

	/* see if we got a key */
	struct dcrypt_private_key *key =
		mail_crypt_global_key_find(&global_keys, pubid);

	if (key != NULL) {
		dcrypt_key_ref_private(key);
		*key_r = key;
		ret = 1;
	}

	mail_crypt_global_keys_free(&global_keys);

	return ret;
}

static
const char *mail_crypt_get_key_path(bool user_key, bool public, const char *pubid)
{
	const char *ret = t_strdup_printf("%s%s%s",
				user_key ? USER_CRYPT_PREFIX :
					  BOX_CRYPT_PREFIX,
				public ? PUBKEYS_PREFIX :
					  PRIVKEYS_PREFIX,
				pubid);
	return ret;
}

static
int mail_crypt_decrypt_private_key(struct mailbox *box, const char *pubid,
				   const char *data,
				   struct dcrypt_private_key **key_r,
				   const char **error_r)
{
	enum dcrypt_key_kind key_kind;
	enum dcrypt_key_encryption_type enc_type;
	const char *enc_hash = NULL, *key_hash = NULL, *pw = NULL;
	struct dcrypt_private_key *key = NULL, *dec_key = NULL;
	struct mail_user *user = mail_storage_get_user(mailbox_get_storage(box));
	int ret = 0;

	i_assert(pubid != NULL);
	i_assert(data != NULL);

	/* see what the key needs for decrypting */
	if (!dcrypt_key_string_get_info(data, NULL, NULL, &key_kind,
					&enc_type, &enc_hash, &key_hash, error_r)) {
		return -1;
	}

	if (key_kind != DCRYPT_KEY_KIND_PRIVATE) {
		*error_r = t_strdup_printf("Cannot use key %s: "
					   "Expected private key, got public key",
					   pubid);
		return -1;
	}

	if (key_hash != NULL && strcmp(key_hash, pubid) != 0) {
		*error_r = t_strdup_printf("Cannot use key %s: "
					   "Incorrect key hash %s stored",
					   pubid,
					   key_hash);
		return -1;
	}

	/* see if it needs decrypting */
	if (enc_type == DCRYPT_KEY_ENCRYPTION_TYPE_NONE) {
		/* no key or password */
	} else if (enc_type == DCRYPT_KEY_ENCRYPTION_TYPE_PASSWORD) {
		pw = mail_user_plugin_getenv(user, MAIL_CRYPT_USERENV_PASSWORD);
		if (pw == NULL) {
			*error_r = t_strdup_printf("Cannot decrypt key %s: "
						   "Password not available",
						   pubid);
			return -1;
		}
	} else if (enc_type == DCRYPT_KEY_ENCRYPTION_TYPE_KEY) {
		if ((ret = mail_crypt_user_get_private_key(user, enc_hash,
							   &dec_key, error_r)) <= 0) {
			/* last resort, look at environment */
			if (ret == 0 && (ret = mail_crypt_env_get_private_key(user, enc_hash,
								  &dec_key, error_r)) == 0) {
				*error_r = t_strdup_printf("Cannot decrypt key %s: "
							   "Private key %s not available:",
							   pubid, enc_hash);
				return -1;
			} else if (ret < 0) {
				*error_r =  t_strdup_printf("Cannot decrypt key %s: %s",
							    pubid, *error_r);
				return ret;
			}
		}
	}

	bool res = dcrypt_key_load_private(&key, data, pw, dec_key, error_r);

	if (dec_key != NULL)
		dcrypt_key_unref_private(&dec_key);

	if (!res)
		return -1;

	if (mail_crypt_private_key_id_match(key, pubid, error_r) <= 0) {
		if (key != NULL)
			dcrypt_key_unref_private(&key);
		return -1;
	}

	i_assert(key != NULL);

	*key_r = key;

	return 1;
}

int mail_crypt_get_private_key(struct mailbox *box, const char *pubid,
				bool user_key, bool shared,
				struct dcrypt_private_key **key_r,
				const char **error_r)
{
	struct mail_user *user = mail_storage_get_user(mailbox_get_storage(box));
	struct mail_crypt_user *muser = mail_crypt_get_mail_crypt_user(user);

	/* check cache */
	if (mail_crypt_get_key_cache(muser->key_cache, pubid, key_r, NULL) > 0) {
		return 1;
	}

	struct mail_attribute_value value;
	struct dcrypt_private_key *key;
	int ret;
	const char *attr_name = mail_crypt_get_key_path(user_key, FALSE, pubid);

	if ((ret = mailbox_attribute_get(box,
					 shared ? MAIL_ATTRIBUTE_TYPE_SHARED :
						  MAIL_ATTRIBUTE_TYPE_PRIVATE,
					 attr_name, &value)) <= 0) {
		if (ret < 0) {
			*error_r = t_strdup_printf("mailbox_attribute_get(%s, %s%s) failed: %s",
						   mailbox_get_vname(box),
						   shared ? "/shared/" :
							    "/priv/",
						   attr_name,
						   mailbox_get_last_internal_error(box, NULL));
		}
		return ret;
	}

	if ((ret = mail_crypt_decrypt_private_key(box, pubid, value.value,
						  &key, error_r)) <= 0)
		return ret;

	i_assert(key != NULL);

	mail_crypt_put_key_cache(&muser->key_cache, pubid, key, NULL);

	*key_r = key;

	return 1;
}

int mail_crypt_user_get_private_key(struct mail_user *user, const char *pubid,
				    struct dcrypt_private_key **key_r,
				    const char **error_r)
{
	struct mail_namespace *ns = mail_namespace_find_inbox(user->namespaces);
	struct mailbox *box = mailbox_alloc(ns->list, "INBOX",
					    MAILBOX_FLAG_READONLY);
	struct mail_attribute_value value;
	int ret;

	/* try retrieve currently active user key */
	if (mailbox_open(box) < 0) {
		*error_r = t_strdup_printf("mailbox_open(%s) failed: %s",
					   "INBOX",
					   mailbox_get_last_internal_error(box, NULL));
		return -1;
	}

	if (pubid == NULL) {
		if ((ret = mailbox_attribute_get(box, MAIL_ATTRIBUTE_TYPE_SHARED,
						 USER_CRYPT_PREFIX ACTIVE_KEY_NAME,
						 &value)) <= 0) {
			if (ret < 0) {
				*error_r = t_strdup_printf("mailbox_attribute_get(%s, /shared/%s) failed: %s",
							   mailbox_get_vname(box),
							   USER_CRYPT_PREFIX ACTIVE_KEY_NAME,
							   mailbox_get_last_internal_error(box, NULL));
			}
		} else {
			pubid = value.value;
			ret = 1;
		}
	} else
		ret = 1;

	/* try to open key */
	if (ret > 0)
		ret = mail_crypt_get_private_key(box, pubid, TRUE, FALSE,
						 key_r, error_r);
	mailbox_free(&box);
	return ret;
}

int mail_crypt_box_get_private_key(struct mailbox *box,
				   struct dcrypt_private_key **key_r,
				   const char **error_r)
{
	struct mail_attribute_value value;
	int ret;
	/* get active key */
	if ((ret = mailbox_attribute_get(box, MAIL_ATTRIBUTE_TYPE_SHARED,
					 BOX_CRYPT_PREFIX ACTIVE_KEY_NAME, &value)) <= 0) {
		if (ret < 0) {
			*error_r = t_strdup_printf("mailbox_attribute_get(%s, /shared/%s) failed: %s",
						   mailbox_get_vname(box),
						   USER_CRYPT_PREFIX ACTIVE_KEY_NAME,
						   mailbox_get_last_internal_error(box, NULL));
		}
		return ret;
	}

	return mail_crypt_get_private_key(box, value.value,
					  FALSE, FALSE,
					  key_r, error_r);
}

static
int mail_crypt_set_private_key(struct mailbox_transaction_context *t,
				bool user_key, bool shared, const char *pubid,
				struct dcrypt_public_key *enc_key,
				struct dcrypt_private_key *key,
				const char **error_r)
{
	/* folder keys must be encrypted with some other key,
	   unless they are shared keys */
	i_assert(user_key || shared || enc_key != NULL);

	buffer_t *data = t_str_new(MAIL_CRYPT_KEY_BUF_SIZE);
	const char *pw = NULL;
	const char *algo = NULL;
	struct mail_user *user = mail_storage_get_user(
					mailbox_get_storage(
						mailbox_transaction_get_mailbox(t)));
	const char *attr_name = mail_crypt_get_key_path(user_key, FALSE, pubid);
	struct mail_attribute_value value;
	int ret;

	if (enc_key != NULL) {
		algo = MAIL_CRYPT_KEY_CIPHER;
	} else if (user_key &&
		   (pw = mail_user_plugin_getenv(user,MAIL_CRYPT_USERENV_PASSWORD))
			!= NULL) {
		algo = MAIL_CRYPT_PW_CIPHER;
	}

	/* export key */
	if (!dcrypt_key_store_private(key, DCRYPT_FORMAT_DOVECOT, algo, data,
				      pw, enc_key, error_r)) {
		return -1;
	}

	/* store it */
	value.value_stream = NULL;
	value.value = str_c(data);
	value.last_change = 0;

	if ((ret = mailbox_attribute_set(t,
					 shared ? MAIL_ATTRIBUTE_TYPE_SHARED :
						  MAIL_ATTRIBUTE_TYPE_PRIVATE,
					 attr_name,
					 &value)) < 0) {
		*error_r = t_strdup_printf("mailbox_attribute_set(%s, %s/%s) failed: %s",
			   mailbox_get_vname(mailbox_transaction_get_mailbox(t)),
			   shared ? "/shared" : "/priv",
			   attr_name,
			   mailbox_get_last_internal_error(
				mailbox_transaction_get_mailbox(t), NULL));
	}

	safe_memset(buffer_get_modifiable_data(data, NULL), 0, data->used);

	return ret;
}

int mail_crypt_user_set_private_key(struct mail_user *user, const char *pubid,
				    struct dcrypt_private_key *key,
				    const char **error_r)
{
	struct mail_namespace *ns = mail_namespace_find_inbox(user->namespaces);
	struct mailbox *box = mailbox_alloc(ns->list, "INBOX",
					    MAILBOX_FLAG_READONLY);
	struct dcrypt_private_key *env_key = NULL;
	struct dcrypt_public_key *enc_key = NULL;
	struct mailbox_transaction_context *t;
	int ret;

	if ((ret = mail_crypt_env_get_private_key(user, NULL, &env_key,
						  error_r)) < 0) {
		return -1;
	} else if (ret > 0) {
		dcrypt_key_convert_private_to_public(env_key, &enc_key);
		dcrypt_key_unref_private(&env_key);
	}

	if (mail_user_plugin_getenv(user, MAIL_CRYPT_REQUIRE_ENCRYPTED_USER_KEY) != NULL &&
	    mail_user_plugin_getenv(user, MAIL_CRYPT_USERENV_PASSWORD) == NULL &&
	    mail_user_plugin_getenv(user, MAIL_CRYPT_USERENV_KEY) == NULL)
	{
		*error_r = MAIL_CRYPT_REQUIRE_ENCRYPTED_USER_KEY " set, cannot "
			   "generate user keypair without password or key";
		return -1;
	}

	if (mailbox_open(box) < 0) {
		*error_r = t_strdup_printf("mailbox_open(%s) failed: %s",
					   "INBOX",
					   mailbox_get_last_internal_error(box, NULL));
		return -1;
	}

	t = mailbox_transaction_begin(box, 0, __func__);

	if ((ret = mail_crypt_set_private_key(t, TRUE, FALSE, pubid, enc_key, key,
					      error_r)) < 0) {
		mailbox_transaction_rollback(&t);
	} else if ((ret = mailbox_transaction_commit(&t)) < 0) {
		*error_r = t_strdup_printf("mailbox_transaction_commit(%s) failed: %s",
					  mailbox_get_vname(box),
					  mailbox_get_last_internal_error(box, NULL));
	}

	mailbox_free(&box);

	return ret;
}

int mail_crypt_box_set_private_key(struct mailbox *box, const char *pubid,
				   struct dcrypt_private_key *key,
				   struct dcrypt_public_key *user_key,
				   const char **error_r)
{
	int ret;
	struct mailbox_transaction_context *t;

	t = mailbox_transaction_begin(box, 0, __func__);
	if ((ret = mail_crypt_set_private_key(t, FALSE, FALSE, pubid, user_key,
					      key, error_r)) < 0) {
		mailbox_transaction_rollback(&t);
	} else if ((ret = mailbox_transaction_commit(&t)) < 0) {
		*error_r = t_strdup_printf("mailbox_transaction_commit(%s) failed: %s",
					  mailbox_get_vname(box),
					  mailbox_get_last_internal_error(box, NULL));
	}

	return ret;
}

static
int mail_crypt_get_public_key(struct mailbox *box, const char *pubid,
			      bool user_key, struct dcrypt_public_key **key_r,
			      const char **error_r)
{
	struct mail_user *user = mail_storage_get_user(mailbox_get_storage(box));
	struct mail_crypt_user *muser = mail_crypt_get_mail_crypt_user(user);

	/* check cache */
	if (mail_crypt_get_key_cache(muser->key_cache, pubid, NULL, key_r) > 0) {
		return 1;
	}

	enum dcrypt_key_kind key_kind;
	const char *key_hash = NULL;
	struct dcrypt_public_key *key;
	struct mail_attribute_value value;
	int ret;
	const char *attr_name = mail_crypt_get_key_path(user_key, TRUE, pubid);

	if ((ret = mailbox_attribute_get(box,
					 MAIL_ATTRIBUTE_TYPE_SHARED,
					 attr_name, &value)) <= 0) {
		if (ret < 0) {
			*error_r = t_strdup_printf("mailbox_attribute_get(%s, %s) failed: %s",
						   mailbox_get_vname(box),
						   attr_name,
						   mailbox_get_last_internal_error(box, NULL));
		}
		return ret;
	}

	if (!dcrypt_key_string_get_info(value.value, NULL, NULL, &key_kind,
					NULL, NULL, &key_hash, error_r)) {
		return -1;
	}

	if (key_kind != DCRYPT_KEY_KIND_PUBLIC) {
		*error_r = t_strdup_printf("Cannot use key %s: "
					   "Expected public key, got private key",
					   pubid);
		return -1;
	}

	if (key_hash != NULL && strcmp(key_hash, pubid) != 0) {
		*error_r = t_strdup_printf("Cannot use key %s: "
					   "Incorrect key hash %s stored",
					   pubid, key_hash);
		return -1;
	}

	/* load the key */
	if (!dcrypt_key_load_public(&key, value.value, error_r)) {
		return -1;
	}

	if (pubid != NULL &&
	    mail_crypt_public_key_id_match(key, pubid, error_r) <= 0) {
		dcrypt_key_unref_public(&key);
		return -1;
	}

	mail_crypt_put_key_cache(&muser->key_cache, pubid, NULL, key);

	*key_r = key;

	return 1;
}

int mail_crypt_user_get_public_key(struct mail_user *user,
				   struct dcrypt_public_key **key_r,
				   const char **error_r)
{
	struct mail_namespace *ns = mail_namespace_find_inbox(user->namespaces);
	struct mailbox *box = mailbox_alloc(ns->list, "INBOX",
					    MAILBOX_FLAG_READONLY);
	struct mail_attribute_value value;
	int ret;

	/* try retrieve currently active user key */
	if (mailbox_open(box) < 0) {
		*error_r = t_strdup_printf("mailbox_open(%s) failed: %s",
					   "INBOX",
					   mailbox_get_last_internal_error(box, NULL));
		return -1;
	}

	if ((ret = mailbox_attribute_get(box, MAIL_ATTRIBUTE_TYPE_SHARED,
					 USER_CRYPT_PREFIX ACTIVE_KEY_NAME,
					 &value)) <= 0) {
		if (ret < 0) {
			*error_r = t_strdup_printf("mailbox_attribute_get(%s, /shared/%s) failed: %s",
						   mailbox_get_vname(box),
						   USER_CRYPT_PREFIX ACTIVE_KEY_NAME,
						   mailbox_get_last_internal_error(box, NULL));
		}
	} else {
		ret = mail_crypt_get_public_key(box, value.value, TRUE, key_r, error_r);
	}

	mailbox_free(&box);
	return ret;
}

int mail_crypt_box_get_public_key(struct mailbox *box,
				  struct dcrypt_public_key **key_r,
				  const char **error_r)
{
	struct mail_attribute_value value;
	int ret;

	if ((ret = mailbox_attribute_get(box, MAIL_ATTRIBUTE_TYPE_SHARED,
					 BOX_CRYPT_PREFIX ACTIVE_KEY_NAME,
					 &value)) <= 0) {
		if (ret < 0) {
			*error_r = t_strdup_printf("mailbox_attribute_get(%s, /shared/%s) failed: %s",
						   mailbox_get_vname(box),
						   BOX_CRYPT_PREFIX ACTIVE_KEY_NAME,
						   mailbox_get_last_internal_error(box, NULL));
		}
		return ret;
	}
	return mail_crypt_get_public_key(box, value.value, FALSE, key_r, error_r);
}

static
int mail_crypt_set_public_key(struct mailbox_transaction_context *t,
			      bool user_key, const char *pubid,
			      struct dcrypt_public_key *key,
			      const char **error_r)
{
	buffer_t *data = t_str_new(MAIL_CRYPT_KEY_BUF_SIZE);
	const char *attr_name = mail_crypt_get_key_path(user_key, TRUE, pubid);
	struct mail_attribute_value value;

	/* export key */
	if (!dcrypt_key_store_public(key, DCRYPT_FORMAT_DOVECOT, data,
				     error_r)) {
		return -1;
	}

	/* store it */
	value.value_stream = NULL;
	value.value = str_c(data);
	value.last_change = 0;

	if (mailbox_attribute_set(t,
				  MAIL_ATTRIBUTE_TYPE_SHARED,
				  attr_name,
				  &value) < 0) {
		*error_r = t_strdup_printf("mailbox_attribute_set(%s, %s/%s) failed: %s",
			   mailbox_get_vname(mailbox_transaction_get_mailbox(t)),
			   "/shared",
			   attr_name,
			   mailbox_get_last_internal_error(
				mailbox_transaction_get_mailbox(t), NULL));
		return -1;
	}

	return 0;
}

int mail_crypt_user_set_public_key(struct mail_user *user, const char *pubid,
				  struct dcrypt_public_key *key,
				  const char **error_r)
{
	struct mail_namespace *ns = mail_namespace_find_inbox(user->namespaces);
	struct mailbox *box = mailbox_alloc(ns->list, "INBOX",
					    MAILBOX_FLAG_READONLY);
	struct mailbox_transaction_context *t;
	struct mail_attribute_value value;
	int ret;

	/* try retrieve currently active user key */
	if (mailbox_open(box) < 0) {
		*error_r = t_strdup_printf("mailbox_open(%s) failed: %s",
					   "INBOX",
					   mailbox_get_last_internal_error(box, NULL));
		return -1;
	}

	t = mailbox_transaction_begin(box, 0, __func__);

	if ((ret = mail_crypt_set_public_key(t, TRUE, pubid, key,
					     error_r)) == 0) {
		value.value_stream = NULL;
		value.value = pubid;
		value.last_change = 0;

		if ((ret = mailbox_attribute_set(t, MAIL_ATTRIBUTE_TYPE_SHARED,
						 USER_CRYPT_PREFIX ACTIVE_KEY_NAME,
						 &value)) < 0) {
			*error_r = t_strdup_printf("mailbox_attribute_set(%s, /shared/%s) failed: %s",
						   mailbox_get_vname(box),
						   USER_CRYPT_PREFIX ACTIVE_KEY_NAME,
						   mailbox_get_last_internal_error(box, NULL));
		}
	}

	if (ret < 0) {
		mailbox_transaction_rollback(&t);
	} else if (mailbox_transaction_commit(&t) < 0) {
		*error_r = t_strdup_printf("mailbox_transaction_commit(%s) failed: %s",
					  mailbox_get_vname(box),
					  mailbox_get_last_internal_error(box, NULL));
		ret = -1;
	}

	mailbox_free(&box);

	return ret;
}

int mail_crypt_box_set_public_key(struct mailbox *box, const char *pubid,
				  struct dcrypt_public_key *key,
				  const char **error_r)
{
	int ret;
	struct mailbox_transaction_context *t;
	struct mail_attribute_value value;

	t = mailbox_transaction_begin(box, 0, __func__);
	if ((ret = mail_crypt_set_public_key(t, FALSE, pubid, key,
					     error_r)) == 0) {
		value.value_stream = NULL;
		value.value = pubid;
		value.last_change = 0;

		if ((ret = mailbox_attribute_set(t, MAIL_ATTRIBUTE_TYPE_SHARED,
						 BOX_CRYPT_PREFIX ACTIVE_KEY_NAME,
						 &value)) < 0) {
			*error_r = t_strdup_printf("mailbox_attribute_set(%s, /shared/%s) failed: %s",
						   mailbox_get_vname(box),
						   BOX_CRYPT_PREFIX ACTIVE_KEY_NAME,
						   mailbox_get_last_internal_error(box, NULL));
		}
	}

	if (ret < 0) {
		mailbox_transaction_rollback(&t);
	} else if (mailbox_transaction_commit(&t) < 0) {
		*error_r = t_strdup_printf("mailbox_transaction_commit(%s) failed: %s",
					  mailbox_get_vname(box),
					  mailbox_get_last_internal_error(box, NULL));
		ret = -1;
	}

	return ret;

}

static
int mail_crypt_user_set_keys(struct mail_user *user,
			     const char *pubid,
			     struct dcrypt_private_key *privkey,
			     struct dcrypt_public_key *pubkey,
			     const char **error_r)
{
	if (mail_crypt_user_set_private_key(user, pubid, privkey, error_r) < 0)
		return -1;
	if (mail_crypt_user_set_public_key(user, pubid, pubkey, error_r) < 0)
		return -1;
	return 0;
}

static
int mail_crypt_box_set_keys(struct mailbox *box,
			    const char *pubid,
			    struct dcrypt_private_key *privkey,
			    struct dcrypt_public_key *user_key,
			    struct dcrypt_public_key *pubkey,
			    const char **error_r)
{
	if (mail_crypt_box_set_private_key(box, pubid, privkey, user_key,
					   error_r) < 0)
		return -1;
	if (mail_crypt_box_set_public_key(box, pubid, pubkey, error_r) < 0)
		return -1;
	return 0;
}

int mail_crypt_box_get_shared_key(struct mailbox *box,
				  const char *pubid,
				  struct dcrypt_private_key **key_r,
				  const char **error_r)
{
	struct mail_user *user = mail_storage_get_user(mailbox_get_storage(box));
	struct mail_crypt_user *muser = mail_crypt_get_mail_crypt_user(user);

	struct dcrypt_private_key *key = NULL;
	struct mail_attribute_value value;
	int ret;

	/* check cache */
	if (mail_crypt_get_key_cache(muser->key_cache, pubid, key_r, NULL) > 0) {
		return 1;
	}

	const char *hexname =
		binary_to_hex((const unsigned char*)user->username,
			      strlen(user->username));

	const char *attr_name = t_strdup_printf(BOX_CRYPT_PREFIX
						PRIVKEYS_PREFIX"%s/%s",
						hexname,
						pubid);

	if ((ret = mailbox_attribute_get(box,
					MAIL_ATTRIBUTE_TYPE_SHARED,
					attr_name, &value)) <= 0) {
		if (ret < 0) {
			*error_r = t_strdup_printf("mailbox_attribute_get(%s, %s) failed: %s",
						mailbox_get_vname(box),
						attr_name,
						mailbox_get_last_internal_error(box, NULL));
			return ret;
		}
		return mail_crypt_get_private_key(box, pubid, FALSE, TRUE, key_r,
						  error_r);
	} else {
		if ((ret = mail_crypt_decrypt_private_key(box, pubid, value.value,
							  &key, error_r)) <= 0)
			return ret;
	}

	mail_crypt_put_key_cache(&muser->key_cache, pubid, key, NULL);

	*key_r = key;

	return 1;
}

int mail_crypt_box_set_shared_key(struct mailbox_transaction_context *t,
				  const char *pubid,
				  struct dcrypt_private_key *privkey,
				  const char *target_uid,
				  struct dcrypt_public_key *user_key,
				  const char **error_r)
{
	struct mail_attribute_value value;
	buffer_t *data = t_str_new(MAIL_CRYPT_KEY_BUF_SIZE);
	int ret;
	const char *attr_name;
	const char *algo = NULL;

	i_assert(target_uid == NULL || user_key != NULL);

	if (target_uid != NULL) {
		/* hash target UID */
		algo = MAIL_CRYPT_KEY_CIPHER;
		const char *hexname =
			binary_to_hex((const unsigned char*)target_uid,
				      strlen(target_uid));
		attr_name = t_strdup_printf(BOX_CRYPT_PREFIX
					    PRIVKEYS_PREFIX"%s/%s",
					    hexname,
					    pubid);
	} else {
		attr_name = t_strdup_printf(BOX_CRYPT_PREFIX
					    PRIVKEYS_PREFIX"%s",
					    pubid);
	}

	if (!dcrypt_key_store_private(privkey, DCRYPT_FORMAT_DOVECOT,
				      algo, data,
				      NULL, user_key, error_r)) {
		return -1;
	}
	
	value.value_stream = NULL;
	value.value = str_c(data);
	value.last_change = 0;

	if ((ret = mailbox_attribute_set(t, MAIL_ATTRIBUTE_TYPE_SHARED,
					 attr_name, &value)) < 0) {
		*error_r = t_strdup_printf("mailbox_attribute_set(%s, /shared/%s) failed: %s",
					   mailbox_get_vname(
						mailbox_transaction_get_mailbox(t)),
					   attr_name,
					   mailbox_get_last_internal_error(
						mailbox_transaction_get_mailbox(t),
						NULL));
	}

	safe_memset(buffer_get_modifiable_data(data, NULL), 0, data->used);

	return ret;
}

int mail_crypt_box_unset_shared_key(struct mailbox_transaction_context *t,
				    const char *pubid,
				    const char *target_uid,
				    const char **error_r)
{
	int ret;

	const char *hexname =
		binary_to_hex((const unsigned char*)target_uid,
			      strlen(target_uid));

	const char *attr_name = t_strdup_printf(BOX_CRYPT_PREFIX
						PRIVKEYS_PREFIX"%s/%s",
						hexname,
						pubid);

	if ((ret = mailbox_attribute_unset(t, MAIL_ATTRIBUTE_TYPE_SHARED,
					   attr_name)) <= 0) {
		if (ret < 0) {
			 *error_r = t_strdup_printf("mailbox_attribute_unset(%s, "
						    " /shared/%s): failed: %s",
						    mailbox_get_vname(
						    mailbox_transaction_get_mailbox(t)),
						    attr_name,
						    mailbox_get_last_internal_error(
						    mailbox_transaction_get_mailbox(t),
						    NULL));
		}
	}

	return ret;
}

static
int mail_crypt_generate_keypair(const char *curve,
				struct dcrypt_keypair *pair_r,
				const char **pubid_r,
				const char **error_r)
{
	if (curve == NULL) {
		*error_r = MAIL_CRYPT_USERENV_CURVE " not set, cannot generate EC key";
		return -1;
	}

	if (!dcrypt_keypair_generate(pair_r, DCRYPT_KEY_EC, 0, curve, error_r)) {
		return -1;
	}

	buffer_t *key_id = t_str_new(MAIL_CRYPT_HASH_BUF_SIZE);
	if (!dcrypt_key_id_public(pair_r->pub, MAIL_CRYPT_KEY_ID_ALGORITHM, key_id,
				  error_r)) {
		dcrypt_keypair_unref(pair_r);
		return -1;
	}

	*pubid_r = binary_to_hex(key_id->data, key_id->used);

	return 0;
}

int mail_crypt_user_generate_keypair(struct mail_user *user,
				     struct dcrypt_keypair *pair,
				     const char **pubid_r,
				     const char **error_r)
{
	struct mail_crypt_user *muser = mail_crypt_get_mail_crypt_user(user);
	const char *curve = mail_user_plugin_getenv(user, MAIL_CRYPT_USERENV_CURVE);

	if (mail_crypt_generate_keypair(curve, pair, pubid_r, error_r) < 0) {
		return -1;
	}

	if (mail_crypt_user_set_keys(user, *pubid_r,
				     pair->priv, pair->pub, error_r) < 0) {
		dcrypt_keypair_unref(pair);
		return -1;
	}

	mail_crypt_put_key_cache(&muser->key_cache, *pubid_r, pair->priv, pair->pub);

	return 0;
}

int mail_crypt_box_generate_keypair(struct mailbox *box,
				    struct dcrypt_keypair *pair,
				    struct dcrypt_public_key *user_key,
				    const char **pubid_r,
				    const char **error_r)
{
	int ret;
	struct mail_user *user = mail_storage_get_user(mailbox_get_storage(box));
	struct mail_crypt_user *muser = mail_crypt_get_mail_crypt_user(user);
	const char *curve = mail_user_plugin_getenv(user,
						    MAIL_CRYPT_USERENV_CURVE);

	if (user_key == NULL) {
		if ((ret = mail_crypt_user_get_public_key(user,
							  &user_key,
							  error_r)) <= 0) {
			if (ret < 0)
				return ret;
			/* generate keypair */
			struct dcrypt_keypair user_pair;
			const char *user_pubid;
			if (mail_crypt_user_generate_keypair(user, &user_pair,
							     &user_pubid,
							     error_r) < 0) {
				return -1;
			}

			mail_crypt_put_key_cache(&muser->key_cache, user_pubid,
						 user_pair.priv, user_pair.pub);

			user_key = user_pair.pub;
			dcrypt_key_unref_private(&user_pair.priv);
		}
	} else {
		dcrypt_key_ref_public(user_key);
	}

	if ((ret = mail_crypt_generate_keypair(curve, pair, pubid_r, error_r)) < 0) {
		/* failed */
	} else if ((ret = mail_crypt_box_set_keys(box, *pubid_r,
						pair->priv, user_key, pair->pub,
						error_r)) < 0) {
		dcrypt_keypair_unref(pair);
	} else {
		mail_crypt_put_key_cache(&muser->key_cache, *pubid_r, pair->priv,
					 pair->pub);
	}

	dcrypt_key_unref_public(&user_key);

	return ret;
}

int mail_crypt_box_get_pvt_digests(struct mailbox *box, pool_t pool,
				   enum mail_attribute_type type,
				   ARRAY_TYPE(const_string) *digests,
				   const char **error_r)
{
	struct mailbox_attribute_iter *iter;
	const char *key;
	int ret;

	iter = mailbox_attribute_iter_init(box, type,
					   BOX_CRYPT_PREFIX PRIVKEYS_PREFIX);
	while ((key = mailbox_attribute_iter_next(iter)) != NULL) {
		key = p_strdup(pool, key);
		array_push_back(digests, &key);
	}
	ret = mailbox_attribute_iter_deinit(&iter);
	if (ret < 0)
		*error_r = mailbox_get_last_internal_error(box, NULL);
	return ret;
}

int mail_crypt_box_get_private_keys(struct mailbox *box,
				    ARRAY_TYPE(dcrypt_private_key) *keys_r,
				    const char **error_r)
{
	struct mailbox_attribute_iter *iter;
	iter = mailbox_attribute_iter_init(box, MAIL_ATTRIBUTE_TYPE_PRIVATE,
					    BOX_CRYPT_PREFIX PRIVKEYS_PREFIX);
	const char *id;
	int ret;

	while ((id = mailbox_attribute_iter_next(iter)) != NULL) {
		struct dcrypt_private_key *key = NULL;
		if ((ret = mail_crypt_get_private_key(box, id, FALSE, FALSE,
						      &key, error_r)) < 0) {
			(void)mailbox_attribute_iter_deinit(&iter);
			return -1;
		} else if (ret > 0)
			array_push_back(keys_r, &key);
	}

	ret = mailbox_attribute_iter_deinit(&iter);
	if (ret < 0)
		*error_r = mailbox_get_last_internal_error(box, NULL);
	return ret;
}

int mail_crypt_box_share_private_keys(struct mailbox_transaction_context *t,
				      struct dcrypt_public_key *dest_pub_key,
				      const char *dest_user,
				      const ARRAY_TYPE(dcrypt_private_key) *priv_keys,
				      const char **error_r)
{
	i_assert(dest_user == NULL || dest_pub_key != NULL);

	struct dcrypt_private_key *const *priv_keyp, *priv_key;
	buffer_t *key_id = t_str_new(MAIL_CRYPT_HASH_BUF_SIZE);
	int ret = 0;

	array_foreach(priv_keys, priv_keyp) {
		priv_key = *priv_keyp;
		ret = -1;
		if (!dcrypt_key_id_private(priv_key, MAIL_CRYPT_KEY_ID_ALGORITHM,
					   key_id, error_r) ||
		    (ret = mail_crypt_box_set_shared_key(t,
							 binary_to_hex(key_id->data,
									key_id->used),
							 priv_key, dest_user,
							 dest_pub_key, error_r)) < 0)
			break;
	}

	return ret;
}

int
mail_crypt_user_get_or_gen_public_key(struct mail_user *user,
				      struct dcrypt_public_key **pub_r,
				      const char **error_r)
{
	i_assert(user != NULL);
	i_assert(pub_r != NULL);
	i_assert(error_r != NULL);

	int ret;
	if ((ret = mail_crypt_user_get_public_key(user, pub_r, error_r)) == 0) {
		struct dcrypt_keypair pair;
		const char *pubid = NULL;
		if (mail_crypt_user_generate_keypair(user, &pair,
						     &pubid, error_r) < 0) {
			return -1;
		}
		*pub_r = pair.pub;
		dcrypt_key_unref_private(&pair.priv);
	} else
		return ret;
	return 0;
}

int
mail_crypt_box_get_or_gen_public_key(struct mailbox *box,
				     struct dcrypt_public_key **pub_r,
				     const char **error_r)
{
	i_assert(box != NULL);
	i_assert(pub_r != NULL);
	i_assert(error_r != NULL);

	struct mail_user *user =
		mail_storage_get_user(mailbox_get_storage(box));
	int ret;
	if ((ret = mail_crypt_box_get_public_key(box, pub_r, error_r)) == 0) {
		struct dcrypt_public_key *user_key;
		if (mail_crypt_user_get_or_gen_public_key(user, &user_key,
							  error_r) < 0) {
			return -1;
		}

		struct dcrypt_keypair pair;
		const char *pubid = NULL;
		if (mail_crypt_box_generate_keypair(box, &pair, user_key,
						    &pubid, error_r) < 0) {
			return -1;
		}
		*pub_r = pair.pub;
		dcrypt_key_unref_public(&user_key);
		dcrypt_key_unref_private(&pair.priv);
	} else
		return ret;
	return 0;
}

bool mail_crypt_acl_secure_sharing_enabled(struct mail_user *user)
{
	const char *env =
		mail_user_plugin_getenv(user, MAIL_CRYPT_ACL_SECURE_SHARE_SETTING);

	/* disabled by default */
	bool ret = FALSE;

	if (env != NULL) {
		/* enable unless specifically
		     requested not to */
		ret = TRUE;
		switch (env[0]) {
			case 'n':
			case 'N':
			case '0':
			case 'f':
			case 'F':
			ret = FALSE;
		}
	}

	return ret;
}

static const struct mailbox_attribute_internal mailbox_internal_attributes[] = {
	{ .type = MAIL_ATTRIBUTE_TYPE_PRIVATE,
	  .key = BOX_CRYPT_PREFIX,
	  .flags = MAIL_ATTRIBUTE_INTERNAL_FLAG_CHILDREN
	},
	{ .type = MAIL_ATTRIBUTE_TYPE_SHARED,
	  .key = BOX_CRYPT_PREFIX,
	  .flags = MAIL_ATTRIBUTE_INTERNAL_FLAG_CHILDREN
	},
	{ .type = MAIL_ATTRIBUTE_TYPE_PRIVATE,
	  .key = USER_CRYPT_PREFIX,
	  .flags = MAIL_ATTRIBUTE_INTERNAL_FLAG_CHILDREN
	},
	{ .type = MAIL_ATTRIBUTE_TYPE_SHARED,
	  .key = USER_CRYPT_PREFIX,
	  .flags = MAIL_ATTRIBUTE_INTERNAL_FLAG_CHILDREN
	}
};

void mail_crypt_key_register_mailbox_internal_attributes(void)
{
	mailbox_attribute_register_internals(mailbox_internal_attributes,
		N_ELEMENTS(mailbox_internal_attributes));
}
