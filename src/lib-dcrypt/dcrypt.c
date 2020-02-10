/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "module-dir.h"
#include "dcrypt.h"
#include "istream.h"
#include "json-tree.h"
#include "dcrypt-private.h"

static struct module *dcrypt_module = NULL;
static struct dcrypt_vfs *dcrypt_vfs = NULL;
static const struct dcrypt_settings dcrypt_default_set = {
	.module_dir = DCRYPT_MODULE_DIR,
};

bool dcrypt_initialize(const char *backend, const struct dcrypt_settings *set,
		       const char **error_r)
{
	struct module_dir_load_settings mod_set;
	const char *error;

	if (dcrypt_vfs != NULL) {
		return TRUE;
	}
	if (backend == NULL) backend = "openssl"; /* default for now */
	if (set == NULL)
		set = &dcrypt_default_set;

	const char *implementation = t_strconcat("dcrypt_",backend,NULL);

	i_zero(&mod_set);
	mod_set.abi_version = DOVECOT_ABI_VERSION;
	mod_set.require_init_funcs = TRUE;
	if (module_dir_try_load_missing(&dcrypt_module, set->module_dir,
					implementation, &mod_set, &error) < 0) {
		if (error_r != NULL)
			*error_r = error;
		return FALSE;
	}
	module_dir_init(dcrypt_module);
	i_assert(dcrypt_vfs != NULL);
	if (dcrypt_vfs->initialize != NULL) {
		if (!dcrypt_vfs->initialize(set, error_r)) {
			dcrypt_deinitialize();
			return FALSE;
		}
	}
	/* Destroy SSL module after(most of) the others. Especially lib-fs
	   backends may still want to access SSL module in their own
	   atexit-callbacks. */
	lib_atexit_priority(dcrypt_deinitialize, LIB_ATEXIT_PRIORITY_LOW);
	return TRUE;
}

void dcrypt_deinitialize(void)
{
	module_dir_unload(&dcrypt_module);
	dcrypt_vfs = NULL;
}

void dcrypt_set_vfs(struct dcrypt_vfs *vfs)
{
	dcrypt_vfs = vfs;
}

bool dcrypt_is_initialized(void)
{
	return dcrypt_vfs != NULL;
}

bool dcrypt_ctx_sym_create(const char *algorithm, enum dcrypt_sym_mode mode,
			   struct dcrypt_context_symmetric **ctx_r,
			   const char **error_r)
{
	i_assert(dcrypt_vfs != NULL);
	return dcrypt_vfs->ctx_sym_create(algorithm, mode, ctx_r, error_r);
}

void dcrypt_ctx_sym_destroy(struct dcrypt_context_symmetric **ctx)
{
	i_assert(dcrypt_vfs != NULL);
	dcrypt_vfs->ctx_sym_destroy(ctx);
}

void dcrypt_ctx_sym_set_key(struct dcrypt_context_symmetric *ctx,
			    const unsigned char *key, size_t key_len)
{
	i_assert(dcrypt_vfs != NULL);
	dcrypt_vfs->ctx_sym_set_key(ctx, key, key_len);
}

void dcrypt_ctx_sym_set_iv(struct dcrypt_context_symmetric *ctx,
			   const unsigned char *iv, size_t iv_len)
{
	i_assert(dcrypt_vfs != NULL);
	dcrypt_vfs->ctx_sym_set_iv(ctx, iv, iv_len);
}

void dcrypt_ctx_sym_set_key_iv_random(struct dcrypt_context_symmetric *ctx)
{
	i_assert(dcrypt_vfs != NULL);
	dcrypt_vfs->ctx_sym_set_key_iv_random(ctx);
}

bool dcrypt_ctx_sym_get_key(struct dcrypt_context_symmetric *ctx, buffer_t *key)
{
	i_assert(dcrypt_vfs != NULL);
	return dcrypt_vfs->ctx_sym_get_key(ctx, key);
}
bool dcrypt_ctx_sym_get_iv(struct dcrypt_context_symmetric *ctx, buffer_t *iv)
{
	i_assert(dcrypt_vfs != NULL);
	return dcrypt_vfs->ctx_sym_get_iv(ctx, iv);
}

unsigned int dcrypt_ctx_sym_get_key_length(struct dcrypt_context_symmetric *ctx)
{
	i_assert(dcrypt_vfs != NULL);
	return dcrypt_vfs->ctx_sym_get_key_length(ctx);
}

unsigned int dcrypt_ctx_sym_get_iv_length(struct dcrypt_context_symmetric *ctx)
{
	i_assert(dcrypt_vfs != NULL);
	return dcrypt_vfs->ctx_sym_get_iv_length(ctx);
}

void dcrypt_ctx_sym_set_aad(struct dcrypt_context_symmetric *ctx,
			    const unsigned char *aad, size_t aad_len)
{
	i_assert(dcrypt_vfs != NULL);
	dcrypt_vfs->ctx_sym_set_aad(ctx, aad, aad_len);
}

bool dcrypt_ctx_sym_get_aad(struct dcrypt_context_symmetric *ctx, buffer_t *aad)
{
	i_assert(dcrypt_vfs != NULL);
	return dcrypt_vfs->ctx_sym_get_aad(ctx, aad);
}

void dcrypt_ctx_sym_set_tag(struct dcrypt_context_symmetric *ctx,
			    const unsigned char *tag, size_t tag_len)
{
	i_assert(dcrypt_vfs != NULL);
	dcrypt_vfs->ctx_sym_set_tag(ctx, tag, tag_len);
}

bool dcrypt_ctx_sym_get_tag(struct dcrypt_context_symmetric *ctx, buffer_t *tag)
{
	i_assert(dcrypt_vfs != NULL);
	return dcrypt_vfs->ctx_sym_get_tag(ctx, tag);
}

unsigned int dcrypt_ctx_sym_get_block_size(struct dcrypt_context_symmetric *ctx)
{
	i_assert(dcrypt_vfs != NULL);
	return dcrypt_vfs->ctx_sym_get_block_size(ctx);
}

bool dcrypt_ctx_sym_init(struct dcrypt_context_symmetric *ctx,
			 const char **error_r)
{
	i_assert(dcrypt_vfs != NULL);
	return dcrypt_vfs->ctx_sym_init(ctx, error_r);
}

bool dcrypt_ctx_sym_update(struct dcrypt_context_symmetric *ctx,
			   const unsigned char *data,
			   size_t data_len, buffer_t *result,
			   const char **error_r)
{
	i_assert(dcrypt_vfs != NULL);
	return dcrypt_vfs->ctx_sym_update(ctx, data, data_len, result, error_r);
}

bool dcrypt_ctx_sym_final(struct dcrypt_context_symmetric *ctx,
			  buffer_t *result, const char **error_r)
{
	i_assert(dcrypt_vfs != NULL);
	return dcrypt_vfs->ctx_sym_final(ctx, result, error_r);
}

void dcrypt_ctx_sym_set_padding(struct dcrypt_context_symmetric *ctx,
				bool padding)
{
	i_assert(dcrypt_vfs != NULL);
	dcrypt_vfs->ctx_sym_set_padding(ctx, padding);
}

bool dcrypt_ctx_hmac_create(const char *algorithm,
			    struct dcrypt_context_hmac **ctx_r,
			    const char **error_r)
{
	i_assert(dcrypt_vfs != NULL);
	return dcrypt_vfs->ctx_hmac_create(algorithm, ctx_r, error_r);
}

void dcrypt_ctx_hmac_destroy(struct dcrypt_context_hmac **ctx)
{
	i_assert(dcrypt_vfs != NULL);
	dcrypt_vfs->ctx_hmac_destroy(ctx);
}

void dcrypt_ctx_hmac_set_key(struct dcrypt_context_hmac *ctx,
			     const unsigned char *key, size_t key_len)
{
	i_assert(dcrypt_vfs != NULL);
	dcrypt_vfs->ctx_hmac_set_key(ctx, key, key_len);
}

bool dcrypt_ctx_hmac_get_key(struct dcrypt_context_hmac *ctx, buffer_t *key)
{
	i_assert(dcrypt_vfs != NULL);
	return dcrypt_vfs->ctx_hmac_get_key(ctx, key);
}

void dcrypt_ctx_hmac_set_key_random(struct dcrypt_context_hmac *ctx)
{
	i_assert(dcrypt_vfs != NULL);
	dcrypt_vfs->ctx_hmac_set_key_random(ctx);
}

unsigned int dcrypt_ctx_hmac_get_digest_length(struct dcrypt_context_hmac *ctx)
{
	i_assert(dcrypt_vfs != NULL);
	return dcrypt_vfs->ctx_hmac_get_digest_length(ctx);
}

bool dcrypt_ctx_hmac_init(struct dcrypt_context_hmac *ctx, const char **error_r)
{
	i_assert(dcrypt_vfs != NULL);
	return dcrypt_vfs->ctx_hmac_init(ctx, error_r);
}

bool dcrypt_ctx_hmac_update(struct dcrypt_context_hmac *ctx,
			    const unsigned char *data, size_t data_len,
			    const char **error_r)
{
	i_assert(dcrypt_vfs != NULL);
	return dcrypt_vfs->ctx_hmac_update(ctx, data, data_len, error_r);
}

bool dcrypt_ctx_hmac_final(struct dcrypt_context_hmac *ctx, buffer_t *result,
			   const char **error_r)
{
	i_assert(dcrypt_vfs != NULL);
	return dcrypt_vfs->ctx_hmac_final(ctx, result, error_r);
}

bool dcrypt_ecdh_derive_secret(struct dcrypt_private_key *local_key,
			       struct dcrypt_public_key *pub_key,
			       buffer_t *shared_secret,
			       const char **error_r)
{
	i_assert(dcrypt_vfs != NULL);
	if (dcrypt_vfs->ecdh_derive_secret == NULL) {
		*error_r = "Not implemented";
		return FALSE;
	}
	return dcrypt_vfs->ecdh_derive_secret(local_key, pub_key, shared_secret,
					      error_r);
}

bool dcrypt_ecdh_derive_secret_local(struct dcrypt_private_key *local_key,
				     buffer_t *R, buffer_t *S,
				     const char **error_r)
{
	i_assert(dcrypt_vfs != NULL);
	return dcrypt_vfs->ecdh_derive_secret_local(local_key, R, S, error_r);
}
bool dcrypt_ecdh_derive_secret_peer(struct dcrypt_public_key *peer_key,
				    buffer_t *R, buffer_t *S,
				    const char **error_r)
{
	i_assert(dcrypt_vfs != NULL);
	return dcrypt_vfs->ecdh_derive_secret_peer(peer_key, R, S, error_r);
}

bool dcrypt_pbkdf2(const unsigned char *password, size_t password_len,
		   const unsigned char *salt, size_t salt_len,
		   const char *hash, unsigned int rounds, buffer_t *result,
		   unsigned int result_len, const char **error_r)
{
	i_assert(dcrypt_vfs != NULL);
	return dcrypt_vfs->pbkdf2(password, password_len, salt, salt_len,
				  hash, rounds, result, result_len, error_r);
}

bool dcrypt_keypair_generate(struct dcrypt_keypair *pair_r,
			     enum dcrypt_key_type kind, unsigned int bits,
			     const char *curve, const char **error_r)
{
	i_assert(dcrypt_vfs != NULL);
	i_zero(pair_r);
	return dcrypt_vfs->generate_keypair(pair_r, kind, bits, curve, error_r);
}

bool dcrypt_key_load_private(struct dcrypt_private_key **key_r,
			     const char *data, const char *password,
			     struct dcrypt_private_key *dec_key,
			     const char **error_r)
{
	i_assert(dcrypt_vfs != NULL);
	return dcrypt_vfs->load_private_key(key_r, data, password,
					    dec_key, error_r);
}

bool dcrypt_key_load_public(struct dcrypt_public_key **key_r,
			    const char *data, const char **error_r)
{
	i_assert(dcrypt_vfs != NULL);
	return dcrypt_vfs->load_public_key(key_r, data, error_r);
}

bool dcrypt_key_store_private(struct dcrypt_private_key *key,
			      enum dcrypt_key_format format,
			      const char *cipher, buffer_t *destination,
			      const char *password,
			      struct dcrypt_public_key *enc_key,
			      const char **error_r)
{
	i_assert(dcrypt_vfs != NULL);
	return dcrypt_vfs->store_private_key(key, format, cipher,
					     destination, password, enc_key,
					     error_r);
}
bool dcrypt_key_store_public(struct dcrypt_public_key *key,
			     enum dcrypt_key_format format,
			     buffer_t *destination, const char **error_r)
{
	i_assert(dcrypt_vfs != NULL);
	return dcrypt_vfs->store_public_key(key, format, destination, error_r);
}

void dcrypt_key_convert_private_to_public(struct dcrypt_private_key *priv_key,
					  struct dcrypt_public_key **pub_key_r)
{
	i_assert(dcrypt_vfs != NULL);
	dcrypt_vfs->private_to_public_key(priv_key, pub_key_r);
}

bool dcrypt_key_string_get_info(const char *key_data,
				enum dcrypt_key_format *format_r,
				enum dcrypt_key_version *version_r,
				enum dcrypt_key_kind *kind_r,
				enum dcrypt_key_encryption_type *encryption_type_r,
				const char **encryption_key_hash_r,
				const char **key_hash_r, const char **error_r)
{
	i_assert(dcrypt_vfs != NULL);
	return dcrypt_vfs->
		key_string_get_info(key_data, format_r, version_r, kind_r,
				    encryption_type_r, encryption_key_hash_r,
				    key_hash_r, error_r);
}

enum dcrypt_key_type dcrypt_key_type_private(struct dcrypt_private_key *key)
{
	i_assert(dcrypt_vfs != NULL);
	return dcrypt_vfs->private_key_type(key);
}

enum dcrypt_key_type dcrypt_key_type_public(struct dcrypt_public_key *key)
{
	i_assert(dcrypt_vfs != NULL);
	return dcrypt_vfs->public_key_type(key);
}

bool dcrypt_key_id_public(struct dcrypt_public_key *key, const char *algorithm,
			  buffer_t *result, const char **error_r)
{
	i_assert(dcrypt_vfs != NULL);
	return dcrypt_vfs->public_key_id(key, algorithm, result, error_r);
}

bool dcrypt_key_id_public_old(struct dcrypt_public_key *key, buffer_t *result,
			      const char **error_r)
{
	i_assert(dcrypt_vfs != NULL);
	return dcrypt_vfs->public_key_id_old(key, result, error_r);
}

bool dcrypt_key_id_private(struct dcrypt_private_key *key,
			   const char *algorithm, buffer_t *result,
			   const char **error_r)
{
	i_assert(dcrypt_vfs != NULL);
	return dcrypt_vfs->private_key_id(key, algorithm, result, error_r);
}

bool dcrypt_key_id_private_old(struct dcrypt_private_key *key, buffer_t *result,
			       const char **error_r)
{
	i_assert(dcrypt_vfs != NULL);
	return dcrypt_vfs->private_key_id_old(key, result, error_r);
}

void dcrypt_keypair_unref(struct dcrypt_keypair *keypair)
{
	i_assert(dcrypt_vfs != NULL);
	dcrypt_vfs->unref_keypair(keypair);
}

void dcrypt_key_ref_public(struct dcrypt_public_key *key)
{
	i_assert(dcrypt_vfs != NULL);
	dcrypt_vfs->ref_public_key(key);
}

void dcrypt_key_ref_private(struct dcrypt_private_key *key)
{
	i_assert(dcrypt_vfs != NULL);
	dcrypt_vfs->ref_private_key(key);
}

void dcrypt_key_unref_public(struct dcrypt_public_key **key)
{
	i_assert(dcrypt_vfs != NULL);
	dcrypt_vfs->unref_public_key(key);
}

void dcrypt_key_unref_private(struct dcrypt_private_key **key)
{
	i_assert(dcrypt_vfs != NULL);
	dcrypt_vfs->unref_private_key(key);
}

bool dcrypt_rsa_encrypt(struct dcrypt_public_key *key,
			const unsigned char *data, size_t data_len,
			buffer_t *result, enum dcrypt_padding padding,
			const char **error_r)
{
	i_assert(dcrypt_vfs != NULL);
	return dcrypt_vfs->rsa_encrypt(key, data, data_len, result,
				       padding, error_r);
}

bool dcrypt_rsa_decrypt(struct dcrypt_private_key *key,
			const unsigned char *data, size_t data_len,
			buffer_t *result, enum dcrypt_padding padding,
			const char **error_r)
{
	i_assert(dcrypt_vfs != NULL);
	return dcrypt_vfs->rsa_decrypt(key, data, data_len, result,
				       padding, error_r);
}

const char *dcrypt_oid2name(const unsigned char *oid, size_t oid_len,
			    const char **error_r)
{
	i_assert(dcrypt_vfs != NULL);
	return dcrypt_vfs->oid2name(oid, oid_len, error_r);
}

bool dcrypt_name2oid(const char *name, buffer_t *oid, const char **error_r)
{
	i_assert(dcrypt_vfs != NULL);
	return dcrypt_vfs->name2oid(name, oid, error_r);
}

bool dcrypt_key_store_private_raw(struct dcrypt_private_key *key,
				  pool_t pool,
				  enum dcrypt_key_type *key_type_r,
				  ARRAY_TYPE(dcrypt_raw_key) *keys_r,
				  const char **error_r)
{
	i_assert(dcrypt_vfs != NULL);
	if (dcrypt_vfs->key_store_private_raw == NULL) {
		*error_r = "Not implemented";
		return FALSE;
	}
	return dcrypt_vfs->key_store_private_raw(key, pool, key_type_r, keys_r,
						 error_r);
}

bool dcrypt_key_store_public_raw(struct dcrypt_public_key *key,
				 pool_t pool,
				 enum dcrypt_key_type *key_type_r,
				 ARRAY_TYPE(dcrypt_raw_key) *keys_r,
				 const char **error_r)
{
	i_assert(dcrypt_vfs != NULL);
	if (dcrypt_vfs->key_store_public_raw == NULL) {
		*error_r = "Not implemented";
		return FALSE;
	}
	return dcrypt_vfs->key_store_public_raw(key, pool, key_type_r, keys_r,
						error_r);
}

bool dcrypt_key_load_private_raw(struct dcrypt_private_key **key_r,
				 enum dcrypt_key_type key_type,
				 const ARRAY_TYPE(dcrypt_raw_key) *keys,
				 const char **error_r)
{
	i_assert(dcrypt_vfs != NULL);
	if (dcrypt_vfs->key_load_private_raw == NULL) {
		*error_r = "Not implemented";
		return FALSE;
	}
	return dcrypt_vfs->key_load_private_raw(key_r, key_type, keys,
						error_r);
}

bool dcrypt_key_load_public_raw(struct dcrypt_public_key **key_r,
				enum dcrypt_key_type key_type,
				const ARRAY_TYPE(dcrypt_raw_key) *keys,
				const char **error_r)
{
	i_assert(dcrypt_vfs != NULL);
	if (dcrypt_vfs->key_load_public_raw == NULL) {
		*error_r = "Not implemented";
		return FALSE;
	}
	return dcrypt_vfs->key_load_public_raw(key_r, key_type, keys,
					       error_r);
}

bool dcrypt_key_get_curve_public(struct dcrypt_public_key *key,
				 const char **curve_r, const char **error_r)
{
	i_assert(dcrypt_vfs != NULL);
	if (dcrypt_vfs->key_get_curve_public == NULL) {
		*error_r = "Not implemented";
		return FALSE;
	}
	return dcrypt_vfs->key_get_curve_public(key, curve_r, error_r);
}

const char *dcrypt_key_get_id_public(struct dcrypt_public_key *key)
{
	i_assert(dcrypt_vfs != NULL);
	if (dcrypt_vfs->key_get_id_public == NULL)
		return NULL;
	return dcrypt_vfs->key_get_id_public(key);
}

const char *dcrypt_key_get_id_private(struct dcrypt_private_key *key)
{
	i_assert(dcrypt_vfs != NULL);
	if (dcrypt_vfs->key_get_id_private == NULL)
		return NULL;
	return dcrypt_vfs->key_get_id_private(key);
}

void dcrypt_key_set_id_public(struct dcrypt_public_key *key, const char *id)
{
	i_assert(dcrypt_vfs != NULL);
	if (dcrypt_vfs->key_set_id_public == NULL)
		return;
	dcrypt_vfs->key_set_id_public(key, id);
}

void dcrypt_key_set_id_private(struct dcrypt_private_key *key, const char *id)
{
	i_assert(dcrypt_vfs != NULL);
	if (dcrypt_vfs->key_set_id_private == NULL)
		return;
	dcrypt_vfs->key_set_id_private(key, id);
}

enum dcrypt_key_usage dcrypt_key_get_usage_public(struct dcrypt_public_key *key)
{
	i_assert(dcrypt_vfs != NULL);
	if (dcrypt_vfs->key_get_usage_public == NULL)
		return DCRYPT_KEY_USAGE_NONE;
	return dcrypt_vfs->key_get_usage_public(key);
}

enum dcrypt_key_usage dcrypt_key_get_usage_private(struct dcrypt_private_key *key)
{
	i_assert(dcrypt_vfs != NULL);
	if (dcrypt_vfs->key_get_usage_private == NULL)
		return DCRYPT_KEY_USAGE_NONE;
	return dcrypt_vfs->key_get_usage_private(key);
}

void dcrypt_key_set_usage_public(struct dcrypt_public_key *key,
				 enum dcrypt_key_usage usage)
{
	i_assert(dcrypt_vfs != NULL);
	if (dcrypt_vfs->key_set_usage_public == NULL)
		return;
	dcrypt_vfs->key_set_usage_public(key, usage);
}

void dcrypt_key_set_usage_private(struct dcrypt_private_key *key,
				  enum dcrypt_key_usage usage)
{
	i_assert(dcrypt_vfs != NULL);
	if (dcrypt_vfs->key_set_usage_private == NULL)
		return;
	dcrypt_vfs->key_set_usage_private(key, usage);
}

bool dcrypt_sign(struct dcrypt_private_key *key, const char *algorithm,
		 enum dcrypt_signature_format format,
		 const void *data, size_t data_len, buffer_t *signature_r,
		 enum dcrypt_padding padding, const char **error_r)
{
	i_assert(dcrypt_vfs != NULL);

	if (dcrypt_vfs->sign == NULL) {
		*error_r = "Not implemented";
		return FALSE;
	}

	return dcrypt_vfs->sign(key, algorithm, format, data, data_len,
				signature_r, padding, error_r);
}

bool dcrypt_verify(struct dcrypt_public_key *key, const char *algorithm,
		   enum dcrypt_signature_format format,
		   const void *data, size_t data_len,
		   const unsigned char *signature, size_t signature_len,
		   bool *valid_r, enum dcrypt_padding padding,
		   const char **error_r)
{
	i_assert(dcrypt_vfs != NULL);

	if (dcrypt_vfs->verify == NULL) {
		*error_r = "Not implemented";
		return FALSE;
	}

	return dcrypt_vfs->verify(key, algorithm, format, data, data_len,
				  signature, signature_len,
				  valid_r, padding, error_r);
}

int parse_jwk_key(const char *key_data, struct json_tree **tree_r,
		  const char **error_r)
{
	struct istream *is = i_stream_create_from_data(key_data, strlen(key_data));
	struct json_parser *parser = json_parser_init(is);
	struct json_tree *tree = json_tree_init();
	const char *error;
	enum json_type type;
	const char *value;
	int ret;

	i_stream_unref(&is);

	while ((ret = json_parse_next(parser, &type, &value)) == 1)
		json_tree_append(tree, type, value);

	i_assert(ret == -1);

	if (json_parser_deinit(&parser, &error) != 0) {
		json_tree_deinit(&tree);
		*error_r = error;
		if (error == NULL)
			*error_r = "Truncated JSON";
		return -1;
	}

	*tree_r = tree;

	return 0;
}
