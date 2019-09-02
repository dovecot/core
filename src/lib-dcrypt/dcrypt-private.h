#ifndef DCRYPT_PRIVATE_H
#define DCRYPT_PRIVATE_H

#define DCRYPT_DOVECOT_KEY_ENCRYPT_HASH "sha256"
#define DCRYPT_DOVECOT_KEY_ENCRYPT_ROUNDS 2048

#define DCRYPT_DOVECOT_KEY_ENCRYPT_NONE 0
#define DCRYPT_DOVECOT_KEY_ENCRYPT_PK 1
#define DCRYPT_DOVECOT_KEY_ENCRYPT_PASSWORD 2

struct dcrypt_vfs {
	bool (*initialize)(const struct dcrypt_settings *set,
			   const char **error_r);

	bool (*ctx_sym_create)(const char *algorithm,
			       enum dcrypt_sym_mode mode,
			       struct dcrypt_context_symmetric **ctx_r,
			       const char **error_r);
	void (*ctx_sym_destroy)(struct dcrypt_context_symmetric **ctx);

	void (*ctx_sym_set_key)(struct dcrypt_context_symmetric *ctx,
				const unsigned char *key, size_t key_len);
	void (*ctx_sym_set_iv)(struct dcrypt_context_symmetric *ctx,
			       const unsigned char *iv, size_t iv_len);
	void (*ctx_sym_set_key_iv_random)(struct dcrypt_context_symmetric *ctx);

	void (*ctx_sym_set_padding)(struct dcrypt_context_symmetric *ctx,
				    bool padding);

	bool (*ctx_sym_get_key)(struct dcrypt_context_symmetric *ctx,
				buffer_t *key);
	bool (*ctx_sym_get_iv)(struct dcrypt_context_symmetric *ctx,
			       buffer_t *iv);

	void (*ctx_sym_set_aad)(struct dcrypt_context_symmetric *ctx,
				const unsigned char *aad, size_t aad_len);
	bool (*ctx_sym_get_aad)(struct dcrypt_context_symmetric *ctx,
				buffer_t *aad);
	void (*ctx_sym_set_tag)(struct dcrypt_context_symmetric *ctx,
				const unsigned char *tag, size_t tag_len);
	bool (*ctx_sym_get_tag)(struct dcrypt_context_symmetric *ctx,
				buffer_t *tag);

	unsigned int (*ctx_sym_get_key_length)(
		struct dcrypt_context_symmetric *ctx);
	unsigned int (*ctx_sym_get_iv_length)(
		struct dcrypt_context_symmetric *ctx);
	unsigned int (*ctx_sym_get_block_size)(
		struct dcrypt_context_symmetric *ctx);

	bool (*ctx_sym_init)(struct dcrypt_context_symmetric *ctx,
			     const char **error_r);
	bool (*ctx_sym_update)(struct dcrypt_context_symmetric *ctx,
			       const unsigned char *data, size_t data_len,
			       buffer_t *result, const char **error_r);
	bool (*ctx_sym_final)(struct dcrypt_context_symmetric *ctx,
			      buffer_t *result, const char **error_r);

	bool (*ctx_hmac_create)(const char *algorithm,
				struct dcrypt_context_hmac **ctx_r,
				const char **error_r);
	void (*ctx_hmac_destroy)(struct dcrypt_context_hmac **ctx);

	void (*ctx_hmac_set_key)(struct dcrypt_context_hmac *ctx,
				 const unsigned char *key, size_t key_len);
	bool (*ctx_hmac_get_key)(struct dcrypt_context_hmac *ctx,
				 buffer_t *key);
	unsigned int (*ctx_hmac_get_digest_length)(
		struct dcrypt_context_hmac *ctx);
	void (*ctx_hmac_set_key_random)(struct dcrypt_context_hmac *ctx);

	bool (*ctx_hmac_init)(struct dcrypt_context_hmac *ctx,
			      const char **error_r);
	bool (*ctx_hmac_update)(struct dcrypt_context_hmac *ctx,
				const unsigned char *data, size_t data_len,
				const char **error_r);
	bool (*ctx_hmac_final)(struct dcrypt_context_hmac *ctx,
			       buffer_t *result, const char **error_r);

	bool (*ecdh_derive_secret_local)(struct dcrypt_private_key *local_key,
					 buffer_t *R, buffer_t *S,
					 const char **error_r);
	bool (*ecdh_derive_secret_peer)(struct dcrypt_public_key *peer_key,
					buffer_t *R, buffer_t *S,
					const char **error_r);
	bool (*pbkdf2)(const unsigned char *password, size_t password_len,
		       const unsigned char *salt, size_t salt_len,
		       const char *hash, unsigned int rounds,
		       buffer_t *result, unsigned int result_len,
		       const char **error_r);

	bool (*generate_keypair)(struct dcrypt_keypair *pair_r,
				 enum dcrypt_key_type kind, unsigned int bits,
				 const char *curve, const char **error_r);

	bool (*load_private_key)(struct dcrypt_private_key **key_r,
				 const char *data, const char *password,
				 struct dcrypt_private_key *dec_key,
				 const char **error_r);
	bool (*load_public_key)(struct dcrypt_public_key **key_r,
				const char *data, const char **error_r);

	bool (*store_private_key)(struct dcrypt_private_key *key,
				  enum dcrypt_key_format format,
				  const char *cipher, buffer_t *destination,
				  const char *password,
				  struct dcrypt_public_key *enc_key,
				  const char **error_r);
	bool (*store_public_key)(struct dcrypt_public_key *key,
				 enum dcrypt_key_format format,
				 buffer_t *destination, const char **error_r);

	void (*private_to_public_key)(struct dcrypt_private_key *priv_key,
				      struct dcrypt_public_key **pub_key_r);

	bool (*key_string_get_info)(
		const char *key_data, enum dcrypt_key_format *format_r,
		enum dcrypt_key_version *version_r,
		enum dcrypt_key_kind *kind_r,
		enum dcrypt_key_encryption_type *encryption_type_r,
		const char **encryption_key_hash_r, const char **key_hash_r,
		const char **error_r);

	void (*unref_keypair)(struct dcrypt_keypair *keypair);
	void (*unref_public_key)(struct dcrypt_public_key **key);
	void (*unref_private_key)(struct dcrypt_private_key **key);
        void (*ref_public_key)(struct dcrypt_public_key *key);
        void (*ref_private_key)(struct dcrypt_private_key *key);

	bool (*rsa_encrypt)(struct dcrypt_public_key *key,
			    const unsigned char *data, size_t data_len,
			    buffer_t *result, enum dcrypt_padding padding,
			    const char **error_r);
	bool (*rsa_decrypt)(struct dcrypt_private_key *key,
			    const unsigned char *data, size_t data_len,
			    buffer_t *result, enum dcrypt_padding padding,
			    const char **error_r);

	const char *(*oid2name)(const unsigned char *oid,
				size_t oid_len, const char **error_r);
	bool (*name2oid)(const char *name, buffer_t *oid,
			 const char **error_r);

	enum dcrypt_key_type (*private_key_type)(struct dcrypt_private_key *key);
	enum dcrypt_key_type (*public_key_type)(struct dcrypt_public_key *key);
	bool (*public_key_id)(struct dcrypt_public_key *key,
			      const char *algorithm, buffer_t *result,
			      const char **error_r);
	bool (*public_key_id_old)(struct dcrypt_public_key *key,
				  buffer_t *result, const char **error_r);
	bool (*private_key_id)(struct dcrypt_private_key *key,
			       const char *algorithm, buffer_t *result,
			       const char **error_r);
	bool (*private_key_id_old)(struct dcrypt_private_key *key,
				   buffer_t *result, const char **error_r);
	bool (*key_store_private_raw)(struct dcrypt_private_key *key,
				      pool_t pool,
				      enum dcrypt_key_type *key_type_r,
				      ARRAY_TYPE(dcrypt_raw_key) *keys_r,
				      const char **error_r);
	bool (*key_store_public_raw)(struct dcrypt_public_key *key,
				     pool_t pool,
				     enum dcrypt_key_type *key_type_r,
				     ARRAY_TYPE(dcrypt_raw_key) *keys_r,
				     const char **error_r);
	bool (*key_load_private_raw)(struct dcrypt_private_key **key_r,
				     enum dcrypt_key_type key_type,
				     const ARRAY_TYPE(dcrypt_raw_key) *keys,
				     const char **error_r);
	bool (*key_load_public_raw)(struct dcrypt_public_key **key_r,
				    enum dcrypt_key_type key_type,
				    const ARRAY_TYPE(dcrypt_raw_key) *keys,
				    const char **error_r);
	bool (*key_get_curve_public)(struct dcrypt_public_key *key,
				     const char **curve_r, const char **error_r);
	const char *(*key_get_id_public)(struct dcrypt_public_key *key);
	const char *(*key_get_id_private)(struct dcrypt_private_key *key);
	void (*key_set_id_public)(struct dcrypt_public_key *key, const char *id);
	void (*key_set_id_private)(struct dcrypt_private_key *key, const char *id);
	enum dcrypt_key_usage (*key_get_usage_public)(struct dcrypt_public_key *key);
	enum dcrypt_key_usage (*key_get_usage_private)(struct dcrypt_private_key *key);
	void (*key_set_usage_public)(struct dcrypt_public_key *key,
				     enum dcrypt_key_usage usage);
	void (*key_set_usage_private)(struct dcrypt_private_key *key,
				      enum dcrypt_key_usage usage);
	bool (*sign)(struct dcrypt_private_key *key, const char *algorithm,
		     enum dcrypt_signature_format format,
		     const void *data, size_t data_len, buffer_t *signature_r,
		     enum dcrypt_padding padding, const char **error_r);
	bool (*verify)(struct dcrypt_public_key *key, const char *algorithm,
		       enum dcrypt_signature_format format,
		       const void *data, size_t data_len,
		       const unsigned char *signature, size_t signature_len,
		       bool *valid_r, enum dcrypt_padding padding,
		       const char **error_r);
	bool (*ecdh_derive_secret)(struct dcrypt_private_key *priv_key,
				   struct dcrypt_public_key *pub_key,
				   buffer_t *shared_secret, const char **error_r);
};

void dcrypt_set_vfs(struct dcrypt_vfs *vfs);

void dcrypt_openssl_init(struct module *module ATTR_UNUSED);
void dcrypt_gnutls_init(struct module *module ATTR_UNUSED);
void dcrypt_openssl_deinit(void);
void dcrypt_gnutls_deinit(void);

int parse_jwk_key(const char *key_data, struct json_tree **tree_r,
		  const char **error_r);

#endif
