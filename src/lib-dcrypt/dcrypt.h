#ifndef DCRYPT_H
#define DCRYPT_H 1
#include "array.h"

struct dcrypt_context_symmetric;
struct dcrypt_context_hmac;
struct dcrypt_public_key;
struct dcrypt_private_key;

struct dcrypt_keypair {
	struct dcrypt_public_key *pub;
	struct dcrypt_private_key *priv;
};

enum dcrypt_sym_mode {
	DCRYPT_MODE_ENCRYPT,
	DCRYPT_MODE_DECRYPT
};

enum dcrypt_key_type {
	DCRYPT_KEY_RSA = 0x1,
	DCRYPT_KEY_EC  = 0x2
};

/**
 * dovecot key format:
 * version version-specific data
 * v1: version tab nid tab raw ec private key (in hex)
 * v2: version colon algorithm oid colon private-or-public-key-only (in hex)
 */
enum dcrypt_key_format {
	DCRYPT_FORMAT_PEM,
	DCRYPT_FORMAT_DOVECOT,
	DCRYPT_FORMAT_JWK, /* JSON Web Key (JWK) [RFC7517] */
};

enum dcrypt_key_encryption_type {
	DCRYPT_KEY_ENCRYPTION_TYPE_NONE,
	DCRYPT_KEY_ENCRYPTION_TYPE_KEY,
	DCRYPT_KEY_ENCRYPTION_TYPE_PASSWORD
};

enum dcrypt_key_version {
	DCRYPT_KEY_VERSION_1,
	DCRYPT_KEY_VERSION_2,
	DCRYPT_KEY_VERSION_NA /* not applicable, PEM key */
};

enum dcrypt_key_kind {
	DCRYPT_KEY_KIND_PUBLIC,
	DCRYPT_KEY_KIND_PRIVATE
};

enum dcrypt_key_usage {
	DCRYPT_KEY_USAGE_NONE,
	DCRYPT_KEY_USAGE_ENCRYPT,
	DCRYPT_KEY_USAGE_SIGN,
};

/* this parameter makes sense with RSA only
   default for RSA means either PSS (sign/verify)
   or OAEP (encrypt/decrypt).
   for ECDSA default can be used.
*/
enum dcrypt_padding {
	DCRYPT_PADDING_DEFAULT,
	DCRYPT_PADDING_RSA_PKCS1_PSS,
	DCRYPT_PADDING_RSA_PKCS1_OAEP,
	DCRYPT_PADDING_RSA_PKCS1, /* for compatibility use only */
	DCRYPT_PADDING_RSA_NO,
};

struct dcrypt_settings {
	/* OpenSSL engine to use */
	const char *crypto_device;
	/* Look for backends in this directory */
	const char *module_dir;
};

struct dcrypt_raw_key {
	const void *parameter;
	size_t len;
};

ARRAY_DEFINE_TYPE(dcrypt_raw_key, struct dcrypt_raw_key);

/**
 * load and initialize dcrypt backend, use either openssl or gnutls
 */
bool dcrypt_initialize(const char *backend, const struct dcrypt_settings *set,
		       const char **error_r);

/**
 * deinitialize dcrypt.
 *
 * NOTE: Do not call this function if you are going to use dcrypt later on.
 * Deinitializing the library using this will not allow it to be reinitialized
 * when using OpenSSL.
 */
void dcrypt_deinitialize(void);

/**
 * create symmetric context
 */
bool dcrypt_ctx_sym_create(const char *algorithm, enum dcrypt_sym_mode mode,
			   struct dcrypt_context_symmetric **ctx_r,
			   const char **error_r);

/**
 * destroy symmetric context and free memory
 */
void dcrypt_ctx_sym_destroy(struct dcrypt_context_symmetric **ctx);

/**
 * key and IV manipulation functions
 */
void dcrypt_ctx_sym_set_key(struct dcrypt_context_symmetric *ctx,
			    const unsigned char *key, size_t key_len);
void dcrypt_ctx_sym_set_iv(struct dcrypt_context_symmetric *ctx,
			   const unsigned char *iv, size_t iv_len);
void dcrypt_ctx_sym_set_key_iv_random(struct dcrypt_context_symmetric *ctx);
bool dcrypt_ctx_sym_get_key(struct dcrypt_context_symmetric *ctx, buffer_t *key);
bool dcrypt_ctx_sym_get_iv(struct dcrypt_context_symmetric *ctx, buffer_t *iv);

/**
 * turn padding on/off (default: on)
 */
void dcrypt_ctx_sym_set_padding(struct dcrypt_context_symmetric *ctx,
				bool padding);

/**
 * authentication data manipulation (use with GCM only)
 */
void dcrypt_ctx_sym_set_aad(struct dcrypt_context_symmetric *ctx,
			    const unsigned char *aad, size_t aad_len);
bool dcrypt_ctx_sym_get_aad(struct dcrypt_context_symmetric *ctx,
			    buffer_t *aad);
/**
 * result tag from aead (use with GCM only)
 */
void dcrypt_ctx_sym_set_tag(struct dcrypt_context_symmetric *ctx,
			    const unsigned char *tag, size_t tag_len);
bool dcrypt_ctx_sym_get_tag(struct dcrypt_context_symmetric *ctx,
			    buffer_t *tag);

/* get various lengths */
unsigned int dcrypt_ctx_sym_get_key_length(struct dcrypt_context_symmetric *ctx);
unsigned int dcrypt_ctx_sym_get_iv_length(struct dcrypt_context_symmetric *ctx);
unsigned int dcrypt_ctx_sym_get_block_size(struct dcrypt_context_symmetric *ctx);

/**
 * initialize crypto
 */
bool dcrypt_ctx_sym_init(struct dcrypt_context_symmetric *ctx,
			 const char **error_r);

/**
 * update with data
 */
bool dcrypt_ctx_sym_update(struct dcrypt_context_symmetric *ctx,
			   const unsigned char *data, size_t data_len,
			   buffer_t *result, const char **error_r);

/**
 * perform final step (may or may not emit data)
 */
bool dcrypt_ctx_sym_final(struct dcrypt_context_symmetric *ctx,
			  buffer_t *result, const char **error_r);

/**
 * create HMAC context, algorithm is digest algorithm
 */
bool dcrypt_ctx_hmac_create(const char *algorithm,
			    struct dcrypt_context_hmac **ctx_r,
			    const char **error_r);
/**
 * destroy HMAC context and free memory
 */
void dcrypt_ctx_hmac_destroy(struct dcrypt_context_hmac **ctx);

/**
 * hmac key manipulation
 */
void dcrypt_ctx_hmac_set_key(struct dcrypt_context_hmac *ctx,
			     const unsigned char *key, size_t key_len);
bool dcrypt_ctx_hmac_get_key(struct dcrypt_context_hmac *ctx, buffer_t *key);
void dcrypt_ctx_hmac_set_key_random(struct dcrypt_context_hmac *ctx);

/**
 * get digest length for HMAC
 */
unsigned int dcrypt_ctx_hmac_get_digest_length(struct dcrypt_context_hmac *ctx);

/**
 * initialize hmac
 */
bool dcrypt_ctx_hmac_init(struct dcrypt_context_hmac *ctx,
			  const char **error_r);

/**
 * update hmac context with data
 */
bool dcrypt_ctx_hmac_update(struct dcrypt_context_hmac *ctx,
			    const unsigned char *data, size_t data_len,
			    const char **error_r);

/**
 * perform final rounds and retrieve result
 */
bool dcrypt_ctx_hmac_final(struct dcrypt_context_hmac *ctx, buffer_t *result,
			   const char **error_r);

/**
 * Elliptic Curve based Diffie-Heffman shared secret derivation */
bool dcrypt_ecdh_derive_secret(struct dcrypt_private_key *priv_key,
			       struct dcrypt_public_key *pub_key,
			       buffer_t *shared_secret,
			       const char **error_r);
/**
 * Helpers for DCRYPT file format */
bool dcrypt_ecdh_derive_secret_local(struct dcrypt_private_key *local_key,
				     buffer_t *R, buffer_t *S,
				     const char **error_r);
bool dcrypt_ecdh_derive_secret_peer(struct dcrypt_public_key *peer_key,
				    buffer_t *R, buffer_t *S,
				    const char **error_r);

/** Signature functions
  algorithm is name of digest algorithm to use, such as SHA256.

  both RSA and EC keys are supported.
*/

/* returns false on error, true on success */
bool dcrypt_sign(struct dcrypt_private_key *key, const char *algorithm,
		 const void *data, size_t data_len, buffer_t *signature_r,
		 enum dcrypt_padding padding, const char **error_r);

/* check valid_r for signature validity
   false return means it wasn't able to verify it for other reasons */
bool dcrypt_verify(struct dcrypt_public_key *key, const char *algorithm,
		   const void *data, size_t data_len,
		   const unsigned char *signature, size_t signature_len,
		   bool *valid_r, enum dcrypt_padding padding,
		   const char **error_r);

/**
 * generate cryptographic data from password and salt. Use 1000-10000 for rounds.
 */
bool dcrypt_pbkdf2(const unsigned char *password, size_t password_len,
		   const unsigned char *salt, size_t salt_len,
		   const char *hash, unsigned int rounds,
		   buffer_t *result, unsigned int result_len,
		   const char **error_r);

bool dcrypt_keypair_generate(struct dcrypt_keypair *pair_r,
			     enum dcrypt_key_type kind, unsigned int bits,
			     const char *curve, const char **error_r);

/**
 * load loads key structure from external format.
 * store stores key structure into external format.
 *
 * you can provide either PASSWORD or ENC_KEY, not both.
 */
bool dcrypt_key_load_private(struct dcrypt_private_key **key_r,
			     const char *data, const char *password,
			     struct dcrypt_private_key *dec_key,
			     const char **error_r);

bool dcrypt_key_load_public(struct dcrypt_public_key **key_r,
			    const char *data, const char **error_r);

/**
 * When encrypting with public key, the cipher parameter here must begin with
 * ecdh-, for example ecdh-aes-256-ctr. An example of a valid cipher for
 * encrypting with password would be aes-256-ctr.
 */
bool dcrypt_key_store_private(struct dcrypt_private_key *key,
			      enum dcrypt_key_format format, const char *cipher,
			      buffer_t *destination, const char *password,
			      struct dcrypt_public_key *enc_key,
			      const char **error_r);

bool dcrypt_key_store_public(struct dcrypt_public_key *key,
			     enum dcrypt_key_format format,
			     buffer_t *destination, const char **error_r);

void dcrypt_key_convert_private_to_public(struct dcrypt_private_key *priv_key,
					  struct dcrypt_public_key **pub_key_r);

void dcrypt_keypair_unref(struct dcrypt_keypair *keypair);
void dcrypt_key_ref_public(struct dcrypt_public_key *key);
void dcrypt_key_ref_private(struct dcrypt_private_key *key);
void dcrypt_key_unref_public(struct dcrypt_public_key **key);
void dcrypt_key_unref_private(struct dcrypt_private_key **key);

enum dcrypt_key_type dcrypt_key_type_private(struct dcrypt_private_key *key);
enum dcrypt_key_type dcrypt_key_type_public(struct dcrypt_public_key *key);
/* return digest of key */
bool dcrypt_key_id_public(struct dcrypt_public_key *key, const char *algorithm,
			  buffer_t *result, const char **error_r);
/* return SHA1 sum of key */
bool dcrypt_key_id_public_old(struct dcrypt_public_key *key, buffer_t *result,
			      const char **error_r);
/* return digest of key */
bool dcrypt_key_id_private(struct dcrypt_private_key *key,
			   const char *algorithm, buffer_t *result,
			   const char **error_r);
/* return SHA1 sum of key */
bool dcrypt_key_id_private_old(struct dcrypt_private_key *key,
			       buffer_t *result, const char **error_r);

/* return raw private key:
   Only ECC supported currently

   returns OID bytes and private key in bigendian bytes
*/
bool dcrypt_key_store_private_raw(struct dcrypt_private_key *key,
				  pool_t pool,
				  enum dcrypt_key_type *key_type_r,
				  ARRAY_TYPE(dcrypt_raw_key) *keys_r,
				  const char **error_r);

/* return raw public key
   Only ECC supported currently

   returns OID bytes and public key in compressed form (z||x)
*/
bool dcrypt_key_store_public_raw(struct dcrypt_public_key *key,
				 pool_t pool,
				 enum dcrypt_key_type *key_type_r,
				 ARRAY_TYPE(dcrypt_raw_key) *keys_r,
				 const char **error_r);

/* load raw private key:
   Only ECC supported currently

   expects OID bytes and private key in bigendian bytes
*/
bool dcrypt_key_load_private_raw(struct dcrypt_private_key **key_r,
				 enum dcrypt_key_type key_type,
				 const ARRAY_TYPE(dcrypt_raw_key) *keys,
				 const char **error_r);

/* load raw public key
   Only ECC supported currently

   expects OID bytes and public key bytes.
*/
bool dcrypt_key_load_public_raw(struct dcrypt_public_key **key_r,
				enum dcrypt_key_type key_type,
				const ARRAY_TYPE(dcrypt_raw_key) *keys,
				const char **error_r);

/* for ECC only - return textual name or OID of used curve */
bool dcrypt_key_get_curve_public(struct dcrypt_public_key *key,
				 const char **curve_r, const char **error_r);

bool dcrypt_key_string_get_info(const char *key_data,
				enum dcrypt_key_format *format_r,
				enum dcrypt_key_version *version_r,
				enum dcrypt_key_kind *kind_r,
				enum dcrypt_key_encryption_type *encryption_type_r,
				const char **encryption_key_hash_r,
				const char **key_hash_r, const char **error_r);

/* Get/Set key identifier, this is optional opaque string identifying the key. */
const char *dcrypt_key_get_id_public(struct dcrypt_public_key *key);
const char *dcrypt_key_get_id_private(struct dcrypt_private_key *key);
void dcrypt_key_set_id_public(struct dcrypt_public_key *key, const char *id);
void dcrypt_key_set_id_private(struct dcrypt_private_key *key, const char *id);

/* Get/Set key usage, optional. Defaults to NONE */
enum dcrypt_key_usage dcrypt_key_get_usage_public(struct dcrypt_public_key *key);
enum dcrypt_key_usage dcrypt_key_get_usage_private(struct dcrypt_private_key *key);
void dcrypt_key_set_usage_public(struct dcrypt_public_key *key,
				 enum dcrypt_key_usage usage);
void dcrypt_key_set_usage_private(struct dcrypt_private_key *key,
				  enum dcrypt_key_usage usage);

/* RSA stuff */
bool dcrypt_rsa_encrypt(struct dcrypt_public_key *key,
			const unsigned char *data, size_t data_len,
			buffer_t *result, enum dcrypt_padding padding,
			const char **error_r);
bool dcrypt_rsa_decrypt(struct dcrypt_private_key *key,
			const unsigned char *data, size_t data_len,
			buffer_t *result, enum dcrypt_padding padding,
			const char **error_r);

/* OID stuff */
const char *dcrypt_oid2name(const unsigned char *oid, size_t oid_len,
			    const char **error_r);
bool dcrypt_name2oid(const char *name, buffer_t *oid, const char **error_r);

#endif
