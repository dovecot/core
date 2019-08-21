/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "hex-binary.h"
#include "safe-memset.h"
#include "randgen.h"
#include "array.h"
#include "module-dir.h"
#include "dovecot-openssl-common.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/objects.h>
#include "dcrypt.h"
#include "dcrypt-private.h"

/**

 key format documentation:
 =========================

 v1 key
 ------
 algo id = openssl NID
 enctype = 0 = none, 1 = ecdhe, 2 = password
 key id = sha256(hex encoded public point)

 public key
 ----------
 1<tab>algo id<tab>public point

 private key
 -----------
 - enctype none
 1<tab>algo id<tab>0<tab>private point<tab>key id

 - enctype ecdh (algorithm AES-256-CTR, key = SHA256(shared secret), IV = \0\0\0...)
 1<tab>algo id<tab>1<tab>private point<tab>ephemeral public key<tab>encryption key id<tab>key id

 - enctype password (algorithm AES-256-CTR, key = PBKDF2(SHA1, 16, password, salt), IV = \0\0\0...)
 1<tab>algo id<tab>2<tab>private point<tab>salt<tab>key id

 v2 key
 ------
 algo oid = ASN1 OID of key algorithm (RSA or EC curve)
 enctype = 0 = none, 1 = ecdhe, 2 = password
 key id = SHA256(i2d_PUBKEY)

 public key
 ----------
 2<tab>HEX(i2d_PUBKEY)<tab>key id

 - enctype none
 2<tab>key algo oid<tab>0<tab>(RSA = i2d_PrivateKey, EC=Private Point)<tab>key id

 - enctype ecdh, key,iv = PBKDF2(hash algo, rounds, shared secret, salt)
 2<tab>key algo oid<tab>1<tab>symmetric algo name<tab>salt<tab>hash algo<tab>rounds<tab>E(RSA = i2d_PrivateKey, EC=Private Point)<tab>ephemeral public key<tab>encryption key id<tab>key id

 - enctype password, key,iv = PBKDF2(hash algo, rounds, password, salt)
  2<tab>key algo oid<tab>1<tab>symmetric algo name<tab>salt<tab>hash algo<tab>rounds<tab>E(RSA = i2d_PrivateKey, EC=Private Point)<tab>key id
**/

#ifndef HAVE_EVP_PKEY_get0
#define EVP_PKEY_get0_EC_KEY(x) x->pkey.ec
#define EVP_PKEY_get0_RSA(x) x->pkey.rsa
#endif

#ifndef HAVE_OBJ_LENGTH
#define OBJ_length(o) ((o)->length)
#endif

#ifndef HAVE_EVP_MD_CTX_NEW
#  define EVP_MD_CTX_new() EVP_MD_CTX_create()
#  define EVP_MD_CTX_free(ctx) EVP_MD_CTX_destroy(ctx)
#endif

#ifndef HAVE_HMAC_CTX_NEW
#  define HMAC_Init_ex(ctx, key, key_len, md, impl) \
	HMAC_Init_ex(&(ctx), key, key_len, md, impl)
#  define HMAC_Update(ctx, data, len) HMAC_Update(&(ctx), data, len)
#  define HMAC_Final(ctx, md, len) HMAC_Final(&(ctx), md, len)
#  define HMAC_CTX_free(ctx) HMAC_cleanup(&(ctx))
#else
#  define HMAC_CTX_free(ctx) \
	STMT_START { HMAC_CTX_free(ctx); (ctx) = NULL; } STMT_END
#endif

/* openssl manual says this is OK */
#define OID_TEXT_MAX_LEN 80

struct dcrypt_context_symmetric {
	pool_t pool;
	const EVP_CIPHER *cipher;
	EVP_CIPHER_CTX *ctx;
	unsigned char *key;
	unsigned char *iv;
	unsigned char *aad;
	size_t aad_len;
	unsigned char *tag;
	size_t tag_len;
	int padding;
	int mode;
};

struct dcrypt_context_hmac {
	pool_t pool;
	const EVP_MD *md;
#ifdef HAVE_HMAC_CTX_NEW
	HMAC_CTX *ctx;
#else
	HMAC_CTX ctx;
#endif
	unsigned char *key;
	size_t klen;
};

struct dcrypt_public_key {
	EVP_PKEY *key;
	unsigned int ref;
};

struct dcrypt_private_key {
	EVP_PKEY *key;
	unsigned int ref;
};

static bool
dcrypt_openssl_public_key_id(struct dcrypt_public_key *key,
			     const char *algorithm, buffer_t *result,
			     const char **error_r);
static bool
dcrypt_openssl_public_key_id_old(struct dcrypt_public_key *key,
				 buffer_t *result, const char **error_r);
static bool
dcrypt_openssl_private_key_id(struct dcrypt_private_key *key,
			      const char *algorithm, buffer_t *result,
			      const char **error_r);
static bool
dcrypt_openssl_private_key_id_old(struct dcrypt_private_key *key,
				  buffer_t *result, const char **error_r);
static void
dcrypt_openssl_private_to_public_key(struct dcrypt_private_key *priv_key,
				     struct dcrypt_public_key **pub_key_r);
static void dcrypt_openssl_unref_private_key(struct dcrypt_private_key **key);
static void dcrypt_openssl_unref_public_key(struct dcrypt_public_key **key);
static bool
dcrypt_openssl_rsa_decrypt(struct dcrypt_private_key *key,
			   const unsigned char *data, size_t data_len,
			   buffer_t *result, const char **error_r);
static bool
dcrypt_openssl_key_string_get_info(const char *key_data,
	enum dcrypt_key_format *format_r, enum dcrypt_key_version *version_r,
	enum dcrypt_key_kind *kind_r,
	enum dcrypt_key_encryption_type *encryption_type_r,
	const char **encryption_key_hash_r, const char **key_hash_r,
	const char **error_r);

static bool dcrypt_openssl_error(const char **error_r)
{
	unsigned long ec;

	if (error_r == NULL) {
		/* caller is not really interested */
		return FALSE; 
	}

	ec = ERR_get_error();
	*error_r = t_strdup_printf("%s", ERR_error_string(ec, NULL));
	return FALSE;
}

static bool dcrypt_openssl_initialize(const struct dcrypt_settings *set,
				      const char **error_r)
{
	if (set->crypto_device != NULL && set->crypto_device[0] != '\0') {
		if (dovecot_openssl_common_global_set_engine(
			set->crypto_device, error_r) <= 0)
			return FALSE;
	}
	return TRUE;
}

/* legacy function for old formats that generates
   hex encoded point from EC public key
 */
static char *ec_key_get_pub_point_hex(const EC_KEY *key)
{
	const EC_POINT *p;
	const EC_GROUP *g;

	p = EC_KEY_get0_public_key(key);
	g = EC_KEY_get0_group(key);
	return EC_POINT_point2hex(g, p, POINT_CONVERSION_COMPRESSED, NULL);
}

static bool
dcrypt_openssl_ctx_sym_create(const char *algorithm, enum dcrypt_sym_mode mode,
			      struct dcrypt_context_symmetric **ctx_r,
			      const char **error_r)
{
	struct dcrypt_context_symmetric *ctx;
	pool_t pool;
	const EVP_CIPHER *cipher;

	cipher = EVP_get_cipherbyname(algorithm);
	if (cipher == NULL) {
		if (error_r != NULL) {
			*error_r = t_strdup_printf("Invalid cipher %s",
						   algorithm);
		}
		return FALSE;
	}

	/* allocate context */
	pool = pool_alloconly_create("dcrypt openssl", 1024);
	ctx = p_new(pool, struct dcrypt_context_symmetric, 1);
	ctx->pool = pool;
	ctx->cipher = cipher;
	ctx->padding = 1;
	ctx->mode = (mode == DCRYPT_MODE_ENCRYPT ? 1 : 0);
	*ctx_r = ctx;
	return TRUE;
}

static void
dcrypt_openssl_ctx_sym_destroy(struct dcrypt_context_symmetric **ctx)
{
	pool_t pool = (*ctx)->pool;

	if ((*ctx)->ctx != NULL)
		EVP_CIPHER_CTX_free((*ctx)->ctx);
	pool_unref(&pool);
	*ctx = NULL;
}

static void
dcrypt_openssl_ctx_sym_set_key(struct dcrypt_context_symmetric *ctx,
			       const unsigned char *key, size_t key_len)
{
	if (ctx->key != NULL)
		p_free(ctx->pool, ctx->key);
	ctx->key = p_malloc(ctx->pool, EVP_CIPHER_key_length(ctx->cipher));
	memcpy(ctx->key, key, I_MIN(key_len,
	       (size_t)EVP_CIPHER_key_length(ctx->cipher)));
}

static void
dcrypt_openssl_ctx_sym_set_iv(struct dcrypt_context_symmetric *ctx,
			      const unsigned char *iv, size_t iv_len)
{
	if(ctx->iv != NULL)
		p_free(ctx->pool, ctx->iv);

	ctx->iv = p_malloc(ctx->pool, EVP_CIPHER_iv_length(ctx->cipher));
	memcpy(ctx->iv, iv, I_MIN(iv_len,
	       (size_t)EVP_CIPHER_iv_length(ctx->cipher)));
}

static void
dcrypt_openssl_ctx_sym_set_key_iv_random(struct dcrypt_context_symmetric *ctx)
{
	if(ctx->key != NULL)
		p_free(ctx->pool, ctx->key);
	if(ctx->iv != NULL)
		p_free(ctx->pool, ctx->iv);

	ctx->key = p_malloc(ctx->pool, EVP_CIPHER_key_length(ctx->cipher));
	random_fill(ctx->key, EVP_CIPHER_key_length(ctx->cipher));
	ctx->iv = p_malloc(ctx->pool, EVP_CIPHER_iv_length(ctx->cipher));
	random_fill(ctx->iv, EVP_CIPHER_iv_length(ctx->cipher));
}

static void
dcrypt_openssl_ctx_sym_set_padding(struct dcrypt_context_symmetric *ctx,
				   bool padding)
{
	ctx->padding = (padding?1:0);
}

static bool
dcrypt_openssl_ctx_sym_get_key(struct dcrypt_context_symmetric *ctx,
			       buffer_t *key)
{
	if(ctx->key == NULL)
		return FALSE;

	buffer_append(key, ctx->key, EVP_CIPHER_key_length(ctx->cipher));
	return TRUE;
}

static bool
dcrypt_openssl_ctx_sym_get_iv(struct dcrypt_context_symmetric *ctx,
			      buffer_t *iv)
{
	if(ctx->iv == NULL)
		return FALSE;

	buffer_append(iv, ctx->iv, EVP_CIPHER_iv_length(ctx->cipher));
	return TRUE;
}

static void
dcrypt_openssl_ctx_sym_set_aad(struct dcrypt_context_symmetric *ctx,
			       const unsigned char *aad, size_t aad_len)
{
	if (ctx->aad != NULL)
		p_free(ctx->pool, ctx->aad);

	/* allow empty aad */
	ctx->aad = p_malloc(ctx->pool, I_MAX(1,aad_len));
	memcpy(ctx->aad, aad, aad_len);
	ctx->aad_len = aad_len;
}

static bool
dcrypt_openssl_ctx_sym_get_aad(struct dcrypt_context_symmetric *ctx,
			       buffer_t *aad)
{
	if (ctx->aad == NULL)
		return FALSE;

	buffer_append(aad, ctx->aad, ctx->aad_len);
	return TRUE;
}

static void
dcrypt_openssl_ctx_sym_set_tag(struct dcrypt_context_symmetric *ctx,
			       const unsigned char *tag, size_t tag_len)
{
	if (ctx->tag != NULL)
		p_free(ctx->pool, ctx->tag);

	/* unlike aad, tag cannot be empty */
	ctx->tag = p_malloc(ctx->pool, tag_len);
	memcpy(ctx->tag, tag, tag_len);
	ctx->tag_len = tag_len;
}

static bool
dcrypt_openssl_ctx_sym_get_tag(struct dcrypt_context_symmetric *ctx,
			       buffer_t *tag)
{
	if (ctx->tag == NULL)
		return FALSE;

	buffer_append(tag, ctx->tag, ctx->tag_len);
	return TRUE;
}

static unsigned int
dcrypt_openssl_ctx_sym_get_key_length(struct dcrypt_context_symmetric *ctx)
{
	return EVP_CIPHER_key_length(ctx->cipher);
}

static unsigned int
dcrypt_openssl_ctx_sym_get_iv_length(struct dcrypt_context_symmetric *ctx)
{
	return EVP_CIPHER_iv_length(ctx->cipher);
}

static unsigned int
dcrypt_openssl_ctx_sym_get_block_size(struct dcrypt_context_symmetric *ctx)
{
	return EVP_CIPHER_block_size(ctx->cipher);
}

static bool
dcrypt_openssl_ctx_sym_init(struct dcrypt_context_symmetric *ctx,
			    const char **error_r)
{
	int ec;
	int len;

	i_assert(ctx->key != NULL);
	i_assert(ctx->iv != NULL);
	i_assert(ctx->ctx == NULL);

	if((ctx->ctx = EVP_CIPHER_CTX_new()) == NULL)
		return dcrypt_openssl_error(error_r);

	ec = EVP_CipherInit_ex(ctx->ctx, ctx->cipher, NULL,
			       ctx->key, ctx->iv, ctx->mode);
	if (ec != 1)
		return dcrypt_openssl_error(error_r);

	EVP_CIPHER_CTX_set_padding(ctx->ctx, ctx->padding);
	len = 0;
	if (ctx->aad != NULL) {
		ec = EVP_CipherUpdate(ctx->ctx, NULL, &len,
				      ctx->aad, ctx->aad_len);
	}
	if (ec != 1)
		return dcrypt_openssl_error(error_r);
	return TRUE;
}

static bool
dcrypt_openssl_ctx_sym_update(struct dcrypt_context_symmetric *ctx,
			      const unsigned char *data, size_t data_len,
			      buffer_t *result, const char **error_r)
{
	const size_t block_size = (size_t)EVP_CIPHER_block_size(ctx->cipher);
	size_t buf_used = result->used;
	unsigned char *buf;
	int outl;

	i_assert(ctx->ctx != NULL);

	/* From `man 3 evp_cipherupdate`:

	   EVP_EncryptUpdate() encrypts inl bytes from the buffer in and writes
	   the encrypted version to out. This function can be called multiple
	   times to encrypt successive blocks of data. The amount of data
	   written depends on the block alignment of the encrypted data: as a
	   result the amount of data written may be anything from zero bytes to
	   (inl + cipher_block_size - 1) so out should contain sufficient room.
	   The actual number of bytes written is placed in outl.
	 */

	buf = buffer_append_space_unsafe(result, data_len + block_size);
	outl = 0;
	if (EVP_CipherUpdate
		(ctx->ctx, buf, &outl, data, data_len) != 1)
		return dcrypt_openssl_error(error_r);
	buffer_set_used_size(result, buf_used + outl);
	return TRUE;
}

static bool
dcrypt_openssl_ctx_sym_final(struct dcrypt_context_symmetric *ctx,
			     buffer_t *result, const char **error_r)
{
	const size_t block_size = (size_t)EVP_CIPHER_block_size(ctx->cipher);
	size_t buf_used = result->used;
	unsigned char *buf;
	int outl;
	int ec;

	i_assert(ctx->ctx != NULL);

	/* From `man 3 evp_cipherupdate`:

	   If padding is enabled (the default) then EVP_EncryptFinal_ex()
	   encrypts the "final" data, that is any data that remains in a partial
	   block. It uses standard block padding (aka PKCS padding). The
	   encrypted final data is written to out which should have sufficient
	   space for one cipher block. The number of bytes written is placed in
	   outl. After this function is called the encryption operation is
	   finished and no further calls to EVP_EncryptUpdate() should be made.
	 */

	buf = buffer_append_space_unsafe(result, block_size);
	outl = 0;

	/* when **DECRYPTING** set expected tag */
	if (ctx->mode == 0 && ctx->tag != NULL) {
		ec = EVP_CIPHER_CTX_ctrl(ctx->ctx, EVP_CTRL_GCM_SET_TAG,
					 ctx->tag_len, ctx->tag);
	} else {
		ec = 1;
	}

	if (ec == 1)
		ec = EVP_CipherFinal_ex(ctx->ctx, buf, &outl);

	if (ec == 1) {
		buffer_set_used_size(result, buf_used + outl);
		/* when **ENCRYPTING** recover tag */
		if (ctx->mode == 1 && ctx->aad != NULL) {
			/* tag should be NULL here */
			i_assert(ctx->tag == NULL);
			/* openssl claims taglen is always 16, go figure .. */
			ctx->tag = p_malloc(ctx->pool, EVP_GCM_TLS_TAG_LEN);
			ec = EVP_CIPHER_CTX_ctrl(ctx->ctx, EVP_CTRL_GCM_GET_TAG,
						 EVP_GCM_TLS_TAG_LEN, ctx->tag);
			ctx->tag_len = EVP_GCM_TLS_TAG_LEN;
		}
	}

	if (ec == 0 && error_r != NULL)
		*error_r = "data authentication failed";
	else if (ec < 0)
		dcrypt_openssl_error(error_r);

	EVP_CIPHER_CTX_free(ctx->ctx);
	ctx->ctx = NULL;

	return (ec == 1);
}

static bool
dcrypt_openssl_ctx_hmac_create(const char *algorithm,
			       struct dcrypt_context_hmac **ctx_r,
			       const char **error_r)
{
	struct dcrypt_context_hmac *ctx;
	pool_t pool;
	const EVP_MD *md;

	md = EVP_get_digestbyname(algorithm);
	if(md == NULL) {
		if (error_r != NULL) {
			*error_r = t_strdup_printf("Invalid digest %s",
						   algorithm);
		}
		return FALSE;
	}

	/* allocate context */
	pool = pool_alloconly_create("dcrypt openssl", 1024);
	ctx = p_new(pool, struct dcrypt_context_hmac, 1);
	ctx->pool = pool;
	ctx->md = md;
	*ctx_r = ctx;
	return TRUE;
}

static void
dcrypt_openssl_ctx_hmac_destroy(struct dcrypt_context_hmac **ctx)
{
	pool_t pool = (*ctx)->pool;
	HMAC_CTX_free((*ctx)->ctx);
	pool_unref(&pool);
	*ctx = NULL;
}

static void
dcrypt_openssl_ctx_hmac_set_key(struct dcrypt_context_hmac *ctx,
				const unsigned char *key, size_t key_len)
{
	if (ctx->key != NULL)
		p_free(ctx->pool, ctx->key);

	ctx->klen = I_MIN(key_len, HMAC_MAX_MD_CBLOCK);
	ctx->key = p_malloc(ctx->pool, ctx->klen);
	memcpy(ctx->key, key, ctx->klen);
}

static bool
dcrypt_openssl_ctx_hmac_get_key(struct dcrypt_context_hmac *ctx, buffer_t *key)
{
	if (ctx->key == NULL)
		return FALSE;
	buffer_append(key, ctx->key, ctx->klen);
	return TRUE;
}

static void
dcrypt_openssl_ctx_hmac_set_key_random(struct dcrypt_context_hmac *ctx)
{
	ctx->klen = HMAC_MAX_MD_CBLOCK;
	ctx->key = p_malloc(ctx->pool, ctx->klen);
	random_fill(ctx->key, ctx->klen);
}

static unsigned int
dcrypt_openssl_ctx_hmac_get_digest_length(struct dcrypt_context_hmac *ctx)
{
	return EVP_MD_size(ctx->md);
}

static bool
dcrypt_openssl_ctx_hmac_init(struct dcrypt_context_hmac *ctx,
			     const char **error_r)
{
	int ec;

	i_assert(ctx->md != NULL);
#ifdef HAVE_HMAC_CTX_NEW
	ctx->ctx = HMAC_CTX_new();
	if (ctx->ctx == NULL)
		return dcrypt_openssl_error(error_r);
#endif
	ec = HMAC_Init_ex(ctx->ctx, ctx->key, ctx->klen, ctx->md, NULL);
	if (ec != 1)
		return dcrypt_openssl_error(error_r);
	return TRUE;
}

static bool
dcrypt_openssl_ctx_hmac_update(struct dcrypt_context_hmac *ctx,
			       const unsigned char *data, size_t data_len,
			       const char **error_r)
{
	int ec;

	ec = HMAC_Update(ctx->ctx, data, data_len);
	if (ec != 1)
		return dcrypt_openssl_error(error_r);
	return TRUE;
}

static bool
dcrypt_openssl_ctx_hmac_final(struct dcrypt_context_hmac *ctx, buffer_t *result,
			      const char **error_r)
{
	int ec;
	unsigned char buf[HMAC_MAX_MD_CBLOCK];
	unsigned int outl;

	ec = HMAC_Final(ctx->ctx, buf, &outl);
	HMAC_CTX_free(ctx->ctx);
	if (ec == 1)
		buffer_append(result, buf, outl);
	else
		return dcrypt_openssl_error(error_r);
	return TRUE;
}

static bool
dcrypt_openssl_generate_ec_key(int nid, EVP_PKEY **key, const char **error_r)
{
	EVP_PKEY_CTX *pctx;
	EVP_PKEY_CTX *ctx;
	EVP_PKEY *params = NULL;

	/* generate parameters for EC */
	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	if (pctx == NULL ||
	    EVP_PKEY_paramgen_init(pctx) < 1 ||
	    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid) < 1 ||
	    EVP_PKEY_paramgen(pctx, &params) < 1)
	{
		dcrypt_openssl_error(error_r);
		EVP_PKEY_CTX_free(pctx);
		return FALSE;
	}

	/* generate key from parameters */
	ctx = EVP_PKEY_CTX_new(params, NULL);
	if (ctx == NULL ||
	    EVP_PKEY_keygen_init(ctx) < 1 ||
	    EVP_PKEY_keygen(ctx, key) < 1)
	{
		dcrypt_openssl_error(error_r);
		EVP_PKEY_free(params);
		EVP_PKEY_CTX_free(pctx);
		EVP_PKEY_CTX_free(ctx);
		return FALSE;
	}

	EVP_PKEY_free(params);
	EVP_PKEY_CTX_free(pctx);
	EVP_PKEY_CTX_free(ctx);
	EC_KEY_set_asn1_flag(EVP_PKEY_get0_EC_KEY((*key)),
			     OPENSSL_EC_NAMED_CURVE);
	EC_KEY_set_conv_form(EVP_PKEY_get0_EC_KEY((*key)),
			     POINT_CONVERSION_COMPRESSED);
	return TRUE;
}

static bool
dcrypt_openssl_generate_rsa_key(int bits, EVP_PKEY **key, const char **error_r)
{
	i_assert(bits >= 256);
	int ec = 0;

	EVP_PKEY_CTX *ctx;
	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if (ctx == NULL ||
	    EVP_PKEY_keygen_init(ctx) < 1 ||
	    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) < 1 ||
	    EVP_PKEY_keygen(ctx, key) < 1) {
		dcrypt_openssl_error(error_r);
		ec = -1;
	}

	EVP_PKEY_CTX_free(ctx);
	return ec == 0;
}

static bool
dcrypt_openssl_ecdh_derive_secret_local(struct dcrypt_private_key *local_key,
					buffer_t *R, buffer_t *S,
					const char **error_r)
{
	i_assert(local_key != NULL && local_key->key != NULL);

	EVP_PKEY *local = local_key->key;
	BN_CTX *bn_ctx = BN_CTX_new();
	if (bn_ctx == NULL)
		return dcrypt_openssl_error(error_r);

	const EC_GROUP *grp = EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(local));
	EC_POINT *pub = EC_POINT_new(grp);

	/* convert ephemeral key data EC point */
	if (pub == NULL ||
	    EC_POINT_oct2point(grp, pub, R->data, R->used, bn_ctx) != 1)
	{
		EC_POINT_free(pub);
		BN_CTX_free(bn_ctx);
		return dcrypt_openssl_error(error_r);
	}
	EC_KEY *ec_key = EC_KEY_new();

	/* convert point to public key */
	int ec = 0;
	if (ec_key == NULL ||
	    EC_KEY_set_group(ec_key, grp) != 1 ||
	    EC_KEY_set_public_key(ec_key, pub) != 1)
		ec = -1;
	else
		EC_KEY_set_conv_form(ec_key, POINT_CONVERSION_COMPRESSED);
	EC_POINT_free(pub);
	BN_CTX_free(bn_ctx);

	/* make sure it looks like a valid key */
	if (ec == -1 || EC_KEY_check_key(ec_key) != 1) {
		EC_KEY_free(ec_key);
		return dcrypt_openssl_error(error_r);
	}

	EVP_PKEY *peer = EVP_PKEY_new();
	if (peer == NULL) {
		EC_KEY_free(ec_key);
		return dcrypt_openssl_error(error_r);
	}
	EVP_PKEY_set1_EC_KEY(peer, ec_key);
	EC_KEY_free(ec_key);
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(local, NULL);

	/* initialize derivation */
	if (pctx == NULL ||
	    EVP_PKEY_derive_init(pctx) != 1 ||
	    EVP_PKEY_derive_set_peer(pctx, peer) != 1) {
		EVP_PKEY_CTX_free(pctx);
		EVP_PKEY_free(peer);
		return dcrypt_openssl_error(error_r);
	}

	/* have to do it twice to get the data length */
	size_t len;
	if (EVP_PKEY_derive(pctx, NULL, &len) != 1) {
		EVP_PKEY_CTX_free(pctx);
		EVP_PKEY_free(peer);
		return dcrypt_openssl_error(error_r);
	}

	unsigned char buf[len];
	memset(buf,0,len);
	if (EVP_PKEY_derive(pctx, buf, &len) != 1) {
		EVP_PKEY_CTX_free(pctx);
		EVP_PKEY_free(peer);
		return dcrypt_openssl_error(error_r);
	}
	EVP_PKEY_CTX_free(pctx);
	buffer_append(S, buf, len);
	EVP_PKEY_free(peer);
	return TRUE;
}

static bool
dcrypt_openssl_ecdh_derive_secret_peer(struct dcrypt_public_key *peer_key,
				       buffer_t *R, buffer_t *S,
				       const char **error_r)
{
	i_assert(peer_key != NULL && peer_key->key != NULL);

	/* ensure peer_key is EC key */
	EVP_PKEY *local = NULL;
	EVP_PKEY *peer = peer_key->key;
	if (EVP_PKEY_base_id(peer) != EVP_PKEY_EC) {
		if (error_r != NULL)
			*error_r = "Only ECC key can be used";
		return FALSE;
	}

	/* generate another key from same group */
	int nid = EC_GROUP_get_curve_name(
		EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(peer)));
	if (!dcrypt_openssl_generate_ec_key(nid, &local, error_r))
		return FALSE;

	/* initialize */
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(local, NULL);
	if (pctx == NULL ||
	    EVP_PKEY_derive_init(pctx) != 1 ||
	    EVP_PKEY_derive_set_peer(pctx, peer) != 1) {
		EVP_PKEY_CTX_free(pctx);
		return dcrypt_openssl_error(error_r);
	}

	/* derive */
	size_t len;
	if (EVP_PKEY_derive(pctx, NULL, &len) != 1) {
		EVP_PKEY_CTX_free(pctx);
		return dcrypt_openssl_error(error_r);
	}
	unsigned char buf[len];
	if (EVP_PKEY_derive(pctx, buf, &len) != 1) {
		EVP_PKEY_CTX_free(pctx);
		return dcrypt_openssl_error(error_r);
	}

	EVP_PKEY_CTX_free(pctx);
	buffer_append(S, buf, len);

	/* get ephemeral key (=R) */
	BN_CTX *bn_ctx = BN_CTX_new();
	const EC_POINT *pub = EC_KEY_get0_public_key(EVP_PKEY_get0_EC_KEY(local));
	const EC_GROUP *grp = EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(local));
	len = EC_POINT_point2oct(grp, pub, POINT_CONVERSION_COMPRESSED,
				 NULL, 0, bn_ctx);
	unsigned char R_buf[len];
	EC_POINT_point2oct(grp, pub, POINT_CONVERSION_COMPRESSED,
			   R_buf, len, bn_ctx);
	BN_CTX_free(bn_ctx);
	buffer_append(R, R_buf, len);
	EVP_PKEY_free(local);

	return TRUE;
}

static bool
dcrypt_openssl_pbkdf2(const unsigned char *password, size_t password_len,
		      const unsigned char *salt, size_t salt_len,
		      const char *hash, unsigned int rounds,
		      buffer_t *result, unsigned int result_len,
		      const char **error_r)
{
	int ret;
	i_assert(rounds > 0);
	i_assert(result_len > 0);
	i_assert(result != NULL);
	/* determine MD */
	const EVP_MD* md = EVP_get_digestbyname(hash);
	if (md == NULL) {
		if (error_r != NULL)
			*error_r = t_strdup_printf("Invalid digest %s", hash);
		return FALSE;
	}

	unsigned char buffer[result_len];
	if ((ret = PKCS5_PBKDF2_HMAC((const char*)password, password_len,
				     salt, salt_len, rounds,
				     md, result_len, buffer)) == 1) {
		buffer_append(result, buffer, result_len);
	}
	if (ret != 1)
		return dcrypt_openssl_error(error_r);
	return TRUE;
}

static bool
dcrypt_openssl_generate_keypair(struct dcrypt_keypair *pair_r,
				enum dcrypt_key_type kind, unsigned int bits,
				const char *curve, const char **error_r)
{
	EVP_PKEY *pkey = NULL;

	i_assert(pair_r != NULL);
	i_zero(pair_r);
	if (kind == DCRYPT_KEY_RSA) {
		if (dcrypt_openssl_generate_rsa_key(bits, &pkey, error_r)) {
			pair_r->priv = i_new(struct dcrypt_private_key, 1);
			pair_r->priv->key = pkey;
			pair_r->priv->ref++;
			pair_r->pub = NULL;
			dcrypt_openssl_private_to_public_key(pair_r->priv,
							     &pair_r->pub);
			return TRUE;
		} else {
			return dcrypt_openssl_error(error_r);
		}
	} else if (kind == DCRYPT_KEY_EC) {
		int nid = OBJ_sn2nid(curve);
		if (nid == NID_undef) {
			if (error_r != NULL)
				*error_r = t_strdup_printf(
					"Unknown EC curve %s", curve);
			return FALSE;
		}
		if (dcrypt_openssl_generate_ec_key(nid, &pkey, error_r)) {
			pair_r->priv = i_new(struct dcrypt_private_key, 1);
			pair_r->priv->key = pkey;
			pair_r->priv->ref++;
			pair_r->pub = NULL;
			dcrypt_openssl_private_to_public_key(pair_r->priv,
							     &pair_r->pub);
			return TRUE;
		} else {
			return dcrypt_openssl_error(error_r);
		}
	}
	if (error_r != NULL)
		*error_r = "Key type not supported in this build";
	return FALSE;
}

static bool
dcrypt_openssl_decrypt_point_v1(buffer_t *data, buffer_t *key, BIGNUM **point_r,
				const char **error_r)
{
	struct dcrypt_context_symmetric *dctx;
	buffer_t *tmp = t_buffer_create(64);

	if (!dcrypt_openssl_ctx_sym_create("aes-256-ctr", DCRYPT_MODE_DECRYPT,
					   &dctx, error_r)) {
		return FALSE;
	}

	/* v1 KEYS have all-zero IV - have to use it ourselves too */
	dcrypt_openssl_ctx_sym_set_iv(dctx, (const unsigned char*)
		"\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0", 16);
	dcrypt_openssl_ctx_sym_set_key(dctx, key->data, key->used);

	if (!dcrypt_openssl_ctx_sym_init(dctx, error_r) ||
	    !dcrypt_openssl_ctx_sym_update(dctx, data->data, data->used,
					   tmp, error_r) ||
	    !dcrypt_openssl_ctx_sym_final(dctx, tmp, error_r)) {
		dcrypt_openssl_ctx_sym_destroy(&dctx);
		return FALSE;
	}

	dcrypt_openssl_ctx_sym_destroy(&dctx);

	*point_r = BN_bin2bn(tmp->data, tmp->used, NULL);
	safe_memset(buffer_get_modifiable_data(tmp, NULL), 0,tmp->used);
	buffer_set_used_size(key, 0);

	if (*point_r == NULL)
		return dcrypt_openssl_error(error_r);
	return TRUE;
}

static bool
dcrypt_openssl_decrypt_point_ec_v1(struct dcrypt_private_key *dec_key,
				   const char *data_hex,
				   const char *peer_key_hex, BIGNUM **point_r,
				   const char **error_r)
{
	buffer_t *peer_key, *data, key, *secret;
	bool res;

	data = t_buffer_create(128);
	peer_key = t_buffer_create(64);

	hex_to_binary(data_hex, data);
	hex_to_binary(peer_key_hex, peer_key);

	secret = t_buffer_create(64);

	if (!dcrypt_openssl_ecdh_derive_secret_local(dec_key, peer_key,
						     secret, error_r))
		return FALSE;

	/* run it thru SHA256 once */
	unsigned char digest[SHA256_DIGEST_LENGTH];
	SHA256(secret->data, secret->used, digest);
	safe_memset(buffer_get_modifiable_data(secret, NULL), 0, secret->used);
	buffer_set_used_size(secret, 0);
	buffer_create_from_const_data(&key, digest, SHA256_DIGEST_LENGTH);

	/* then use this as key */
	res = dcrypt_openssl_decrypt_point_v1(data, &key, point_r, error_r);
	memset(digest, 0, sizeof(digest));
	safe_memset(digest, 0, SHA256_DIGEST_LENGTH);

	return res;
}

static bool
dcrypt_openssl_decrypt_point_password_v1(const char *data_hex,
					 const char *password_hex,
					 const char *salt_hex, BIGNUM **point_r,
					 const char **error_r)
{
	buffer_t *salt, *data, *password, *key;
	struct dcrypt_context_symmetric *dctx;

	data = t_buffer_create(128);
	salt = t_buffer_create(16);
	password = t_buffer_create(32);
	key = t_buffer_create(32);

	hex_to_binary(data_hex, data);
	hex_to_binary(salt_hex, salt);
	hex_to_binary(password_hex, password);

	/* aes-256-ctr uses 32 byte key, and v1 uses all-zero IV */
	if (!dcrypt_openssl_pbkdf2(password->data, password->used,
				   salt->data, salt->used,
				   "sha256", 16, key, 32, error_r)) {
		dcrypt_ctx_sym_destroy(&dctx);
		return FALSE;
	}

	return dcrypt_openssl_decrypt_point_v1(data, key, point_r, error_r);
}

static bool
dcrypt_openssl_load_private_key_dovecot_v1(struct dcrypt_private_key **key_r,
					   int len, const char **input,
					   const char *password,
					   struct dcrypt_private_key *dec_key,
					   const char **error_r)
{
	int nid, ec, enctype;
	BIGNUM *point = NULL;

	if (str_to_int(input[1], &nid) != 0) {
		if (error_r != NULL)
			*error_r = "Corrupted data";
		return FALSE;
	}

	if (str_to_int(input[2], &enctype) != 0) {
		if (error_r != NULL)
			*error_r = "Corrupted data";
		return FALSE;
	}

	/* decode and optionally decipher private key value */
	if (enctype == DCRYPT_DOVECOT_KEY_ENCRYPT_NONE) {
		point = BN_new();
		if (point == NULL || BN_hex2bn(&point, input[3]) < 1) {
			BN_free(point);
			return dcrypt_openssl_error(error_r);
		}
	} else if (enctype == DCRYPT_DOVECOT_KEY_ENCRYPT_PASSWORD) {
		/* by password */
		if (password == NULL) {
			if (error_r != NULL) *error_r = "password missing";
			return FALSE;
		}
		const char *enc_priv_pt = input[3];
		const char *salt = input[4];
		if (!dcrypt_openssl_decrypt_point_password_v1(
			enc_priv_pt, password, salt, &point, error_r)) {
			return FALSE;
		}
	} else if (enctype == DCRYPT_DOVECOT_KEY_ENCRYPT_PK) {
		/* by key */
		if (dec_key == NULL) {
			if (error_r != NULL) *error_r = "decrypt key missing";
			return FALSE;
		}
		const char *enc_priv_pt = input[3];
		const char *peer_key = input[4];
		if (!dcrypt_openssl_decrypt_point_ec_v1(
			dec_key, enc_priv_pt, peer_key, &point, error_r)) {
			return FALSE;
		}
	} else {
		if (error_r != NULL)
			*error_r = "Invalid key data";
		return FALSE;
	}

	EC_KEY *eckey = EC_KEY_new_by_curve_name(nid);
	if (eckey == NULL) return dcrypt_openssl_error(error_r);

	/* assign private key */
	BN_CTX *bnctx = BN_CTX_new();
	if (bnctx == NULL) {
		EC_KEY_free(eckey);
		return dcrypt_openssl_error(error_r);
	}
	EC_KEY_set_conv_form(eckey, POINT_CONVERSION_COMPRESSED);
	EC_KEY_set_private_key(eckey, point);
	EC_KEY_precompute_mult(eckey, bnctx);
	EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);
	EC_POINT *pub = EC_POINT_new(EC_KEY_get0_group(eckey));
	if (pub == NULL) {
		EC_KEY_free(eckey);
		BN_CTX_free(bnctx);
		return dcrypt_openssl_error(error_r);
	}
	/* calculate public key */
	ec = EC_POINT_mul(EC_KEY_get0_group(eckey), pub, point,
			  NULL, NULL, bnctx);
	EC_KEY_set_public_key(eckey, pub);
	BN_free(point);
	EC_POINT_free(pub);
	BN_CTX_free(bnctx);

	/* make sure it looks OK and is correct */
	if (ec == 1 && EC_KEY_check_key(eckey) == 1) {
		unsigned char digest[SHA256_DIGEST_LENGTH];
		/* validate that the key was loaded correctly */
		char *id = ec_key_get_pub_point_hex(eckey);
		if (id == NULL) {
			EC_KEY_free(eckey);
			return dcrypt_openssl_error(error_r);
		}
		SHA256((unsigned char*)id, strlen(id), digest);
		OPENSSL_free(id);
		const char *digest_hex =
			binary_to_hex(digest, SHA256_DIGEST_LENGTH);
		if (strcmp(digest_hex, input[len-1]) != 0) {
			if (error_r != NULL)
				*error_r = "Key id mismatch after load";
			EC_KEY_free(eckey);
			return FALSE;
		}
		EVP_PKEY *key = EVP_PKEY_new();
		if (key == NULL) {
			EC_KEY_free(eckey);
			return dcrypt_openssl_error(error_r);
		}
		EVP_PKEY_set1_EC_KEY(key, eckey);
		EC_KEY_free(eckey);
		*key_r = i_new(struct dcrypt_private_key, 1);
		(*key_r)->key = key;
		(*key_r)->ref++;
		return TRUE;
	}

	EC_KEY_free(eckey);

	return dcrypt_openssl_error(error_r);
}

/* encrypt/decrypt private keys */
static bool
dcrypt_openssl_cipher_key_dovecot_v2(const char *cipher,
				     enum dcrypt_sym_mode mode,
				     buffer_t *input, buffer_t *secret,
				     buffer_t *salt, const char *digalgo,
				     unsigned int rounds, buffer_t *result_r,
				     const char **error_r)
{
	struct dcrypt_context_symmetric *dctx;
	bool res;

	if (!dcrypt_openssl_ctx_sym_create(cipher, mode, &dctx, error_r)) {
		return FALSE;
	}

	/* generate encryption key/iv based on secret/salt */
	buffer_t *key_data = t_buffer_create(128);
	res = dcrypt_openssl_pbkdf2(secret->data, secret->used,
		salt->data, salt->used, digalgo, rounds, key_data,
		dcrypt_openssl_ctx_sym_get_key_length(dctx) +
			dcrypt_openssl_ctx_sym_get_iv_length(dctx),
		error_r);

	if (!res) {
		dcrypt_openssl_ctx_sym_destroy(&dctx);
		return FALSE;
	}

	buffer_t *tmp = t_buffer_create(128);
	const unsigned char *kd = buffer_free_without_data(&key_data);

	/* perform ciphering */
	dcrypt_openssl_ctx_sym_set_key(dctx, kd,
		dcrypt_openssl_ctx_sym_get_key_length(dctx));
	dcrypt_openssl_ctx_sym_set_iv(dctx,
		kd + dcrypt_openssl_ctx_sym_get_key_length(dctx),
		dcrypt_openssl_ctx_sym_get_iv_length(dctx));

	if (!dcrypt_openssl_ctx_sym_init(dctx, error_r) ||
	    !dcrypt_openssl_ctx_sym_update(dctx, input->data,
					   input->used, tmp, error_r) ||
	    !dcrypt_openssl_ctx_sym_final(dctx, tmp, error_r)) {
		res = FALSE;
	} else {
		/* provide result if succeeded */
		buffer_append_buf(result_r, tmp, 0, (size_t)-1);
		res = TRUE;
	}
	/* and ensure no data leaks */
	safe_memset(buffer_get_modifiable_data(tmp, NULL), 0, tmp->used);

	dcrypt_openssl_ctx_sym_destroy(&dctx);
	return res;
}

static bool
dcrypt_openssl_load_private_key_dovecot_v2(struct dcrypt_private_key **key_r,
					   int len, const char **input,
					   const char *password,
					   struct dcrypt_private_key *dec_key,
					   const char **error_r)
{
	int enctype;
	buffer_t *key_data = t_buffer_create(256);

	/* check for encryption type */
	if (str_to_int(input[2], &enctype) != 0) {
		if (error_r != NULL)
			*error_r = "Corrupted data";
		return FALSE;
	}

	if (enctype < 0 || enctype > 2) {
		if (error_r != NULL)
			*error_r = "Corrupted data";
		return FALSE;
	}

	/* match encryption type to field counts */
	if ((enctype == DCRYPT_DOVECOT_KEY_ENCRYPT_NONE && len != 5) ||
	    (enctype == DCRYPT_DOVECOT_KEY_ENCRYPT_PASSWORD && len != 9) ||
 	    (enctype == DCRYPT_DOVECOT_KEY_ENCRYPT_PK && len != 11)) {
		if (error_r != NULL)
			*error_r = "Corrupted data";
		return FALSE;
	}

	/* get key type */
	int nid = OBJ_txt2nid(input[1]);

	if (nid == NID_undef)
		return dcrypt_openssl_error(error_r);

	/* decode and possibly decipher private key value */
	if (enctype == DCRYPT_DOVECOT_KEY_ENCRYPT_NONE) {
		if (hex_to_binary(input[3], key_data) != 0) {
			if (error_r != NULL)
				*error_r = "Corrupted data";
		}
	} else if (enctype == DCRYPT_DOVECOT_KEY_ENCRYPT_PK) {
		if (dec_key == NULL) {
			if (error_r != NULL) *error_r = "decrypt key missing";
			return FALSE;
		}
		unsigned int rounds;
		struct dcrypt_public_key *pubkey = NULL;
		if (str_to_uint(input[6], &rounds) != 0) {
			if (error_r != NULL)
				*error_r = "Corrupted data";
			return FALSE;
		}

		buffer_t *data = t_buffer_create(128);

		/* check that we have correct decryption key */
		dcrypt_openssl_private_to_public_key(dec_key, &pubkey);
		if (!dcrypt_openssl_public_key_id(pubkey, "sha256",
						  data, error_r)) {
			dcrypt_openssl_unref_public_key(&pubkey);
			return FALSE;
		}

		dcrypt_openssl_unref_public_key(&pubkey);

		if (strcmp(binary_to_hex(data->data, data->used),
			   input[9]) != 0) {
			if (error_r != NULL)
				*error_r = "No private key available";
			return FALSE;
		}


		buffer_t *salt, *peer_key, *secret;
		salt = t_buffer_create(strlen(input[4])/2);
		peer_key = t_buffer_create(strlen(input[8])/2);
		secret = t_buffer_create(128);

		buffer_set_used_size(data, 0);
		hex_to_binary(input[4], salt);
		hex_to_binary(input[8], peer_key);
		hex_to_binary(input[7], data);

		/* get us secret value to use for key/iv generation */
		if (EVP_PKEY_base_id((EVP_PKEY*)dec_key) == EVP_PKEY_RSA) {
			if (!dcrypt_openssl_rsa_decrypt(dec_key,
				peer_key->data, peer_key->used, secret,
				error_r))
				return FALSE;
		} else {
			/* perform ECDH */
			if (!dcrypt_openssl_ecdh_derive_secret_local(
				dec_key, peer_key, secret, error_r))
				return FALSE;
		}
		/* decrypt key */
		if (!dcrypt_openssl_cipher_key_dovecot_v2(input[3],
			DCRYPT_MODE_DECRYPT, data, secret, salt,
			input[5], rounds, key_data, error_r)) {
			return FALSE;
		}
	} else if (enctype == DCRYPT_DOVECOT_KEY_ENCRYPT_PASSWORD) {
		if (password == NULL) {
			if (error_r != NULL) *error_r = "password missing";
			return FALSE;
		}
		unsigned int rounds;
		if (str_to_uint(input[6], &rounds) != 0) {
			if (error_r != NULL)
				*error_r = "Corrupted data";
			return FALSE;
		}

		buffer_t *salt, secret, *data;
		salt = t_buffer_create(strlen(input[4])/2);
		buffer_create_from_const_data(&secret, password, strlen(password));
		data = t_buffer_create(strlen(input[7])/2);
		if (hex_to_binary(input[4], salt) != 0 ||
		    hex_to_binary(input[7], data) != 0) {
			if (error_r != NULL)
				*error_r = "Corrupted data";
			return FALSE;
		}

		if (!dcrypt_openssl_cipher_key_dovecot_v2(input[3],
			DCRYPT_MODE_DECRYPT, data, &secret, salt,
			input[5], rounds, key_data, error_r)) {
			return FALSE;
		}
	}

	/* decode actual key */
	if (EVP_PKEY_type(nid) == EVP_PKEY_RSA) {
		RSA *rsa = RSA_new();
		const unsigned char *ptr = buffer_get_data(key_data, NULL);
		if (rsa == NULL ||
		    d2i_RSAPrivateKey(&rsa, &ptr, key_data->used) == NULL ||
		    RSA_check_key(rsa) != 1) {
			safe_memset(buffer_get_modifiable_data(key_data, NULL),
				    0, key_data->used);
			RSA_free(rsa);
			return dcrypt_openssl_error(error_r);
		}
		safe_memset(buffer_get_modifiable_data(key_data, NULL),
			    0, key_data->used);
		buffer_set_used_size(key_data, 0);
		EVP_PKEY *pkey = EVP_PKEY_new();
		if (pkey == NULL) {
			RSA_free(rsa);
			return dcrypt_openssl_error(error_r);
		}
		EVP_PKEY_set1_RSA(pkey, rsa);
		RSA_free(rsa);
		*key_r = i_new(struct dcrypt_private_key, 1);
		(*key_r)->key = pkey;
		(*key_r)->ref++;
	} else {
		int ec;
		BIGNUM *point = BN_new();
		if (point == NULL ||
		    BN_mpi2bn(key_data->data, key_data->used, point) == NULL) {
			safe_memset(buffer_get_modifiable_data(key_data, NULL),
				    0, key_data->used);
			BN_free(point);
			return dcrypt_openssl_error(error_r);
		}
		EC_KEY *eckey = EC_KEY_new_by_curve_name(nid);
		safe_memset(buffer_get_modifiable_data(key_data, NULL),
			    0, key_data->used);
		buffer_set_used_size(key_data, 0);
		BN_CTX *bnctx = BN_CTX_new();
		if (eckey == NULL || bnctx == NULL) {
			BN_free(point);
			EC_KEY_free(eckey);
			BN_CTX_free(bnctx);
			return dcrypt_openssl_error(error_r);
		}
		EC_KEY_set_conv_form(eckey, POINT_CONVERSION_COMPRESSED);
		EC_KEY_set_private_key(eckey, point);
		EC_KEY_precompute_mult(eckey, bnctx);
		EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);
		EC_POINT *pub = EC_POINT_new(EC_KEY_get0_group(eckey));
		if (pub == NULL)
			ec = -1;
		else {
			/* calculate public key */
			ec = EC_POINT_mul(EC_KEY_get0_group(eckey), pub, point,
					  NULL, NULL, bnctx);
			EC_KEY_set_public_key(eckey, pub);
			EC_POINT_free(pub);
		}
		BN_free(point);
		BN_CTX_free(bnctx);
		/* make sure the EC key is valid */
		EVP_PKEY *key = EVP_PKEY_new();
		if (ec == 1 && key != NULL && EC_KEY_check_key(eckey) == 1) {
			EVP_PKEY_set1_EC_KEY(key, eckey);
			EC_KEY_free(eckey);
			*key_r = i_new(struct dcrypt_private_key, 1);
			(*key_r)->key = key;
			(*key_r)->ref++;
		} else {
			EVP_PKEY_free(key);
			EC_KEY_free(eckey);
			return dcrypt_openssl_error(error_r);
		}
	}

	/* finally compare key to key id */
	dcrypt_openssl_private_key_id(*key_r, "sha256", key_data, NULL);

	if (strcmp(binary_to_hex(key_data->data, key_data->used),
		   input[len-1]) != 0) {
		dcrypt_openssl_unref_private_key(key_r);
		if (error_r != NULL)
			*error_r = "Key id mismatch after load";
		return FALSE;
	}

	return TRUE;
}

static bool
dcrypt_openssl_load_private_key_dovecot(struct dcrypt_private_key **key_r,
					const char *data, const char *password,
					struct dcrypt_private_key *key,
					enum dcrypt_key_version version,
					const char **error_r)
{
	const char **input = t_strsplit(data, ":\t");
	size_t len = str_array_length(input);

	switch (version) {
	case DCRYPT_KEY_VERSION_1:
		return dcrypt_openssl_load_private_key_dovecot_v1(
			key_r, len, input, password, key, error_r);
	case DCRYPT_KEY_VERSION_2:
		return dcrypt_openssl_load_private_key_dovecot_v2(
			key_r, len, input, password, key, error_r);
	case DCRYPT_KEY_VERSION_NA:
		i_unreached();
	}
	return FALSE;
}

static bool
dcrypt_openssl_load_public_key_dovecot_v1(struct dcrypt_public_key **key_r,
					  int len, const char **input,
					  const char **error_r)
{
	int nid;
	if (str_to_int(input[1], &nid) != 0) {
		if (error_r != NULL)
			*error_r = "Corrupted data";
		return FALSE;
	}

	EC_KEY *eckey = EC_KEY_new_by_curve_name(nid);
	if (eckey == NULL) {
		dcrypt_openssl_error(error_r);
		return FALSE;
	}

	EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);
	BN_CTX *bnctx = BN_CTX_new();

	EC_POINT *point = EC_POINT_new(EC_KEY_get0_group(eckey));
	if (bnctx == NULL || point == NULL ||
	    EC_POINT_hex2point(EC_KEY_get0_group(eckey),
	    input[2], point, bnctx) == NULL) {
		BN_CTX_free(bnctx);
		EC_KEY_free(eckey);
		EC_POINT_free(point);
		dcrypt_openssl_error(error_r);
		return FALSE;
	}
	BN_CTX_free(bnctx);

	EC_KEY_set_public_key(eckey, point);
	EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);

	EC_POINT_free(point);

	if (EC_KEY_check_key(eckey) == 1) {
		EVP_PKEY *key = EVP_PKEY_new();
		EVP_PKEY_set1_EC_KEY(key, eckey);
		EC_KEY_free(eckey);
		/* make sure digest matches */
		buffer_t *dgst = t_buffer_create(32);
		struct dcrypt_public_key tmp = { key, 0 };
		dcrypt_openssl_public_key_id_old(&tmp, dgst, NULL);
		if (strcmp(binary_to_hex(dgst->data, dgst->used),
			   input[len-1]) != 0) {
			if (error_r != NULL)
				*error_r = "Key id mismatch after load";
			EVP_PKEY_free(key);
			return FALSE;
		}
		*key_r = i_new(struct dcrypt_public_key, 1);
		(*key_r)->key = key;
		(*key_r)->ref++;
		return TRUE;
	}

	dcrypt_openssl_error(error_r);
	return FALSE;
}

static bool
dcrypt_openssl_load_public_key_dovecot_v2(struct dcrypt_public_key **key_r,
					  int len, const char **input,
					  const char **error_r)
{
	buffer_t tmp;
	size_t keylen = strlen(input[1])/2;
	unsigned char keybuf[keylen];
	const unsigned char *ptr;
	buffer_create_from_data(&tmp, keybuf, keylen);
	hex_to_binary(input[1], &tmp);
	ptr = keybuf;

	EVP_PKEY *pkey = EVP_PKEY_new();
	if (pkey == NULL || d2i_PUBKEY(&pkey, &ptr, keylen)==NULL) {
		EVP_PKEY_free(pkey);
		dcrypt_openssl_error(error_r);
		return FALSE;
	}

	/* make sure digest matches */
	buffer_t *dgst = t_buffer_create(32);
	struct dcrypt_public_key tmpkey = {pkey, 0};
	dcrypt_openssl_public_key_id(&tmpkey, "sha256", dgst, NULL);
	if (strcmp(binary_to_hex(dgst->data, dgst->used), input[len-1]) != 0) {
		if (error_r != NULL)
			*error_r = "Key id mismatch after load";
		EVP_PKEY_free(pkey);
		return FALSE;
	}

	*key_r = i_new(struct dcrypt_public_key, 1);
	(*key_r)->key = pkey;
	(*key_r)->ref++;
	return TRUE;
}

static bool
dcrypt_openssl_load_public_key_dovecot(struct dcrypt_public_key **key_r,
				       const char *data,
				       enum dcrypt_key_version version,
				       const char **error_r)
{
	const char **input = t_strsplit(data, ":\t");
	size_t len = str_array_length(input);

	switch (version) {
	case DCRYPT_KEY_VERSION_1:
		return dcrypt_openssl_load_public_key_dovecot_v1(
			key_r, len, input, error_r);
		break;
	case DCRYPT_KEY_VERSION_2:
		return dcrypt_openssl_load_public_key_dovecot_v2(
			key_r, len, input, error_r);
		break;
	case DCRYPT_KEY_VERSION_NA:
		i_unreached();
	}
	return FALSE;
}

static bool
dcrypt_openssl_encrypt_private_key_dovecot(buffer_t *key, int enctype,
					   const char *cipher,
					   const char *password,
					   struct dcrypt_public_key *enc_key,
					   buffer_t *destination,
					   const char **error_r)
{
	bool res;
	unsigned char *ptr;

	unsigned char salt[8];
	buffer_t *peer_key = t_buffer_create(128);
	buffer_t *secret = t_buffer_create(128);
	cipher = t_str_lcase(cipher);

	str_append(destination, cipher);
	str_append_c(destination, ':');
	random_fill(salt, sizeof(salt));
	binary_to_hex_append(destination, salt, sizeof(salt));
	buffer_t saltbuf;
	buffer_create_from_const_data(&saltbuf, salt, sizeof(salt));

	/* so we don't have to make new version if we ever upgrade these */
	str_append(destination, t_strdup_printf(":%s:%d:",
		DCRYPT_DOVECOT_KEY_ENCRYPT_HASH,
		DCRYPT_DOVECOT_KEY_ENCRYPT_ROUNDS));

	if (enctype == DCRYPT_DOVECOT_KEY_ENCRYPT_PK) {
		if (EVP_PKEY_base_id(enc_key->key) == EVP_PKEY_RSA) {
			size_t used = buffer_get_used_size(secret);
			/* peer key, in this case, is encrypted secret,
			   which is 16 bytes of data */
			ptr = buffer_append_space_unsafe(secret, 16);
			random_fill(ptr, 16);
			buffer_set_used_size(secret, used+16);
			if (!dcrypt_rsa_encrypt(enc_key, secret->data,
						secret->used, peer_key,
						error_r)) {
				return FALSE;
			}
		} else if (EVP_PKEY_base_id(enc_key->key) == EVP_PKEY_EC) {
			/* generate secret by ECDHE */
			if (!dcrypt_openssl_ecdh_derive_secret_peer(
				enc_key, peer_key, secret, error_r)) {
				return FALSE;
			}
		} else {
			/* Loading the key should have failed */
			i_unreached();
		}
		/* add encryption key id, reuse peer_key buffer */
	} else if (enctype == DCRYPT_DOVECOT_KEY_ENCRYPT_PASSWORD) {
		str_append(secret, password);
	}

	/* encrypt key using secret and salt */
	buffer_t *tmp = t_buffer_create(128);
	res = dcrypt_openssl_cipher_key_dovecot_v2(cipher,
		DCRYPT_MODE_ENCRYPT, key, secret, &saltbuf,
		DCRYPT_DOVECOT_KEY_ENCRYPT_HASH,
		DCRYPT_DOVECOT_KEY_ENCRYPT_ROUNDS, tmp, error_r);
	safe_memset(buffer_get_modifiable_data(secret, NULL), 0, secret->used);
	binary_to_hex_append(destination, tmp->data, tmp->used);

	/* some additional fields or private key version */
	if (enctype == DCRYPT_DOVECOT_KEY_ENCRYPT_PK) {
		str_append_c(destination, ':');

		/* for RSA, this is the actual encrypted secret */
		binary_to_hex_append(destination,
				     peer_key->data, peer_key->used);
		str_append_c(destination, ':');

		buffer_set_used_size(peer_key, 0);
		if (!dcrypt_openssl_public_key_id(enc_key, "sha256",
						  peer_key, error_r))
			return FALSE;
		binary_to_hex_append(destination,
				     peer_key->data, peer_key->used);
	}
	return res;
}

static bool
dcrypt_openssl_store_private_key_dovecot(struct dcrypt_private_key *key,
					 const char *cipher,
					 buffer_t *destination,
					 const char *password,
					 struct dcrypt_public_key *enc_key,
					 const char **error_r)
{
	size_t dest_used = buffer_get_used_size(destination);
	const char *cipher2 = NULL;
	EVP_PKEY *pkey = key->key;
	char objtxt[OID_TEXT_MAX_LEN];
	ASN1_OBJECT *obj;

	if (EVP_PKEY_base_id(pkey) == EVP_PKEY_EC) {
		/* because otherwise we get wrong nid */
		obj = OBJ_nid2obj(EC_GROUP_get_curve_name(
			EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(pkey))));

	} else {
		obj = OBJ_nid2obj(EVP_PKEY_id(pkey));
	}

	int enctype = DCRYPT_KEY_ENCRYPTION_TYPE_NONE;
	int len = OBJ_obj2txt(objtxt, sizeof(objtxt), obj, 1);
	if (len < 1)
		return dcrypt_openssl_error(error_r);
	if (len > (int)sizeof(objtxt)) {
		if (error_r != NULL)
			*error_r = "Object identifier too long";
		return FALSE;
	}

	buffer_t *buf = t_buffer_create(256);

	/* convert key to private key value */
	if (EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA) {
		unsigned char *ptr;
		RSA *rsa = EVP_PKEY_get0_RSA(pkey);
		int len = i2d_RSAPrivateKey(rsa, &ptr);
		if (len < 1)
			return dcrypt_openssl_error(error_r);
		buffer_append(buf, ptr, len);
	} else if (EVP_PKEY_base_id(pkey) == EVP_PKEY_EC) {
		unsigned char *ptr;
		EC_KEY *eckey = EVP_PKEY_get0_EC_KEY(pkey);
		const BIGNUM *pk = EC_KEY_get0_private_key(eckey);
		/* serialize to MPI which is portable */
		int len = BN_bn2mpi(pk, NULL);
		ptr = buffer_append_space_unsafe(buf, len);
		BN_bn2mpi(pk, ptr);
	} else {
		/* Loading the key should have failed */
		i_unreached();
	}

	/* see if we want ECDH based or password based encryption */
	if (cipher != NULL && strncasecmp(cipher, "ecdh-", 5) == 0) {
		i_assert(enc_key != NULL);
		i_assert(password == NULL);
		enctype = DCRYPT_DOVECOT_KEY_ENCRYPT_PK;
		cipher2 = cipher+5;
	} else if (cipher != NULL) {
		i_assert(enc_key == NULL);
		i_assert(password != NULL);
		enctype = DCRYPT_DOVECOT_KEY_ENCRYPT_PASSWORD;
		cipher2 = cipher;
	} else if (enctype == DCRYPT_KEY_ENCRYPTION_TYPE_NONE) {
		i_assert(enc_key == NULL && password == NULL);
	}

	/* put in OID and encryption type */
	str_append(destination, t_strdup_printf("2:%s:%d:",
		objtxt, enctype));

	/* perform encryption if desired */
	if (enctype != DCRYPT_KEY_ENCRYPTION_TYPE_NONE) {
		if (!dcrypt_openssl_encrypt_private_key_dovecot(buf,
			enctype, cipher2, password, enc_key, destination,
			error_r)) {
			buffer_set_used_size(destination, dest_used);
			return FALSE;
		}
	} else {
		binary_to_hex_append(destination, buf->data, buf->used);
	}

	/* append public key id */
	str_append_c(destination, ':');
	buffer_set_used_size(buf, 0);
	bool res = dcrypt_openssl_private_key_id(key, "sha256", buf, error_r);
	binary_to_hex_append(destination, buf->data, buf->used);

	if (!res) {
		/* well, that didn't end well */
		buffer_set_used_size(destination, dest_used);
		return FALSE;
	}
	return TRUE;
}

static bool
dcrypt_openssl_store_public_key_dovecot(struct dcrypt_public_key *key,
					buffer_t *destination,
					const char **error_r)
{
	EVP_PKEY *pubkey = key->key;
	unsigned char *tmp = NULL;
	size_t dest_used = buffer_get_used_size(destination);

	int rv = i2d_PUBKEY(pubkey, &tmp);

	if (tmp == NULL)
		return dcrypt_openssl_error(error_r);

	/* then store it */
	str_append_c(destination, '2');
	str_append_c(destination, ':');
	binary_to_hex_append(destination, tmp, rv);
	OPENSSL_free(tmp);

	/* append public key ID */
	str_append_c(destination, ':');

	buffer_t *buf = t_buffer_create(32);
	bool res = dcrypt_openssl_public_key_id(key, "sha256", buf, error_r);

	if (!res) {
		buffer_set_used_size(destination, dest_used);
		return FALSE;
	}

	str_append(destination, binary_to_hex(buf->data, buf->used));
	return TRUE;
}

static bool
dcrypt_openssl_load_private_key(struct dcrypt_private_key **key_r,
				const char *data, const char *password,
				struct dcrypt_private_key *dec_key,
				const char **error_r)
{
	i_assert(key_r != NULL);

	enum dcrypt_key_format format;
	enum dcrypt_key_version version;
	enum dcrypt_key_kind kind;
	if (!dcrypt_openssl_key_string_get_info(data, &format, &version,
				&kind, NULL, NULL, NULL, error_r)) {
		return FALSE;
	}
	if (kind != DCRYPT_KEY_KIND_PRIVATE) {
		if (error_r != NULL) *error_r = "key is not private";
		return FALSE;
	}

	if (format == DCRYPT_FORMAT_DOVECOT)
		return dcrypt_openssl_load_private_key_dovecot(key_r, data,
				password, dec_key, version, error_r);

	EVP_PKEY *key = NULL, *key2;

	BIO *key_in = BIO_new_mem_buf((void*)data, strlen(data));

	key = EVP_PKEY_new();

	key2 = PEM_read_bio_PrivateKey(key_in, &key, NULL, (void*)password);

	BIO_vfree(key_in);

	if (key2 == NULL) {
		EVP_PKEY_free(key);
		return dcrypt_openssl_error(error_r);
	}

	if (EVP_PKEY_base_id(key) == EVP_PKEY_EC) {
		EC_KEY_set_conv_form(EVP_PKEY_get0_EC_KEY(key),
				     POINT_CONVERSION_COMPRESSED);
	}

	*key_r = i_new(struct dcrypt_private_key, 1);
	(*key_r)->key = key;
	(*key_r)->ref++;

	return TRUE;
}

static bool
dcrypt_openssl_load_public_key(struct dcrypt_public_key **key_r,
			       const char *data, const char **error_r)
{
	enum dcrypt_key_format format;
	enum dcrypt_key_version version;
	enum dcrypt_key_kind kind;
	i_assert(key_r != NULL);

	if (!dcrypt_openssl_key_string_get_info(data, &format, &version,
						&kind, NULL, NULL, NULL,
						error_r)) {
		return FALSE;
	}
	if (kind != DCRYPT_KEY_KIND_PUBLIC) {
		if (error_r != NULL) *error_r = "key is not public";
		return FALSE;
	}

	if (format == DCRYPT_FORMAT_DOVECOT)
		return dcrypt_openssl_load_public_key_dovecot(key_r, data,
				version, error_r);

	EVP_PKEY *key = NULL;
	BIO *key_in = BIO_new_mem_buf((void*)data, strlen(data));
	if (key_in == NULL)
		return dcrypt_openssl_error(error_r);

	key = PEM_read_bio_PUBKEY(key_in, &key, NULL, NULL);
	if (BIO_reset(key_in) <= 0)
		i_unreached();
	if (key == NULL) { /* ec keys are bother */
		/* read the header */
		char buf[27]; /* begin public key */
		if (BIO_gets(key_in, buf, sizeof(buf)) != 1) {
			BIO_vfree(key_in);
			return dcrypt_openssl_error(error_r);
		}
		if (strcmp(buf, "-----BEGIN PUBLIC KEY-----") != 0) {
			if (error_r != NULL)
				*error_r = "Missing public key header";
			return FALSE;
		}
		BIO *b64 = BIO_new(BIO_f_base64());
		if (b64 == NULL) {
			BIO_vfree(key_in);
			return dcrypt_openssl_error(error_r);
		}
		EC_KEY *eckey = d2i_EC_PUBKEY_bio(b64, NULL);
		if (eckey != NULL) {
			EC_KEY_set_conv_form(eckey, POINT_CONVERSION_COMPRESSED);
			EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);
			key = EVP_PKEY_new();
			if (key != NULL)
				EVP_PKEY_set1_EC_KEY(key, eckey);
			EC_KEY_free(eckey);
		}
	}

	BIO_vfree(key_in);

	if (key == NULL)
		return dcrypt_openssl_error(error_r);

	*key_r = i_new(struct dcrypt_public_key, 1);
	(*key_r)->key = key;
	(*key_r)->ref++;

	return TRUE;
}

static bool
dcrypt_openssl_store_private_key(struct dcrypt_private_key *key,
				 enum dcrypt_key_format format,
				 const char *cipher, buffer_t *destination,
				 const char *password,
				 struct dcrypt_public_key *enc_key,
				 const char **error_r)
{
	i_assert(key != NULL && key->key != NULL);

	int ec;
	if (format == DCRYPT_FORMAT_DOVECOT) {
		bool ret;
		ret = dcrypt_openssl_store_private_key_dovecot(
			key, cipher, destination, password, enc_key, error_r);
		return ret;
	}

	EVP_PKEY *pkey = key->key;
	BIO *key_out = BIO_new(BIO_s_mem());
	if (key_out == NULL)
		return dcrypt_openssl_error(error_r);

	const EVP_CIPHER *algo = NULL;
	if (cipher != NULL) {
		algo = EVP_get_cipherbyname(cipher);
		if (algo == NULL) {
			if (error_r != NULL) {
				*error_r = t_strdup_printf(
					"Invalid cipher %s", cipher);
			}
			return FALSE;
		}
	}

	ec = PEM_write_bio_PrivateKey(key_out, pkey, algo,
				      NULL, 0, NULL, (void*)password);

	if (BIO_flush(key_out) <= 0)
		ec = -1;

	if (ec != 1) {
		BIO_vfree(key_out);
		return dcrypt_openssl_error(error_r);
	}

	long bs;
	char *buf;
	bs = BIO_get_mem_data(key_out, &buf);
	buffer_append(destination, buf, bs);
	BIO_vfree(key_out);

	return TRUE;
}

static bool
dcrypt_openssl_store_public_key(struct dcrypt_public_key *key,
				enum dcrypt_key_format format,
				buffer_t *destination, const char **error_r)
{
	int ec;

	i_assert(key != NULL && key->key != NULL);

	if (format == DCRYPT_FORMAT_DOVECOT) {
		return dcrypt_openssl_store_public_key_dovecot(key, destination,
							       error_r);
	}

	EVP_PKEY *pkey = key->key;
	BIO *key_out = BIO_new(BIO_s_mem());
	if (key_out == NULL)
		return dcrypt_openssl_error(error_r);

	BIO *b64;
	if (EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA)
		ec = PEM_write_bio_PUBKEY(key_out, pkey);
	else if ((b64 = BIO_new(BIO_f_base64())) == NULL)
		ec = -1;
	else {
		(void)BIO_puts(key_out, "-----BEGIN PUBLIC KEY-----\n");
		(void)BIO_push(b64, key_out);
		ec = i2d_EC_PUBKEY_bio(b64, EVP_PKEY_get0_EC_KEY(pkey));
		if (BIO_flush(b64) <= 0)
			ec = -1;
		(void)BIO_pop(b64);
		BIO_vfree(b64);
		if (BIO_puts(key_out, "-----END PUBLIC KEY-----") <= 0)
			ec = -1;
	}

	if (ec != 1) {
		BIO_vfree(key_out);
		return dcrypt_openssl_error(error_r);
	}

	long bs;
	char *buf;
	bs = BIO_get_mem_data(key_out, &buf);
	buffer_append(destination, buf, bs);
	BIO_vfree(key_out);

	return TRUE;
}

static void
dcrypt_openssl_private_to_public_key(struct dcrypt_private_key *priv_key,
				     struct dcrypt_public_key **pub_key_r)
{
	i_assert(priv_key != NULL && pub_key_r != NULL);

	EVP_PKEY *pkey = priv_key->key;
	EVP_PKEY *pk;

	pk = EVP_PKEY_new();
	i_assert(pk != NULL); /* we shouldn't get malloc() failures */

	if (EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA)
	{
		RSA *rsa = RSAPublicKey_dup(EVP_PKEY_get0_RSA(pkey));
		EVP_PKEY_set1_RSA(pk, rsa);
		RSA_free(rsa);
	} else if (EVP_PKEY_base_id(pkey) == EVP_PKEY_EC) {
		EC_KEY* eck = EVP_PKEY_get1_EC_KEY(pkey);
		EC_KEY_set_asn1_flag(eck, OPENSSL_EC_NAMED_CURVE);
		EVP_PKEY_set1_EC_KEY(pk, eck);
		EC_KEY_free(eck);
	} else {
		/* Loading the key should have failed */
		i_unreached();
	}

	*pub_key_r = i_new(struct dcrypt_public_key, 1);
	(*pub_key_r)->key = pk;
	(*pub_key_r)->ref++;
}

static bool
dcrypt_openssl_key_string_get_info(
	const char *key_data, enum dcrypt_key_format *format_r,
	enum dcrypt_key_version *version_r, enum dcrypt_key_kind *kind_r,
	enum dcrypt_key_encryption_type *encryption_type_r,
	const char **encryption_key_hash_r, const char **key_hash_r,
	const char **error_r)
{
	enum dcrypt_key_format format = DCRYPT_FORMAT_PEM;
	enum dcrypt_key_version version = DCRYPT_KEY_VERSION_NA;
	enum dcrypt_key_encryption_type encryption_type =
		DCRYPT_KEY_ENCRYPTION_TYPE_NONE;
	enum dcrypt_key_kind kind = DCRYPT_KEY_KIND_PUBLIC;
	char *encryption_key_hash = NULL;
	char *key_hash = NULL;

	i_assert(key_data != NULL);

	/* is it PEM key */
	if (str_begins(key_data, "-----BEGIN ")) {
		format = DCRYPT_FORMAT_PEM;
		version = DCRYPT_KEY_VERSION_NA;
		key_data += 11;
		if (str_begins(key_data, "RSA ")) {
			if (error_r != NULL)
				*error_r = "RSA private key format not "
					"supported, convert it to PKEY format "
					"with openssl pkey";
			return FALSE;
		}
		if (str_begins(key_data, "ENCRYPTED ")) {
			encryption_type = DCRYPT_KEY_ENCRYPTION_TYPE_PASSWORD;
			key_data += 10;
		}
		if (str_begins(key_data, "PRIVATE KEY-----"))
			kind = DCRYPT_KEY_KIND_PRIVATE;
		else if (str_begins(key_data, "PUBLIC KEY-----"))
			kind = DCRYPT_KEY_KIND_PUBLIC;
		else {
			if (error_r != NULL)
				*error_r = "Unknown/invalid PEM key type";
			return FALSE;
		}
	} else {
		if (str_begins(key_data, "1:")) {
			if (error_r != NULL)
				*error_r = "Dovecot v1 key format "
					"uses tab to separate fields";
			return FALSE;
		} else if (str_begins(key_data, "2\t")) {
			if (error_r != NULL)
				*error_r = "Dovecot v2 key format uses "
					"colon to separate fields";
			return FALSE;
		}
		const char **fields = t_strsplit(key_data, ":\t");
		int nfields = str_array_length(fields);

		if (nfields < 2) {
			if (error_r != NULL)
				*error_r = "Unknown key format";
			return FALSE;
		}

		format = DCRYPT_FORMAT_DOVECOT;

		/* field 1 - version */
		if (strcmp(fields[0], "1") == 0) {
			version = DCRYPT_KEY_VERSION_1;
			if (nfields == 4) {
				kind = DCRYPT_KEY_KIND_PUBLIC;
			} else if (nfields == 5 && strcmp(fields[2],"0") == 0) {
				kind = DCRYPT_KEY_KIND_PRIVATE;
				encryption_type = DCRYPT_KEY_ENCRYPTION_TYPE_NONE;
			} else if (nfields == 6 && strcmp(fields[2],"2") == 0) {
				kind = DCRYPT_KEY_KIND_PRIVATE;
				encryption_type = DCRYPT_KEY_ENCRYPTION_TYPE_PASSWORD;
			} else if (nfields == 7 && strcmp(fields[2],"1") == 0) {
				kind = DCRYPT_KEY_KIND_PRIVATE;
				encryption_type = DCRYPT_KEY_ENCRYPTION_TYPE_KEY;
				if (encryption_key_hash_r != NULL)
					encryption_key_hash = i_strdup(fields[nfields-2]);
			} else {
				if (error_r != NULL)
					*error_r = "Invalid dovecot v1 encoding";
				return FALSE;
			}
		} else if (strcmp(fields[0], "2") == 0) {
			version = DCRYPT_KEY_VERSION_2;
			if (nfields == 3) {
				kind = DCRYPT_KEY_KIND_PUBLIC;
			} else if (nfields == 5 && strcmp(fields[2],"0") == 0) {
				kind = DCRYPT_KEY_KIND_PRIVATE;
				encryption_type = DCRYPT_KEY_ENCRYPTION_TYPE_NONE;
			} else if (nfields == 9 && strcmp(fields[2],"2") == 0) {
				kind = DCRYPT_KEY_KIND_PRIVATE;
				encryption_type = DCRYPT_KEY_ENCRYPTION_TYPE_PASSWORD;
			} else if (nfields == 11 && strcmp(fields[2],"1") == 0) {
				kind = DCRYPT_KEY_KIND_PRIVATE;
				encryption_type = DCRYPT_KEY_ENCRYPTION_TYPE_KEY;
				if (encryption_key_hash_r != NULL)
					encryption_key_hash = i_strdup(fields[nfields-2]);
			} else {
				if (error_r != NULL)
					*error_r = "Invalid dovecot v2 encoding";
				return FALSE;
			}
		} else {
			if (error_r != NULL)
				*error_r = "Invalid dovecot key version";
			return FALSE;
		}

		/* last field is always key hash */
		if (key_hash_r != NULL)
			key_hash = i_strdup(fields[nfields-1]);
	}

	if (format_r != NULL) *format_r = format;
	if (version_r != NULL) *version_r = version;
	if (encryption_type_r != NULL) *encryption_type_r = encryption_type;
	if (encryption_key_hash_r != NULL) {
		*encryption_key_hash_r = t_strdup(encryption_key_hash);
		i_free(encryption_key_hash);
	}
	if (kind_r != NULL) *kind_r = kind;
	if (key_hash_r != NULL) {
		*key_hash_r = t_strdup(key_hash);
		i_free(key_hash);
	}
	return TRUE;
}

static void dcrypt_openssl_ref_public_key(struct dcrypt_public_key *key)
{
	i_assert(key != NULL && key->ref > 0);
	key->ref++;
}

static void dcrypt_openssl_ref_private_key(struct dcrypt_private_key *key)
{
	i_assert(key != NULL && key->ref > 0);
	key->ref++;
}

static void dcrypt_openssl_unref_public_key(struct dcrypt_public_key **key)
{
	i_assert(key != NULL && *key != NULL);
	struct dcrypt_public_key *_key = *key;
	i_assert(_key->ref > 0);
	*key = NULL;
	if (--_key->ref > 0) return;
	EVP_PKEY_free(_key->key);
	i_free(_key);
}

static void dcrypt_openssl_unref_private_key(struct dcrypt_private_key **key)
{
	i_assert(key != NULL && *key != NULL);
	struct dcrypt_private_key *_key = *key;
	i_assert(_key->ref > 0);
	*key = NULL;
	if (--_key->ref > 0) return;
	EVP_PKEY_free(_key->key);
	i_free(_key);
}

static void dcrypt_openssl_unref_keypair(struct dcrypt_keypair *keypair)
{
	i_assert(keypair != NULL);
	dcrypt_openssl_unref_public_key(&keypair->pub);
	dcrypt_openssl_unref_private_key(&keypair->priv);
}

static bool
dcrypt_openssl_rsa_encrypt(struct dcrypt_public_key *key,
			   const unsigned char *data, size_t data_len,
			   buffer_t *result, const char **error_r)
{
	int ec;
	i_assert(key != NULL && key->key != NULL);
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key->key, NULL);
	size_t outl = EVP_PKEY_size(key->key);
	unsigned char buf[outl];

	if (ctx == NULL ||
	    EVP_PKEY_encrypt_init(ctx) < 1 ||
	    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) < 1 ||
	    EVP_PKEY_encrypt(ctx, buf, &outl, data, data_len) < 1) {
		dcrypt_openssl_error(error_r);
		ec = -1;
	} else {
		buffer_append(result, buf, outl);
		ec = 0;
	}

	EVP_PKEY_CTX_free(ctx);

	return ec == 0;
}

static bool
dcrypt_openssl_rsa_decrypt(struct dcrypt_private_key *key,
			   const unsigned char *data, size_t data_len,
			   buffer_t *result, const char **error_r)
{
	int ec;
	i_assert(key != NULL && key->key != NULL);
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key->key, NULL);
	size_t outl = EVP_PKEY_size(key->key);
	unsigned char buf[outl];

	if (ctx == NULL ||
	    EVP_PKEY_decrypt_init(ctx) < 1 ||
	    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) < 1 ||
	    EVP_PKEY_decrypt(ctx, buf, &outl, data, data_len) < 1) {
		dcrypt_openssl_error(error_r);
		ec = -1;
	} else {
		buffer_append(result, buf, outl);
		ec = 0;
	}

	EVP_PKEY_CTX_free(ctx);

	return ec == 0;
}

static const char *
dcrypt_openssl_oid2name(const unsigned char *oid, size_t oid_len,
			const char **error_r)
{
	const char *name;
	i_assert(oid != NULL);
	ASN1_OBJECT *obj = d2i_ASN1_OBJECT(NULL, &oid, oid_len);
	if (obj == NULL) {
		dcrypt_openssl_error(error_r);
		return NULL;
	}
	name = OBJ_nid2sn(OBJ_obj2nid(obj));
	ASN1_OBJECT_free(obj);
	return name;
}

static bool
dcrypt_openssl_name2oid(const char *name, buffer_t *oid, const char **error_r)
{
	i_assert(name != NULL);
	ASN1_OBJECT *obj = OBJ_txt2obj(name, 0);
	if (obj == NULL)
		return dcrypt_openssl_error(error_r);

	size_t len = OBJ_length(obj);
	if (len == 0)
	{
		if (error_r != NULL)
			*error_r = "Object has no OID assigned";
		return FALSE;
	}
	len = i2d_ASN1_OBJECT(obj, NULL);
	unsigned char *bufptr = buffer_append_space_unsafe(oid, len);
	i2d_ASN1_OBJECT(obj, &bufptr);
	ASN1_OBJECT_free(obj);
	if (bufptr != NULL) {
		return TRUE;
	}
	return dcrypt_openssl_error(error_r);
}

static enum dcrypt_key_type
dcrypt_openssl_private_key_type(struct dcrypt_private_key *key)
{
	i_assert(key != NULL && key->key != NULL);
	EVP_PKEY *priv = key->key;
	if (EVP_PKEY_base_id(priv) == EVP_PKEY_RSA) return DCRYPT_KEY_RSA;
	else if (EVP_PKEY_base_id(priv) == EVP_PKEY_EC) return DCRYPT_KEY_EC;
	else i_unreached();
}

static enum dcrypt_key_type
dcrypt_openssl_public_key_type(struct dcrypt_public_key *key)
{
	i_assert(key != NULL && key->key != NULL);
	EVP_PKEY *pub = key->key;
	if (EVP_PKEY_base_id(pub) == EVP_PKEY_RSA) return DCRYPT_KEY_RSA;
	else if (EVP_PKEY_base_id(pub) == EVP_PKEY_EC) return DCRYPT_KEY_EC;
	else i_unreached();
}

/** this is the v1 old legacy way of doing key id's **/
static bool
dcrypt_openssl_public_key_id_old(struct dcrypt_public_key *key,
				 buffer_t *result, const char **error_r)
{
	unsigned char buf[SHA256_DIGEST_LENGTH];
	i_assert(key != NULL && key->key != NULL);
	EVP_PKEY *pub = key->key;

	if (EVP_PKEY_base_id(pub) != EVP_PKEY_EC) {
		if (error_r != NULL)
			*error_r = "Only EC key supported";
		return FALSE;
	}

	char *pub_pt_hex = ec_key_get_pub_point_hex(EVP_PKEY_get0_EC_KEY(pub));
	if (pub_pt_hex == NULL)
		return dcrypt_openssl_error(error_r);
	/* digest this */
	SHA256((const unsigned char*)pub_pt_hex, strlen(pub_pt_hex), buf);
	buffer_append(result, buf, SHA256_DIGEST_LENGTH);
	OPENSSL_free(pub_pt_hex);
	return TRUE;
}

static bool
dcrypt_openssl_private_key_id_old(struct dcrypt_private_key *key,
				  buffer_t *result, const char **error_r)
{
	unsigned char buf[SHA256_DIGEST_LENGTH];
	i_assert(key != NULL && key->key != NULL);
	EVP_PKEY *priv = key->key;

	if (EVP_PKEY_base_id(priv) != EVP_PKEY_EC) {
		if (error_r != NULL)
			*error_r = "Only EC key supported";
		return FALSE;
	}

	char *pub_pt_hex = ec_key_get_pub_point_hex(EVP_PKEY_get0_EC_KEY(priv));
	if (pub_pt_hex == NULL)
		return dcrypt_openssl_error(error_r);
	/* digest this */
	SHA256((const unsigned char*)pub_pt_hex, strlen(pub_pt_hex), buf);
	buffer_append(result, buf, SHA256_DIGEST_LENGTH);
	OPENSSL_free(pub_pt_hex);
	return TRUE;
}

/** this is the new which uses H(der formatted public key) **/
static bool
dcrypt_openssl_public_key_id_evp(EVP_PKEY *key,
				 const EVP_MD *md, buffer_t *result,
				 const char **error_r)
{
	bool res = FALSE;
	unsigned char buf[EVP_MD_size(md)], *ptr;

	if (EVP_PKEY_base_id(key) == EVP_PKEY_EC) {
		EC_KEY_set_conv_form(EVP_PKEY_get0_EC_KEY(key),
				     POINT_CONVERSION_COMPRESSED);
	}
	BIO *b = BIO_new(BIO_s_mem());
	if (b == NULL || i2d_PUBKEY_bio(b, key) < 1) {
		BIO_vfree(b);
		return dcrypt_openssl_error(error_r);
	}
	long len = BIO_get_mem_data(b, &ptr);
	unsigned int hlen = sizeof(buf);
	/* then hash it */
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (ctx == NULL ||
	    EVP_DigestInit_ex(ctx, md, NULL) < 1 ||
	    EVP_DigestUpdate(ctx, (const unsigned char*)ptr, len) < 1 ||
	    EVP_DigestFinal_ex(ctx, buf, &hlen) < 1) {
		res = dcrypt_openssl_error(error_r);
	} else {
		buffer_append(result, buf, hlen);
		res = TRUE;
	}
	EVP_MD_CTX_free(ctx);
	BIO_vfree(b);

	return res;
}

static bool
dcrypt_openssl_public_key_id(struct dcrypt_public_key *key,
			     const char *algorithm, buffer_t *result,
			     const char **error_r)
{
	const EVP_MD *md = EVP_get_digestbyname(algorithm);
	i_assert(key != NULL && key->key != NULL);
	EVP_PKEY *pub = key->key;

	if (md == NULL) {
		if (error_r != NULL) {
			*error_r = t_strdup_printf(
				"Unknown cipher %s", algorithm);
		}
		return FALSE;
	}

	return dcrypt_openssl_public_key_id_evp(pub, md, result, error_r);
}

static bool
dcrypt_openssl_private_key_id(struct dcrypt_private_key *key,
			      const char *algorithm, buffer_t *result,
			      const char **error_r)
{
	const EVP_MD *md = EVP_get_digestbyname(algorithm);
	i_assert(key != NULL && key->key != NULL);
	EVP_PKEY *priv = key->key;

	if (md == NULL) {
		if (error_r != NULL)
			*error_r = t_strdup_printf(
				"Unknown cipher %s", algorithm);
		return FALSE;
	}

	return dcrypt_openssl_public_key_id_evp(priv, md, result, error_r);
}


static bool
dcrypt_openssl_key_store_private_raw(struct dcrypt_private_key *key,
				     pool_t pool,
				     enum dcrypt_key_type *type_r,
				     ARRAY_TYPE(dcrypt_raw_key) *keys_r,
				     const char **error_r)
{
	i_assert(key != NULL && key->key != NULL);
	i_assert(array_is_created(keys_r));
	EVP_PKEY *priv = key->key;
	ARRAY_TYPE(dcrypt_raw_key) keys;
	t_array_init(&keys, 2);

	if (EVP_PKEY_base_id(priv) == EVP_PKEY_RSA) {
		if (error_r != NULL)
			*error_r = "Not implemented";
		return FALSE;
	} else if (EVP_PKEY_base_id(priv) == EVP_PKEY_EC) {
		/* store OID */
		EC_KEY *key = EVP_PKEY_get0_EC_KEY(priv);
		int nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(key));
		ASN1_OBJECT *obj = OBJ_nid2obj(nid);
		int len = OBJ_length(obj);
		if (len == 0) {
			if (error_r != NULL)
				*error_r = "Object has no OID assigned";
			return FALSE;
		}
		len = i2d_ASN1_OBJECT(obj, NULL);
		unsigned char *bufptr = p_malloc(pool, len);
		struct dcrypt_raw_key *item = array_append_space(&keys);
		item->parameter = bufptr;
		item->len = i2d_ASN1_OBJECT(obj, &bufptr);
		ASN1_OBJECT_free(obj);
		/* store private key */
		const BIGNUM *b = EC_KEY_get0_private_key(key);
		len = BN_num_bytes(b);
		item = array_append_space(&keys);
		bufptr = p_malloc(pool, len);
		if (BN_bn2bin(b, bufptr) < len)
			return dcrypt_openssl_error(error_r);
		item->parameter = bufptr;
		item->len = len;
		*type_r = DCRYPT_KEY_EC;
	} else {
		if (error_r != NULL)
			*error_r = "Key type unsupported";
		return FALSE;
	}

	array_append_array(keys_r, &keys);
	return TRUE;
}

static bool
dcrypt_openssl_key_store_public_raw(struct dcrypt_public_key *key,
				    pool_t pool,
				    enum dcrypt_key_type *type_r,
				    ARRAY_TYPE(dcrypt_raw_key) *keys_r,
				    const char **error_r)
{
	i_assert(key != NULL && key->key != NULL);
	EVP_PKEY *pub = key->key;
	ARRAY_TYPE(dcrypt_raw_key) keys;
	t_array_init(&keys, 2);

	if (EVP_PKEY_base_id(pub) == EVP_PKEY_RSA) {
		if (error_r != NULL)
			*error_r = "Not implemented";
		return FALSE;
	} else if (EVP_PKEY_base_id(pub) == EVP_PKEY_EC) {
		/* store OID */
		EC_KEY *key = EVP_PKEY_get0_EC_KEY(pub);
		int nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(key));
		ASN1_OBJECT *obj = OBJ_nid2obj(nid);
		int len = OBJ_length(obj);
		if (len == 0) {
			if (error_r != NULL)
				*error_r = "Object has no OID assigned";
			return FALSE;
		}
		len = i2d_ASN1_OBJECT(obj, NULL);
		unsigned char *bufptr = p_malloc(pool, len);
		struct dcrypt_raw_key *item = array_append_space(&keys);
		item->parameter = bufptr;
		item->len = i2d_ASN1_OBJECT(obj, &bufptr);
		ASN1_OBJECT_free(obj);

		/* store public key */
		const EC_POINT *point = EC_KEY_get0_public_key(key);
		len = EC_POINT_point2oct(EC_KEY_get0_group(key), point,
					 POINT_CONVERSION_UNCOMPRESSED,
					 NULL, 0, NULL);
		bufptr = p_malloc(pool, len);
		item = array_append_space(&keys);
		item->parameter = bufptr;
		item->len = len;
		if (EC_POINT_point2oct(EC_KEY_get0_group(key), point,
				       POINT_CONVERSION_UNCOMPRESSED,
				       bufptr, len, NULL) < (unsigned int)len)
			return dcrypt_openssl_error(error_r);
		*type_r = DCRYPT_KEY_EC;
	} else {
		if (error_r != NULL)
			*error_r = "Key type unsupported";
		return FALSE;
	}

	array_append_array(keys_r, &keys);

	return TRUE;
}

static bool
dcrypt_openssl_key_load_private_raw(struct dcrypt_private_key **key_r,
				    enum dcrypt_key_type type,
				    const ARRAY_TYPE(dcrypt_raw_key) *keys,
				    const char **error_r)
{
	int ec;
	i_assert(keys != NULL && array_is_created(keys) && array_count(keys) > 1);
	const struct dcrypt_raw_key *item;

	if (type == DCRYPT_KEY_RSA) {
		if (error_r != NULL)
			*error_r = "Not implemented";
		return FALSE;
	} else if (type == DCRYPT_KEY_EC) {
		/* get curve */
		if (array_count(keys) < 2) {
			if (error_r != NULL)
				*error_r = "Invalid parameters";
			return FALSE;
		}
		item = array_idx(keys, 0);
		const unsigned char *oid = item->parameter;
		ASN1_OBJECT *obj = d2i_ASN1_OBJECT(NULL, &oid, item->len);
		if (obj == NULL)
			return dcrypt_openssl_error(error_r);
		int nid = OBJ_obj2nid(obj);
		ASN1_OBJECT_free(obj);

		/* load private point */
		item = array_idx(keys, 1);
		BIGNUM *bn = BN_secure_new();
		if (BN_bin2bn(item->parameter, item->len, bn) == NULL) {
			BN_free(bn);
			return dcrypt_openssl_error(error_r);
		}

		/* setup a key */
		EC_KEY *key = EC_KEY_new_by_curve_name(nid);
		ec = EC_KEY_set_private_key(key, bn);
		BN_free(bn);

		if (ec != 1) {
			EC_KEY_free(key);
			return dcrypt_openssl_error(error_r);
		}

		/* calculate & assign public key */
		EC_POINT *pub = EC_POINT_new(EC_KEY_get0_group(key));
		if (pub == NULL) {
			EC_KEY_free(key);
			return dcrypt_openssl_error(error_r);
		}
		/* calculate public key */
		ec = EC_POINT_mul(EC_KEY_get0_group(key), pub,
				  EC_KEY_get0_private_key(key),
				  NULL, NULL, NULL);
		if (ec == 1)
			ec = EC_KEY_set_public_key(key, pub);
		EC_POINT_free(pub);

		/* check the key */
		if (ec != 1 || EC_KEY_check_key(key) != 1) {
			EC_KEY_free(key);
			return dcrypt_openssl_error(error_r);
		}

		EVP_PKEY *pkey = EVP_PKEY_new();
		EVP_PKEY_set1_EC_KEY(pkey, key);
		EC_KEY_free(key);
		*key_r = i_new(struct dcrypt_private_key, 1);
		(*key_r)->key = pkey;
		(*key_r)->ref++;
		return TRUE;
	} else {
		if (error_r != NULL)
			*error_r = "Key type unsupported";
	}

	return FALSE;
}

static bool
dcrypt_openssl_key_load_public_raw(struct dcrypt_public_key **key_r,
				   enum dcrypt_key_type type,
				   const ARRAY_TYPE(dcrypt_raw_key) *keys,
				   const char **error_r)
{
	int ec;
	i_assert(keys != NULL && array_is_created(keys) && array_count(keys) > 1);
	const struct dcrypt_raw_key *item;

	if (type == DCRYPT_KEY_RSA) {
		if (error_r != NULL)
			*error_r = "Not implemented";
		return FALSE;
	} else if (type == DCRYPT_KEY_EC) {
		/* get curve */
		if (array_count(keys) < 2) {
			if (error_r != NULL)
				*error_r = "Invalid parameters";
			return FALSE;
		}
		item = array_idx(keys, 0);
		const unsigned char *oid = item->parameter;
		ASN1_OBJECT *obj = d2i_ASN1_OBJECT(NULL, &oid, item->len);
		if (obj == NULL) {
			dcrypt_openssl_error(error_r);
			return FALSE;
		}
		int nid = OBJ_obj2nid(obj);
		ASN1_OBJECT_free(obj);

		/* set group */
		EC_GROUP *group = EC_GROUP_new_by_curve_name(nid);
		if (group == NULL) {
			dcrypt_openssl_error(error_r);
			return FALSE;
		}

		/* load point */
		item = array_idx(keys, 1);
		EC_POINT *point = EC_POINT_new(group);
		if (EC_POINT_oct2point(group, point, item->parameter,
				       item->len, NULL) != 1) {
			EC_POINT_free(point);
			EC_GROUP_free(group);
			return dcrypt_openssl_error(error_r);
		}

		EC_KEY *key = EC_KEY_new();
		ec = EC_KEY_set_group(key, group);
		if (ec == 1)
			ec = EC_KEY_set_public_key(key, point);
		EC_POINT_free(point);
		EC_GROUP_free(group);

		if (ec != 1 || EC_KEY_check_key(key) != 1) {
			EC_KEY_free(key);
			return dcrypt_openssl_error(error_r);
		}

		EVP_PKEY *pkey = EVP_PKEY_new();
		EVP_PKEY_set1_EC_KEY(pkey, key);
		EC_KEY_free(key);
		*key_r = i_new(struct dcrypt_public_key, 1);
		(*key_r)->key = pkey;
		(*key_r)->ref++;
		return TRUE;
	} else {
		if (error_r != NULL)
			*error_r = "Key type unsupported";
	}

	return FALSE;
}

static bool
dcrypt_openssl_key_get_curve_public(struct dcrypt_public_key *key,
				    const char **curve_r, const char **error_r)
{
	EVP_PKEY *pkey = key->key;
	char objtxt[OID_TEXT_MAX_LEN];

	if (EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) {
		*error_r = "Unsupported key type";
		return FALSE;
	}

	ASN1_OBJECT *obj = OBJ_nid2obj(EC_GROUP_get_curve_name(
				EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(pkey))));

	int len = OBJ_obj2txt(objtxt, sizeof(objtxt), obj, 1);
	ASN1_OBJECT_free(obj);

	if (len < 1) {
		return dcrypt_openssl_error(error_r);
	} else if ((unsigned int)len > sizeof(objtxt)) {
		*error_r = "Object name too long";
		return FALSE;
	}

	*curve_r = t_strndup(objtxt, len);
	return TRUE;
}

static struct dcrypt_vfs dcrypt_openssl_vfs = {
	.initialize = dcrypt_openssl_initialize,
	.ctx_sym_create = dcrypt_openssl_ctx_sym_create,
	.ctx_sym_destroy = dcrypt_openssl_ctx_sym_destroy,
	.ctx_sym_set_key = dcrypt_openssl_ctx_sym_set_key,
	.ctx_sym_set_iv = dcrypt_openssl_ctx_sym_set_iv,
	.ctx_sym_set_key_iv_random = dcrypt_openssl_ctx_sym_set_key_iv_random,
	.ctx_sym_set_padding = dcrypt_openssl_ctx_sym_set_padding,
	.ctx_sym_get_key = dcrypt_openssl_ctx_sym_get_key,
	.ctx_sym_get_iv = dcrypt_openssl_ctx_sym_get_iv,
	.ctx_sym_set_aad = dcrypt_openssl_ctx_sym_set_aad,
	.ctx_sym_get_aad = dcrypt_openssl_ctx_sym_get_aad,
	.ctx_sym_set_tag = dcrypt_openssl_ctx_sym_set_tag,
	.ctx_sym_get_tag = dcrypt_openssl_ctx_sym_get_tag,
	.ctx_sym_get_key_length = dcrypt_openssl_ctx_sym_get_key_length,
	.ctx_sym_get_iv_length = dcrypt_openssl_ctx_sym_get_iv_length,
	.ctx_sym_get_block_size = dcrypt_openssl_ctx_sym_get_block_size,
	.ctx_sym_init = dcrypt_openssl_ctx_sym_init,
	.ctx_sym_update = dcrypt_openssl_ctx_sym_update,
	.ctx_sym_final = dcrypt_openssl_ctx_sym_final,
	.ctx_hmac_create = dcrypt_openssl_ctx_hmac_create,
	.ctx_hmac_destroy = dcrypt_openssl_ctx_hmac_destroy,
	.ctx_hmac_set_key = dcrypt_openssl_ctx_hmac_set_key,
	.ctx_hmac_set_key_random = dcrypt_openssl_ctx_hmac_set_key_random,
	.ctx_hmac_get_digest_length = dcrypt_openssl_ctx_hmac_get_digest_length,
	.ctx_hmac_get_key = dcrypt_openssl_ctx_hmac_get_key,
	.ctx_hmac_init = dcrypt_openssl_ctx_hmac_init,
	.ctx_hmac_update = dcrypt_openssl_ctx_hmac_update,
	.ctx_hmac_final = dcrypt_openssl_ctx_hmac_final,
	.ecdh_derive_secret_local = dcrypt_openssl_ecdh_derive_secret_local,
	.ecdh_derive_secret_peer = dcrypt_openssl_ecdh_derive_secret_peer,
	.pbkdf2 = dcrypt_openssl_pbkdf2,
	.generate_keypair = dcrypt_openssl_generate_keypair,
	.load_private_key = dcrypt_openssl_load_private_key,
	.load_public_key = dcrypt_openssl_load_public_key,
	.store_private_key = dcrypt_openssl_store_private_key,
	.store_public_key = dcrypt_openssl_store_public_key,
	.private_to_public_key = dcrypt_openssl_private_to_public_key,
	.key_string_get_info = dcrypt_openssl_key_string_get_info,
	.unref_keypair = dcrypt_openssl_unref_keypair,
	.unref_public_key = dcrypt_openssl_unref_public_key,
	.unref_private_key = dcrypt_openssl_unref_private_key,
	.ref_public_key = dcrypt_openssl_ref_public_key,
	.ref_private_key = dcrypt_openssl_ref_private_key,
	.rsa_encrypt = dcrypt_openssl_rsa_encrypt,
	.rsa_decrypt = dcrypt_openssl_rsa_decrypt,
	.oid2name = dcrypt_openssl_oid2name,
	.name2oid = dcrypt_openssl_name2oid,
	.private_key_type = dcrypt_openssl_private_key_type,
	.public_key_type = dcrypt_openssl_public_key_type,
	.public_key_id = dcrypt_openssl_public_key_id,
	.public_key_id_old = dcrypt_openssl_public_key_id_old,
	.private_key_id = dcrypt_openssl_private_key_id,
	.private_key_id_old = dcrypt_openssl_private_key_id_old,
	.key_store_private_raw = dcrypt_openssl_key_store_private_raw,
	.key_store_public_raw = dcrypt_openssl_key_store_public_raw,
	.key_load_private_raw = dcrypt_openssl_key_load_private_raw,
	.key_load_public_raw = dcrypt_openssl_key_load_public_raw,
	.key_get_curve_public = dcrypt_openssl_key_get_curve_public,
};

void dcrypt_openssl_init(struct module *module ATTR_UNUSED)
{
	dovecot_openssl_common_global_ref();
	dcrypt_set_vfs(&dcrypt_openssl_vfs);
}

void dcrypt_openssl_deinit(void)
{
	dovecot_openssl_common_global_unref();
}
