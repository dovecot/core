/* Copyright (c) 2022 Dovecot authors, see the included COPYING file */

#ifdef DOVECOT_USE_OPENSSL3

#include "lib.h"
#include "buffer.h"
#include "base64.h"
#include "str.h"
#include "hex-binary.h"
#include "safe-memset.h"
#include "randgen.h"
#include "array.h"
#include "module-dir.h"
#include "istream.h"
#include "json-tree.h"
#include "dovecot-openssl-common.h"
#include "dcrypt.h"
#include "dcrypt-private.h"

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/objects.h>
#include <openssl/bn.h>
#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>

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

/* Not always present */
#ifndef HAVE_BN_secure_new
#  define BN_secure_new BN_new
#endif

/* openssl manual says this is OK */
#define OID_TEXT_MAX_LEN 80

#define t_base64url_decode_str(x) t_base64url_decode_str(BASE64_DECODE_FLAG_IGNORE_PADDING, (x))

#ifdef HAVE_ERR_get_error_all
#  define openssl_get_error_data(data, flags) \
	ERR_get_error_all(NULL, NULL, NULL, data, flags)
#else
#  define openssl_get_error_data(data, flags) \
	ERR_get_error_line_data(NULL, NULL, data, flags)
#endif

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
	EVP_MAC *mac;
	EVP_MAC_CTX *ctx;
	const EVP_MD *md;
	unsigned char *key;
	size_t klen;
};

struct dcrypt_public_key {
	EVP_PKEY *key;
	unsigned int ref;
	enum dcrypt_key_usage usage;
	char *key_id;
};

struct dcrypt_private_key {
	EVP_PKEY *key;
	unsigned int ref;
	enum dcrypt_key_usage usage;
	char *key_id;
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
static void
dcrypt_openssl_unref_private_key(struct dcrypt_private_key **key);
static void
dcrypt_openssl_unref_public_key(struct dcrypt_public_key **key);
static bool
dcrypt_openssl_rsa_decrypt(struct dcrypt_private_key *key,
			   const unsigned char *data, size_t data_len,
			   buffer_t *result, enum dcrypt_padding padding,
			   const char **error_r);
static bool
dcrypt_openssl_key_string_get_info(const char *key_data,
	enum dcrypt_key_format *format_r, enum dcrypt_key_version *version_r,
	enum dcrypt_key_kind *kind_r,
	enum dcrypt_key_encryption_type *encryption_type_r,
	const char **encryption_key_hash_r, const char **key_hash_r,
	const char **error_r);

static const char *ssl_err2str(unsigned long err, const char *data, int flags)
{
	const char *ret;
	char *buf;
	const size_t err_size = 256;

	buf = t_malloc_no0(err_size);
	/* will add \0 and the end */
	ERR_error_string_n(err, buf, err_size);
	ret = buf;

	if ((flags & ERR_TXT_STRING) != 0)
		ret = t_strdup_printf("%s: %s", buf, data);
	return ret;
}

static bool dcrypt_openssl_error(const char **error_r)
{
	string_t *errstr = NULL;
	unsigned long err;
	const char *data, *final_error;
	int flags;

	while ((err = openssl_get_error_data(&data, &flags)) != 0) {
		if (ERR_GET_REASON(err) == ERR_R_MALLOC_FAILURE)
			i_fatal_status(FATAL_OUTOFMEM, "OpenSSL malloc() failed");
		if (ERR_peek_error() == 0)
			break;
		if (errstr == NULL)
			errstr = t_str_new(128);
		else
			str_append(errstr, ", ");
		str_append(errstr, ssl_err2str(err, data, flags));
	}
	if (err == 0) {
		if (errno != 0)
			final_error = strerror(errno);
		else
			final_error = "Unknown error";
	} else {
		final_error = ssl_err2str(err, data, flags);
	}
	if (errstr == NULL)
		*error_r = final_error;
	else {
		str_printfa(errstr, ", %s", final_error);
		*error_r = str_c(errstr);
	}

	return FALSE;
}

static int
dcrypt_openssl_padding_mode(enum dcrypt_padding padding,
			    bool sig, const char **error_r)
{
	switch (padding) {
	case DCRYPT_PADDING_DEFAULT:
		if (sig) return RSA_PKCS1_PSS_PADDING;
		else return RSA_PKCS1_OAEP_PADDING;
	case DCRYPT_PADDING_RSA_PKCS1_OAEP:
		return RSA_PKCS1_OAEP_PADDING;
	case DCRYPT_PADDING_RSA_PKCS1_PSS:
		return RSA_PKCS1_PSS_PADDING;
	case DCRYPT_PADDING_RSA_PKCS1:
		return RSA_PKCS1_PADDING;
	case DCRYPT_PADDING_RSA_NO:
		return RSA_NO_PADDING;
	default:
		*error_r = "Unsupported padding mode";
		return -1;
	}
	i_unreached();
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
		*error_r = t_strdup_printf("Invalid cipher %s", algorithm);
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
	p_free(ctx->pool, ctx->key);
	ctx->key = p_malloc(ctx->pool, EVP_CIPHER_key_length(ctx->cipher));
	memcpy(ctx->key, key, I_MIN(key_len,
	       (size_t)EVP_CIPHER_key_length(ctx->cipher)));
}

static void
dcrypt_openssl_ctx_sym_set_iv(struct dcrypt_context_symmetric *ctx,
			      const unsigned char *iv, size_t iv_len)
{
	p_free(ctx->pool, ctx->iv);
	ctx->iv = p_malloc(ctx->pool, EVP_CIPHER_iv_length(ctx->cipher));
	memcpy(ctx->iv, iv, I_MIN(iv_len,
	       (size_t)EVP_CIPHER_iv_length(ctx->cipher)));
}

static void
dcrypt_openssl_ctx_sym_set_key_iv_random(struct dcrypt_context_symmetric *ctx)
{
	p_free(ctx->pool, ctx->key);
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
	if (ctx->key == NULL)
		return FALSE;

	buffer_append(key, ctx->key, EVP_CIPHER_key_length(ctx->cipher));
	return TRUE;
}

static bool
dcrypt_openssl_ctx_sym_get_iv(struct dcrypt_context_symmetric *ctx,
			      buffer_t *iv)
{
	if (ctx->iv == NULL)
		return FALSE;

	buffer_append(iv, ctx->iv, EVP_CIPHER_iv_length(ctx->cipher));
	return TRUE;
}

static void
dcrypt_openssl_ctx_sym_set_aad(struct dcrypt_context_symmetric *ctx,
			       const unsigned char *aad, size_t aad_len)
{
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
	i_assert(tag_len > 0);
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

	if ((ctx->ctx = EVP_CIPHER_CTX_new()) == NULL)
		dcrypt_openssl_error(error_r);

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
	if (EVP_CipherUpdate(ctx->ctx, buf, &outl, data, data_len) != 1)
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

	if (ec == 0)
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
	const EVP_MD *md = EVP_get_digestbyname(algorithm);
	if (md == NULL) {
		*error_r = t_strdup_printf("Invalid digest %s", algorithm);
		return FALSE;
	}
	EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
	if (mac == NULL) {
		*error_r = "No HMAC support";
		return FALSE;
	}
	/* allocate context */
	pool = pool_alloconly_create("dcrypt openssl", 1024);
	ctx = p_new(pool, struct dcrypt_context_hmac, 1);
	ctx->pool = pool;
	ctx->mac = mac;
	ctx->md = md;
	*ctx_r = ctx;
	return TRUE;
}

static void
dcrypt_openssl_ctx_hmac_destroy(struct dcrypt_context_hmac **ctx)
{
	pool_t pool = (*ctx)->pool;
	EVP_MAC_free((*ctx)->mac);
	pool_unref(&pool);
	*ctx = NULL;
}

static void
dcrypt_openssl_ctx_hmac_set_key(struct dcrypt_context_hmac *ctx,
				const unsigned char *key, size_t key_len)
{
	p_free(ctx->pool, ctx->key);
	ctx->klen = I_MIN(key_len, 200 /* same as HMAC_MAX_MD_CBLOCK */);
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
	ctx->klen = 200; /* same as HMAC_MAX_MD_CBLOCK */
	ctx->key = p_malloc(ctx->pool, ctx->klen);
	random_fill(ctx->key, ctx->klen);
}

static unsigned int
dcrypt_openssl_ctx_hmac_get_digest_length(struct dcrypt_context_hmac *ctx)
{
	return EVP_MAC_CTX_get_mac_size(ctx->ctx);
}

static bool
dcrypt_openssl_ctx_hmac_init(struct dcrypt_context_hmac *ctx,
			     const char **error_r)
{
	int ec;

	i_assert(ctx->mac != NULL);
	const char *name = EVP_MD_get0_name(ctx->md);
	OSSL_PARAM params[] = {
		OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, (void*)name, strlen(name)),
		OSSL_PARAM_END
	};
	ctx->ctx = EVP_MAC_CTX_new(ctx->mac);
	if (ctx->ctx == NULL)
		dcrypt_openssl_error(error_r);
	ec = EVP_MAC_init(ctx->ctx, ctx->key, ctx->klen, params);
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

	ec = EVP_MAC_update(ctx->ctx, data, data_len);
	if (ec != 1)
		return dcrypt_openssl_error(error_r);
	return TRUE;
}

static bool
dcrypt_openssl_ctx_hmac_final(struct dcrypt_context_hmac *ctx, buffer_t *result,
			      const char **error_r)
{
	int ec;
	size_t outl;
	size_t outsize = dcrypt_openssl_ctx_hmac_get_digest_length(ctx);
	unsigned char buf[outsize];
	ec = EVP_MAC_final(ctx->ctx, buf, &outl, outsize);
	EVP_MAC_CTX_free(ctx->ctx);
	ctx->ctx = NULL;
	if (ec == 1)
		buffer_append(result, buf, outl);
	else
		return dcrypt_openssl_error(error_r);
	return TRUE;
}

/* legacy function for old formats that generates
   hex encoded point from EC public key
 */
static const char *ec_key_get_pub_point_hex(const EVP_PKEY *pkey)
{
	/* get the public key */
	unsigned char buf[EVP_PKEY_size(pkey)*2];
	size_t len;
	EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, buf, sizeof(buf), &len);
	return binary_to_hex_ucase(buf, len);
}

static int dcrypt_EVP_PKEY_get_nid(const EVP_PKEY *pkey)
{
	char buf[128];
	size_t len;
	int ec = EVP_PKEY_get_group_name(pkey, buf, sizeof(buf), &len);
	i_assert(ec == 1 && len > 0);
	buf[len] = '\0';
	return OBJ_txt2nid(buf);
}

static OSSL_PARAM dcrypt_construct_param_BN(const char *key, const BIGNUM *bn)
{
	int bn_len = BN_num_bytes(bn)+1;
	buffer_t *buf = t_buffer_create(bn_len);
	BN_bn2nativepad(bn, buffer_append_space_unsafe(buf, bn_len), bn_len);
	return OSSL_PARAM_construct_BN(key, buffer_get_modifiable_data(buf, NULL), buf->used);
}

static bool
dcrypt_openssl_ec_get_pubkey_point(const EC_GROUP *g, const BIGNUM *priv, EC_POINT **pub_r)
{
	bool ret = FALSE;
	BN_CTX *bnctx = BN_CTX_new();
	EC_POINT *pub = EC_POINT_new(g);
	EC_POINT_mul(g, pub, priv, NULL, NULL, bnctx);
	if (EC_POINT_is_at_infinity(g, pub) == 0 &&
	    EC_POINT_is_on_curve(g, pub, bnctx) == 1) {
		/* This point looks valid */
		*pub_r = pub;
		ret = TRUE;
	} else {
		EC_POINT_free(pub);
	}
	BN_CTX_free(bnctx);
	return ret;
}

static bool
dcrypt_evp_pkey_from_bn(int nid, BIGNUM *bn, EVP_PKEY **pkey_r, const char **error_r)
{
	i_assert(bn != NULL);

	EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(nid);
	EC_POINT *pub;
	if (!dcrypt_openssl_ec_get_pubkey_point(ec_group, bn, &pub)) {
		*error_r = "Point is not on curve";
		EC_GROUP_free(ec_group);
		return FALSE;
	}

	char *group = (char*)OBJ_nid2sn(nid);
	unsigned char *pptr = NULL;
	size_t plen = EC_POINT_point2buf(ec_group, pub, POINT_CONVERSION_COMPRESSED, &pptr, NULL);
	EC_POINT_free(pub);
	EC_GROUP_free(ec_group);

	/* create OSSL PARAMS */
	OSSL_PARAM params[6];
	params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group, 0);
	params[1] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, "named_curve", 0);
	params[2] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, "compressed", 0);
	params[3] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pptr, plen);
	params[4] = dcrypt_construct_param_BN(OSSL_PKEY_PARAM_PRIV_KEY, bn);
	params[5] = OSSL_PARAM_construct_end();

	EVP_PKEY_CTX *ctx =
	    EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	EVP_PKEY *pkey = EVP_PKEY_new();

	int ec;
	if ((ec = EVP_PKEY_fromdata_init(ctx)) != 1 ||
	    (ec = EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params)) != 1) {
		/* pass */
	}

	EVP_PKEY_CTX_free(ctx);
	OPENSSL_free(pptr);

	if (ec != 1) {
		EVP_PKEY_free(pkey);
		return dcrypt_openssl_error(error_r);
	}

	*pkey_r = pkey;
	return TRUE;
}

static bool
dcrypt_evp_pkey_from_point(int nid, EC_POINT *point, EVP_PKEY **pkey_r, const char **error_r)
{
	char *group = (char*)OBJ_nid2sn(nid);
	EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(nid);
	unsigned char *pptr = NULL;
	size_t plen = EC_POINT_point2buf(ec_group, point, POINT_CONVERSION_COMPRESSED, &pptr, NULL);
	EC_GROUP_free(ec_group);

	/* create OSSL PARAMS */
	OSSL_PARAM params[5];
	params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group, 0);
	params[1] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, "named_curve", 0);
	params[2] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, "uncompressed", 0);
	params[3] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pptr, plen);
	params[4] = OSSL_PARAM_construct_end();

	EVP_PKEY_CTX *ctx =
	    EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	EVP_PKEY *pkey = EVP_PKEY_new();

	int ec;
	if ((ec = EVP_PKEY_fromdata_init(ctx)) != 1 ||
	    (ec = EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params)) != 1) {
		/* pass */
	}
	OPENSSL_free(pptr);
	EVP_PKEY_CTX_free(ctx);
	if (ec != 1) {
		EVP_PKEY_free(pkey);
		return dcrypt_openssl_error(error_r);
	}
	*pkey_r = pkey;
	return TRUE;
}

static bool
dcrypt_openssl_generate_ec_key(int nid, EVP_PKEY **key, const char **error_r)
{
	EVP_PKEY_CTX *pctx;
	EVP_PKEY_CTX *ctx;
	EVP_PKEY *params = NULL;

	/* generate parameters for EC */
	pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (pctx == NULL ||
	    EVP_PKEY_paramgen_init(pctx) < 1 ||
	    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid) < 1 ||
	    EVP_PKEY_CTX_set_ec_param_enc(pctx, OPENSSL_EC_NAMED_CURVE) < 1 ||
	    EVP_PKEY_paramgen(pctx, &params) < 1)
	{
		dcrypt_openssl_error(error_r);
		EVP_PKEY_CTX_free(pctx);
		return FALSE;
	}

	/* generate key from parameters */
	ctx = EVP_PKEY_CTX_new_from_pkey(NULL, params, NULL);
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
dcrypt_openssl_ecdh_derive_secret(struct dcrypt_private_key *priv_key,
				  struct dcrypt_public_key *pub_key,
				  buffer_t *shared_secret,
				  const char **error_r)
{
	/* initialize */
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(priv_key->key, NULL);
	if (pctx == NULL ||
	    EVP_PKEY_derive_init(pctx) != 1 ||
	    EVP_PKEY_derive_set_peer(pctx, pub_key->key) != 1) {
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
	buffer_append(shared_secret, buf, len);

	return TRUE;
}

static bool
dcrypt_openssl_ecdh_derive_secret_local(struct dcrypt_private_key *local_key,
					buffer_t *R, buffer_t *S,
					const char **error_r)
{
	bool ret;
	i_assert(local_key != NULL && local_key->key != NULL);

	EVP_PKEY *local = local_key->key;

	char buf[128];
	size_t len;
	int ec;
	ec = EVP_PKEY_get_group_name(local, buf, sizeof(buf), &len);
	i_assert(ec == 1 && len > 0);
	buf[len] = '\0';

	/* create OSSL PARAMS */
	OSSL_PARAM params[] = {
		OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, buf, len),
		OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, "named_curve", 11),
		OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, "compressed", 10),
		OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void*)R->data, R->used),
		OSSL_PARAM_END
	};

	EVP_PKEY_CTX *ctx =
	    EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	EVP_PKEY *peer = EVP_PKEY_new();

	if ((EVP_PKEY_fromdata_init(ctx)) != 1 ||
	    (EVP_PKEY_fromdata(ctx, &peer, EVP_PKEY_PUBLIC_KEY, params)) != 1) {
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(peer);
		return dcrypt_openssl_error(error_r);
	}
	EVP_PKEY_CTX_free(ctx);

	struct dcrypt_public_key pub_key;
	i_zero(&pub_key);
	pub_key.key = peer;

	ret = dcrypt_openssl_ecdh_derive_secret(local_key, &pub_key, S, error_r);

	EVP_PKEY_free(peer);
	return ret;
}

static bool
dcrypt_openssl_ecdh_derive_secret_peer(struct dcrypt_public_key *peer_key,
				       buffer_t *R, buffer_t *S,
				       const char **error_r)
{
	i_assert(peer_key != NULL && peer_key->key != NULL);
	bool ret;

	/* ensure peer_key is EC key */
	EVP_PKEY *local = NULL;
	EVP_PKEY *peer = peer_key->key;
	if (EVP_PKEY_base_id(peer) != EVP_PKEY_EC) {
		*error_r = "Only ECC key can be used";
		return FALSE;
	}

	/* generate another key from same group */
	int nid = dcrypt_EVP_PKEY_get_nid(peer);
	if (!dcrypt_openssl_generate_ec_key(nid, &local, error_r))
		return FALSE;

	struct dcrypt_private_key priv_key;
	i_zero(&priv_key);
	priv_key.key = local;

	if (!(ret = dcrypt_openssl_ecdh_derive_secret(&priv_key, peer_key, S,
						 error_r))) {
		EVP_PKEY_free(local);
		return FALSE;
	}

	/* get ephemeral key (=R) */
	unsigned char *pub;
	size_t len = EVP_PKEY_get1_encoded_public_key(local, &pub);
	buffer_append(R, pub, len);
	OPENSSL_free(pub);
	EVP_PKEY_free(local);

	return ret;
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
	const EVP_MD *md = EVP_get_digestbyname(hash);
	if (md == NULL) {
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
			*error_r = t_strdup_printf("Unknown EC curve %s", curve);
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
					   &dctx, error_r))
		return FALSE;

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
	safe_memset(buffer_get_modifiable_data(tmp, NULL), 0, tmp->used);
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
				   "sha256", 16, key, 32, error_r))
		return FALSE;

	return dcrypt_openssl_decrypt_point_v1(data, key, point_r, error_r);
}

static bool
dcrypt_openssl_load_private_key_dovecot_v1(struct dcrypt_private_key **key_r,
					   int len, const char **input,
					   const char *password,
					   struct dcrypt_private_key *dec_key,
					   const char **error_r)
{
	int nid, enctype;
	BIGNUM *point = NULL;

	if (str_to_int(input[1], &nid) != 0) {
		*error_r = "Corrupted data";
		return FALSE;
	}

	if (str_to_int(input[2], &enctype) != 0) {
		*error_r = "Corrupted data";
		return FALSE;
	}

	/* decode and optionally decipher private key value */
	if (enctype == DCRYPT_DOVECOT_KEY_ENCRYPT_NONE) {
		point = BN_secure_new();
		if (BN_hex2bn(&point, input[3]) < 1) {
			BN_free(point);
			return dcrypt_openssl_error(error_r);
		}
	} else if (enctype == DCRYPT_DOVECOT_KEY_ENCRYPT_PASSWORD) {
		/* by password */
		if (password == NULL) {
			*error_r = "password missing";
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
			*error_r = "decrypt key missing";
			return FALSE;
		}
		const char *enc_priv_pt = input[3];
		const char *peer_key = input[4];
		if (!dcrypt_openssl_decrypt_point_ec_v1(
			dec_key, enc_priv_pt, peer_key, &point, error_r)) {
			return FALSE;
		}
	} else {
		*error_r = "Invalid key data";
		return FALSE;
	}

	EVP_PKEY *pkey;
	if (!dcrypt_evp_pkey_from_bn(nid, point, &pkey, error_r)) {
		BN_free(point);
		return FALSE;
	}
	BN_free(point);

	unsigned char digest[SHA256_DIGEST_LENGTH];
	const char *id = ec_key_get_pub_point_hex(pkey);
	SHA256((const void*)id, strlen(id), digest);
	const char *digest_hex = binary_to_hex(digest, sizeof(digest));
	/* validate that the key was loaded correctly */
	if (strcmp(digest_hex, input[len-1]) != 0) {
		*error_r = "Key id mismatch after load";
		EVP_PKEY_free(pkey);
		return FALSE;
	}
	*key_r = i_new(struct dcrypt_private_key, 1);
	(*key_r)->key = pkey;
	(*key_r)->ref++;
	return TRUE;
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

	if (!dcrypt_openssl_ctx_sym_create(cipher, mode, &dctx, error_r))
		return FALSE;

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
		buffer_append_buf(result_r, tmp, 0, SIZE_MAX);
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
		*error_r = "Corrupted data";
		return FALSE;
	}

	if (enctype < 0 || enctype > 2) {
		*error_r = "Corrupted data";
		return FALSE;
	}

	/* match encryption type to field counts */
	if ((enctype == DCRYPT_DOVECOT_KEY_ENCRYPT_NONE && len != 5) ||
	    (enctype == DCRYPT_DOVECOT_KEY_ENCRYPT_PASSWORD && len != 9) ||
	    (enctype == DCRYPT_DOVECOT_KEY_ENCRYPT_PK && len != 11)) {
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
			*error_r = "Corrupted data";
			return FALSE;
		}
	} else if (enctype == DCRYPT_DOVECOT_KEY_ENCRYPT_PK) {
		if (dec_key == NULL) {
			*error_r = "decrypt key missing";
			return FALSE;
		}
		unsigned int rounds;
		struct dcrypt_public_key *pubkey = NULL;
		if (str_to_uint(input[6], &rounds) != 0) {
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
				DCRYPT_PADDING_RSA_PKCS1_OAEP, error_r))
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
			*error_r = "password missing";
			return FALSE;
		}
		unsigned int rounds;
		if (str_to_uint(input[6], &rounds) != 0) {
			*error_r = "Corrupted data";
			return FALSE;
		}

		buffer_t *salt, secret, *data;
		salt = t_buffer_create(strlen(input[4])/2);
		buffer_create_from_const_data(&secret, password, strlen(password));
		data = t_buffer_create(strlen(input[7])/2);
		if (hex_to_binary(input[4], salt) != 0 ||
		    hex_to_binary(input[7], data) != 0) {
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
		EVP_PKEY *pkey = NULL;
		size_t len;
		const unsigned char *ptr = buffer_get_data(key_data, &len);
		if (d2i_PrivateKey(EVP_PKEY_RSA, &pkey, &ptr, (long)len) == NULL) {
			safe_memset(buffer_get_modifiable_data(key_data, NULL),
				    0, key_data->used);
			return dcrypt_openssl_error(error_r);
		}
		safe_memset(buffer_get_modifiable_data(key_data, NULL),
			    0, key_data->used);
		*key_r = i_new(struct dcrypt_private_key, 1);
		(*key_r)->key = pkey;
		(*key_r)->ref++;
	} else {
		BIGNUM *point = BN_secure_new();
		if (BN_mpi2bn(key_data->data, key_data->used, point) == NULL) {
			safe_memset(buffer_get_modifiable_data(key_data, NULL),
				    0, key_data->used);
			BN_free(point);
			return dcrypt_openssl_error(error_r);
		}
		safe_memset(buffer_get_modifiable_data(key_data, NULL),
			    0, key_data->used);
		EVP_PKEY *pkey;
		if (!dcrypt_evp_pkey_from_bn(nid, point, &pkey, error_r)) {
			BN_free(point);
			return FALSE;
		}
		BN_free(point);
		*key_r = i_new(struct dcrypt_private_key, 1);
		(*key_r)->key = pkey;
		(*key_r)->ref++;
	}

	/* finally compare key to key id */
	str_truncate(key_data, 0);
	if (!dcrypt_openssl_private_key_id(*key_r, "sha256", key_data, error_r)) {
		dcrypt_openssl_unref_private_key(key_r);
		return FALSE;
	}

	if (strcmp(binary_to_hex(key_data->data, key_data->used),
		   input[len-1]) != 0) {
		dcrypt_openssl_unref_private_key(key_r);
		*error_r = "Key id mismatch after load";
		return FALSE;
	}

	return TRUE;
}

/* JWK Parameter names defined at https://www.iana.org/assignments/jose/jose.xhtml */

static const struct jwk_to_ssl_map_entry {
	const char *jwk_curve;
	int nid;
} jwk_to_ssl_curves[] = {
	/* See https://tools.ietf.org/search/rfc8422#appendix-A */
	{ .jwk_curve = "P-256", .nid = NID_X9_62_prime256v1 },
	{ .jwk_curve = "P-384", .nid = NID_secp384r1 },
	{ .jwk_curve = "P-521", .nid = NID_secp521r1 },
	{ .jwk_curve = NULL, .nid = 0 }
};

static const char *key_usage_to_jwk_use(enum dcrypt_key_usage usage)
{
	switch (usage) {
	case DCRYPT_KEY_USAGE_NONE:
		return "";
	case DCRYPT_KEY_USAGE_ENCRYPT:
		return "enc";
	case DCRYPT_KEY_USAGE_SIGN:
		return "sig";
	};
	i_unreached();
}

static enum dcrypt_key_usage jwk_use_to_key_usage(const char *use)
{
	if (strcmp(use, "enc") == 0)
		return DCRYPT_KEY_USAGE_ENCRYPT;
	if (strcmp(use, "sig") == 0)
		return DCRYPT_KEY_USAGE_SIGN;
	return DCRYPT_KEY_USAGE_NONE;
}

static int jwk_curve_to_nid(const char *curve)
{
	/* use static mapping table to get correct input for OpenSSL */
	const struct jwk_to_ssl_map_entry *entry = jwk_to_ssl_curves;
	for (; entry->jwk_curve != NULL; entry++)
		if (strcmp(curve, entry->jwk_curve) == 0)
			return entry->nid;
	return 0;
}

static const char *nid_to_jwk_curve(int nid)
{
	const struct jwk_to_ssl_map_entry *entry = jwk_to_ssl_curves;
	for (; entry->jwk_curve != NULL; entry++)
		if (nid == entry->nid)
			return entry->jwk_curve;
	return NULL;
}

/* Loads both public and private key */
static bool load_jwk_ec_key(EVP_PKEY **key_r, bool want_private_key,
			    const struct json_tree_node *root,
			    const char *password ATTR_UNUSED,
			    struct dcrypt_private_key *dec_key ATTR_UNUSED,
			    const char **error_r)
{
	i_assert(password == NULL && dec_key == NULL);
	const char *crv, *x, *y, *d;
	const struct json_tree_node *node;

	if ((node = json_tree_find_key(root, "crv")) == NULL ||
	    (crv = json_tree_get_value_str(node)) == NULL) {
		*error_r = "Missing crv parameter";
		return FALSE;
	}

	if ((node = json_tree_find_key(root, "x")) == NULL ||
	    (x = json_tree_get_value_str(node)) == NULL) {
		*error_r = "Missing x parameter";
		return FALSE;
	}

	if ((node = json_tree_find_key(root, "y")) == NULL ||
	    (y = json_tree_get_value_str(node)) == NULL) {
		*error_r = "Missing y parameter";
		return FALSE;
	}

	int nid = jwk_curve_to_nid(crv);
	if (nid == 0) {
		*error_r = "Invalid curve";
		return FALSE;
	}

	/* base64 decode x and y */
	buffer_t *bx = t_base64url_decode_str(x);
	buffer_t *by = t_base64url_decode_str(y);
	BIGNUM *pd = NULL;

	/* FIXME: Support decryption */
	if (want_private_key) {
		if ((node = json_tree_find_key(root, "d")) == NULL ||
		    (d = json_tree_get_value_str(node)) == NULL) {
			*error_r = "Missing d parameter";
			return FALSE;
		}
		buffer_t *bd = t_base64url_decode_str(d);
		if ((pd = BN_bin2bn(bd->data, bd->used, pd)) == NULL)
			return dcrypt_openssl_error(error_r);
	}

	BIGNUM *px = NULL, *py = NULL;
	if ((px = BN_bin2bn(bx->data, bx->used, px)) == NULL ||
	    (py = BN_bin2bn(by->data, by->used, py)) == NULL) {
		BN_free(pd);
		BN_free(px);
		BN_free(py);
		return dcrypt_openssl_error(error_r);
	}

	EC_GROUP *g = EC_GROUP_new_by_curve_name(nid);
	EC_POINT *p = EC_POINT_new(g);
	BN_CTX *bnctx = BN_CTX_new();

	bool res;

	/* ensure it landed on the curve */
	if (EC_POINT_set_affine_coordinates(g, p, px, py, bnctx) == 1) {
		res = TRUE;
	} else {
		res = dcrypt_openssl_error(error_r);
	}

	EVP_PKEY *pkey;
	if (!res) {
		/* pass */
	} else if (want_private_key) {
		res = dcrypt_evp_pkey_from_bn(nid, pd, &pkey, error_r);
		/* check that we got same private key */
		if (res) {
			BIGNUM *cx = BN_new();
			BIGNUM *cy = BN_new();
			if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &cx) != 1 ||
			    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &cy) != 1)
				i_unreached();
			if (BN_cmp(px, cx) != 0 ||
			    BN_cmp(py, cy) != 0) {
				ERR_raise_data(ERR_R_EC_LIB, ERR_R_INVALID_PROPERTY_DEFINITION,
					       "Private key did not match with public key");
				EVP_PKEY_free(pkey);
				res = FALSE;
			}
			BN_free(cx);
			BN_free(cy);
		}
	} else {
		res = dcrypt_evp_pkey_from_point(nid, p, &pkey, error_r);
	}

	BN_CTX_free(bnctx);
	EC_POINT_free(p);
	EC_GROUP_free(g);
	BN_free(pd);
	BN_free(px);
	BN_free(py);

	if (!res)
		return dcrypt_openssl_error(error_r);
	*key_r = pkey;
	return TRUE;
}

/* Loads both public and private key */
static bool load_jwk_rsa_key(EVP_PKEY **key_r, bool want_private_key,
			     const struct json_tree_node *root,
			     const char *password ATTR_UNUSED,
			     struct dcrypt_private_key *dec_key ATTR_UNUSED,
			     const char **error_r)
{
	const char *n, *e, *d = NULL, *p = NULL, *q = NULL, *dp = NULL;
	const char *dq = NULL, *qi = NULL;
	const struct json_tree_node *node;

	/* n and e must be present */
	if ((node = json_tree_find_key(root, "n")) == NULL ||
	    (n = json_tree_get_value_str(node)) == NULL) {
		*error_r = "Missing n parameter";
		return FALSE;
	}

	if ((node = json_tree_find_key(root, "e")) == NULL ||
	    (e = json_tree_get_value_str(node)) == NULL) {
		*error_r = "Missing e parameter";
		return FALSE;
	}

	if (want_private_key) {
		if ((node = json_tree_find_key(root, "d")) == NULL ||
		    (d = json_tree_get_value_str(node)) == NULL) {
			*error_r = "Missing d parameter";
			return FALSE;
		}

		if ((node = json_tree_find_key(root, "p")) == NULL ||
		    (p = json_tree_get_value_str(node)) == NULL) {
			*error_r = "Missing p parameter";
			return FALSE;
		}

		if ((node = json_tree_find_key(root, "q")) == NULL ||
		    (q = json_tree_get_value_str(node)) == NULL) {
			*error_r = "Missing q parameter";
			return FALSE;
		}

		if ((node = json_tree_find_key(root, "dp")) == NULL ||
		    (dp = json_tree_get_value_str(node)) == NULL) {
			*error_r = "Missing dp parameter";
			return FALSE;
		}

		if ((node = json_tree_find_key(root, "dq")) == NULL ||
		    (dq = json_tree_get_value_str(node)) == NULL) {
			*error_r = "Missing dq parameter";
			return FALSE;
		}

		if ((node = json_tree_find_key(root, "qi")) == NULL ||
		    (qi = json_tree_get_value_str(node)) == NULL) {
			*error_r = "Missing qi parameter";
			return FALSE;
		}
	}

	/* convert into BIGNUMs */
	BIGNUM *pn = NULL, *pe = NULL, *pd = NULL, *pp = NULL;
	BIGNUM *pq = NULL, *pdp = NULL, *pdq = NULL, *pqi = NULL;
	buffer_t *bn = t_base64url_decode_str(n);
	buffer_t *be = t_base64url_decode_str(e);
	if (want_private_key) {
		pd = BN_secure_new();
		buffer_t *bd = t_base64url_decode_str(d);
		if (BN_bin2bn(bd->data, bd->used, pd) == NULL) {
			BN_free(pd);
			return dcrypt_openssl_error(error_r);
		}
	} else {
		pd = NULL;
	}

	pn = BN_new();
	pe = BN_new();

	if (BN_bin2bn(bn->data, bn->used, pn) == NULL ||
	    BN_bin2bn(be->data, be->used, pe) == NULL) {
		BN_free(pd);
		BN_free(pn);
		BN_free(pe);
		return dcrypt_openssl_error(error_r);
	}

	if (want_private_key) {
		pp = BN_secure_new();
		pq = BN_secure_new();
		pdp = BN_secure_new();
		pdq = BN_secure_new();
		pqi = BN_secure_new();

		buffer_t *bp = t_base64url_decode_str(p);
		buffer_t *bq = t_base64url_decode_str(q);
		buffer_t *bdp = t_base64url_decode_str(dp);
		buffer_t *bdq = t_base64url_decode_str(dq);
		buffer_t *bqi = t_base64url_decode_str(qi);

		if (BN_bin2bn(bp->data, bp->used, pp) == NULL ||
		    BN_bin2bn(bq->data, bq->used, pq) == NULL ||
		    BN_bin2bn(bdp->data, bdp->used, pdp) == NULL ||
		    BN_bin2bn(bdq->data, bdq->used, pdq) == NULL ||
		    BN_bin2bn(bqi->data, bqi->used, pqi) == NULL) {
			BN_free(pn);
			BN_free(pe);
			BN_free(pp);
			BN_free(pq);
			BN_free(pdp);
			BN_free(pdq);
			BN_free(pqi);
			return dcrypt_openssl_error(error_r);
		}
	}

	/* create pkey */
	OSSL_PARAM params[9];
	params[0] = dcrypt_construct_param_BN(OSSL_PKEY_PARAM_RSA_N, pn);
	params[1] = dcrypt_construct_param_BN(OSSL_PKEY_PARAM_RSA_E, pe);

	if (want_private_key) {
		params[2] = dcrypt_construct_param_BN(OSSL_PKEY_PARAM_RSA_FACTOR1, pp);
		params[3] = dcrypt_construct_param_BN(OSSL_PKEY_PARAM_RSA_FACTOR2, pq);
		params[4] = dcrypt_construct_param_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1, pdp);
		params[5] = dcrypt_construct_param_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1, pdq);
		params[6] = dcrypt_construct_param_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, pqi);
		params[7] = OSSL_PARAM_construct_end();
	} else {
		params[2] = OSSL_PARAM_construct_end();
	}

	/* then load the key */
	EVP_PKEY_CTX *ctx =
	    EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	EVP_PKEY *pkey = EVP_PKEY_new();

	int ec;
	if ((ec = EVP_PKEY_fromdata_init(ctx)) != 1 ||
	    (ec = EVP_PKEY_fromdata(ctx, &pkey, want_private_key ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY, params)) != 1) {
		/* pass */
	}
	EVP_PKEY_CTX_free(ctx);
	BN_free(pn);
	BN_free(pe);

	if (want_private_key) {
		BN_free(pp);
		BN_free(pq);
		BN_free(pdp);
		BN_free(pdq);
		BN_free(pqi);
	}

	if (ec != 1) {
		EVP_PKEY_free(pkey);
		return dcrypt_openssl_error(error_r);
	}

	*key_r = pkey;

	return TRUE;
}


static bool
dcrypt_openssl_load_private_key_jwk(struct dcrypt_private_key **key_r,
				    const char *data, const char *password,
				    struct dcrypt_private_key *dec_key,
				    const char **error_r)
{
	const char *kty;
	const char *error;
	const struct json_tree_node *root, *node;
	struct json_tree *key_tree;
	EVP_PKEY *pkey = NULL;
	bool ret;

	if (parse_jwk_key(data, &key_tree, &error) != 0) {
		*error_r = t_strdup_printf("Cannot load JWK private key: %s",
					   error);
		return FALSE;
	}

	root = json_tree_root(key_tree);

	/* check key type */
	if ((node = json_tree_find_key(root, "kty")) == NULL) {
		*error_r = "Cannot load JWK private key: no kty parameter";
		json_tree_deinit(&key_tree);
		return FALSE;
	}

	kty = json_tree_get_value_str(node);

	if (null_strcmp(kty, "EC") == 0) {
		ret = load_jwk_ec_key(&pkey, TRUE, root, password, dec_key, &error);
	} else if (strcmp(kty, "RSA") == 0) {
		ret = load_jwk_rsa_key(&pkey, TRUE, root, password, dec_key, &error);
	} else {
		error = "Unsupported key type";
		ret = FALSE;
	}

	i_assert(ret || error != NULL);

	if (!ret)
		*error_r = t_strdup_printf("Cannot load JWK private key: %s", error);
	else {
		*key_r = i_new(struct dcrypt_private_key, 1);
		(*key_r)->key = pkey;
		(*key_r)->ref++;
		/* check if kid is present */
		if ((node = json_tree_find_key(root, "kid")) != NULL)
			(*key_r)->key_id = i_strdup_empty(json_tree_get_value_str(node));
		/* check if use is present */
		if ((node = json_tree_find_key(root, "use")) != NULL)
			(*key_r)->usage = jwk_use_to_key_usage(json_tree_get_value_str(node));
	}

	json_tree_deinit(&key_tree);

	return ret;
}

static bool
dcrypt_openssl_load_public_key_jwk(struct dcrypt_public_key **key_r,
				   const char *data, const char **error_r)
{
	const char *kty;
	const char *error;
	const struct json_tree_node *root, *node;
	struct json_tree *key_tree;
	EVP_PKEY *pkey = NULL;
	bool ret;

	if (parse_jwk_key(data, &key_tree, &error) != 0) {
		*error_r = t_strdup_printf("Cannot load JWK public key: %s",
					   error);
		return FALSE;
	}

	root = json_tree_root(key_tree);

	/* check key type */
	if ((node = json_tree_find_key(root, "kty")) == NULL) {
		*error_r = "Cannot load JWK public key: no kty parameter";
		json_tree_deinit(&key_tree);
		return FALSE;
	}

	kty = json_tree_get_value_str(node);

	if (null_strcmp(kty, "EC") == 0) {
		ret = load_jwk_ec_key(&pkey, FALSE, root, NULL, NULL, &error);
	} else if (strcmp(kty, "RSA") == 0) {
	      ret = load_jwk_rsa_key(&pkey, FALSE, root, NULL, NULL, &error);
	} else {
		error = "Unsupported key type";
		ret = FALSE;
	}

	i_assert(ret || error != NULL);

	if (!ret)
		*error_r = t_strdup_printf("Cannot load JWK public key: %s", error);
	else {
		*key_r = i_new(struct dcrypt_public_key, 1);
		(*key_r)->key = pkey;
		(*key_r)->ref++;
		/* check if kid is present */
		if ((node = json_tree_find_key(root, "kid")) != NULL)
			(*key_r)->key_id = i_strdup_empty(json_tree_get_value_str(node));
		/* check if use is present */
		if ((node = json_tree_find_key(root, "use")) != NULL)
			(*key_r)->usage = jwk_use_to_key_usage(json_tree_get_value_str(node));
	}

	json_tree_deinit(&key_tree);

	return ret;
}


static int bn2base64url(const BIGNUM *bn, string_t *dest)
{
	int len = BN_num_bytes(bn);
	unsigned char data[len];
	if (BN_bn2bin(bn, data) != len)
		return -1;
	base64url_encode(BASE64_ENCODE_FLAG_NO_PADDING, SIZE_MAX, data, len, dest);
	return 0;
}

/* FIXME: Add encryption support */
/* FIXME: Add support for 'algo' field */
static bool store_jwk_ec_key(EVP_PKEY *pkey, bool is_private_key,
			     enum dcrypt_key_usage usage,
			     const char *key_id,
			     const char *cipher ATTR_UNUSED,
			     const char *password ATTR_UNUSED,
			     struct dcrypt_public_key *enc_key ATTR_UNUSED,
			     string_t *dest, const char **error_r)
{
	i_assert(cipher == NULL && password == NULL && enc_key == NULL);

	BIGNUM *x = NULL, *y = NULL;
	if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &x) != 1 ||
	    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &y) != 1)
		i_unreached();

	char int_curve[128];
	size_t ncurve;
	if (EVP_PKEY_get_group_name(pkey, int_curve, sizeof(int_curve), &ncurve) != 1)
		i_unreached();
	int_curve[ncurve] = '\0';

	int nid = OBJ_txt2nid(int_curve);
	const char *curve = nid_to_jwk_curve(nid);
	const char *use = key_usage_to_jwk_use(usage);
	string_t *temp = t_str_new(256);

	str_printfa(temp, "{\"kty\":\"EC\",\"crv\":\"%s\"", curve);
	str_append(temp, ",\"x\":\"");
	bn2base64url(x, temp);
	str_append(temp, "\",\"y\":\"");
	bn2base64url(y, temp);

	if (use != NULL) {
		str_append(temp, "\",\"use\":\"");
		json_append_escaped(temp, use);
	}
	if (key_id != NULL) {
		str_append(temp, "\",\"kid\":\"");
		json_append_escaped(temp, key_id);
	}
	BN_free(x);
	BN_free(y);

	if (is_private_key) {
		BIGNUM *d = NULL;
		EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &d);
		if (d == NULL) {
			*error_r = "No private key available";
			return FALSE;
		}
		str_append(temp, "\",\"d\":\"");
		bn2base64url(d, temp);
		BN_free(d);
	}
	str_append(temp, "\"}");
	str_append_str(dest, temp);
	return TRUE;
}

/* FIXME: Add RSA support */

static bool store_jwk_key(EVP_PKEY *pkey, bool is_private_key,
			  enum dcrypt_key_usage usage,
			  const char *key_id,
			  const char *cipher,
			  const char *password,
			  struct dcrypt_public_key *enc_key,
			  string_t *dest, const char **error_r)
{
	i_assert(cipher == NULL && password == NULL && enc_key == NULL);
	if (EVP_PKEY_base_id(pkey) == EVP_PKEY_EC) {
		return store_jwk_ec_key(pkey, is_private_key, usage, key_id,
					cipher, password, enc_key, dest, error_r);
	}
	*error_r = "Unsupported key type";
	return FALSE;
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
		*error_r = "Corrupted data";
		return FALSE;
	}

	EC_GROUP *g = EC_GROUP_new_by_curve_name(nid);
	BN_CTX *bnctx = BN_CTX_new();
	if (bnctx == NULL)
		dcrypt_openssl_error(error_r);
	EC_POINT *point = EC_POINT_new(g);
	if (point == NULL)
		 dcrypt_openssl_error(error_r);

	if (EC_POINT_hex2point(g, input[2], point, bnctx) == NULL) {
		BN_CTX_free(bnctx);
		EC_POINT_free(point);
		EC_GROUP_free(g);
		dcrypt_openssl_error(error_r);
		return FALSE;
	}
	BN_CTX_free(bnctx);

	EVP_PKEY *pkey;
	if (!dcrypt_evp_pkey_from_point(nid, point, &pkey, error_r)) {
		EC_POINT_free(point);
		EC_GROUP_free(g);
		return FALSE;
	}
	EC_POINT_free(point);
	EC_GROUP_free(g);

	/* make sure digest matches */
	buffer_t *dgst = t_buffer_create(32);
	struct dcrypt_public_key tmp;
	i_zero(&tmp);
	tmp.key = pkey;
	if (!dcrypt_openssl_public_key_id_old(&tmp, dgst, error_r)) {
		EVP_PKEY_free(pkey);
		return FALSE;
	}

	if (strcmp(binary_to_hex(dgst->data, dgst->used),
		   input[len-1]) != 0) {
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
dcrypt_openssl_load_public_key_dovecot_v2(struct dcrypt_public_key **key_r,
					  int len, const char **input,
					  const char **error_r)
{
	buffer_t tmp;
	size_t keylen = strlen(input[1])/2;
	unsigned char keybuf[keylen+1];
	buffer_create_from_data(&tmp, keybuf, keylen);
	hex_to_binary(input[1], &tmp);
	const unsigned char *ptr = tmp.data;

	EVP_PKEY *pkey = NULL;
	if (d2i_PUBKEY(&pkey, &ptr, tmp.used) == NULL) {
		EVP_PKEY_free(pkey);
		dcrypt_openssl_error(error_r);
		return FALSE;
	}

	/* make sure digest matches */
	buffer_t *dgst = t_buffer_create(32);
	struct dcrypt_public_key tmpkey = {
		.key = pkey
	};
	if (!dcrypt_openssl_public_key_id(&tmpkey, "sha256", dgst, error_r)) {
		EVP_PKEY_free(pkey);
		return FALSE;
	}
	if (strcmp(binary_to_hex(dgst->data, dgst->used), input[len-1]) != 0) {
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
	case DCRYPT_KEY_VERSION_2:
		return dcrypt_openssl_load_public_key_dovecot_v2(
			key_r, len, input, error_r);
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
						DCRYPT_PADDING_RSA_PKCS1_OAEP,
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
		obj = OBJ_nid2obj(dcrypt_EVP_PKEY_get_nid(pkey));
	} else {
		obj = OBJ_nid2obj(EVP_PKEY_id(pkey));
	}

	int enctype = DCRYPT_KEY_ENCRYPTION_TYPE_NONE;
	int len = OBJ_obj2txt(objtxt, sizeof(objtxt), obj, 1);
	if (len < 1)
		return dcrypt_openssl_error(error_r);
	if (len > (int)sizeof(objtxt)) {
		*error_r = "Object identifier too long";
		return FALSE;
	}

	buffer_t *buf = t_buffer_create(256);

	/* convert key to private key value */
	if (EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA) {
		unsigned char *ptr;
		int len = i2d_PrivateKey(pkey, &ptr);
		if (len < 1)
			return dcrypt_openssl_error(error_r);
		buffer_append(buf, ptr, len);
	} else if (EVP_PKEY_base_id(pkey) == EVP_PKEY_EC) {
		unsigned char *ptr;
		BIGNUM *pk = NULL;
		if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &pk) < 1) {
			*error_r = "Private key not available";
			return FALSE;
		}
		/* serialize to MPI which is portable */
		int len = BN_bn2mpi(pk, NULL);
		ptr = buffer_append_space_unsafe(buf, len);
		BN_bn2mpi(pk, ptr);
		BN_free(pk);
	} else {
		/* Loading the key should have failed */
		i_unreached();
	}

	/* see if we want ECDH based or password based encryption */
	if (cipher != NULL && str_begins_icase(cipher, "ecdh-", &cipher2)) {
		i_assert(enc_key != NULL);
		i_assert(password == NULL);
		enctype = DCRYPT_DOVECOT_KEY_ENCRYPT_PK;
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
				&kind, NULL, NULL, NULL, error_r))
		return FALSE;
	if (kind != DCRYPT_KEY_KIND_PRIVATE) {
		*error_r = "key is not private";
		return FALSE;
	}

	if (format == DCRYPT_FORMAT_JWK) {
		bool ret;
		T_BEGIN {
			ret = dcrypt_openssl_load_private_key_jwk(key_r, data, password,
								  dec_key, error_r);
		} T_END_PASS_STR_IF(!ret, error_r);
		return ret;
	}

	if (format == DCRYPT_FORMAT_DOVECOT) {
		bool ret;
		T_BEGIN {
			ret = dcrypt_openssl_load_private_key_dovecot(key_r, data,
					password, dec_key, version, error_r);
		} T_END_PASS_STR_IF(!ret, error_r);
		return ret;
	}

	EVP_PKEY *key = NULL, *key2;
	BIO *key_in = BIO_new_mem_buf((void*)data, strlen(data));
	key = EVP_PKEY_new();
	key2 = PEM_read_bio_PrivateKey(key_in, &key, NULL, (void*)password);
	BIO_vfree(key_in);

	if (key2 == NULL) {
		EVP_PKEY_free(key);
		return dcrypt_openssl_error(error_r);
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
						error_r))
		return FALSE;
	/* JWK private keys can be loaded as public */
	if (kind != DCRYPT_KEY_KIND_PUBLIC && format != DCRYPT_FORMAT_JWK) {
		*error_r = "key is not public";
		return FALSE;
	}

	if (format == DCRYPT_FORMAT_JWK) {
		bool ret;
		T_BEGIN {
			ret = dcrypt_openssl_load_public_key_jwk(key_r, data, error_r);
		} T_END_PASS_STR_IF(!ret, error_r);
		return ret;
	}
	if (format == DCRYPT_FORMAT_DOVECOT) {
		bool ret;
		T_BEGIN {
			ret = dcrypt_openssl_load_public_key_dovecot(key_r, data,
								     version, error_r);
		} T_END_PASS_STR_IF(!ret, error_r);
		return ret;
	}

	EVP_PKEY *key = NULL;
	BIO *key_in = BIO_new_mem_buf((void*)data, strlen(data));
	if (key_in == NULL)
		return dcrypt_openssl_error(error_r);

	key = PEM_read_bio_PUBKEY(key_in, &key, NULL, NULL);
	if (BIO_reset(key_in) <= 0)
		i_unreached();

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
		return dcrypt_openssl_store_private_key_dovecot(key, cipher, destination,
								password, enc_key, error_r);
	}
	EVP_PKEY *pkey = key->key;

	if (format == DCRYPT_FORMAT_JWK) {
		return store_jwk_key(pkey, TRUE, key->usage, key->key_id,
				     cipher, password, enc_key,
				     destination, error_r);
	}


	BIO *key_out = BIO_new(BIO_s_mem());
	if (key_out == NULL)
		return dcrypt_openssl_error(error_r);

	const EVP_CIPHER *algo = NULL;
	if (cipher != NULL) {
		algo = EVP_get_cipherbyname(cipher);
		if (algo == NULL) {
			*error_r = t_strdup_printf("Invalid cipher %s", cipher);
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

	if (format == DCRYPT_FORMAT_JWK) {
		bool ret;
		ret = store_jwk_key(pkey, FALSE, key->usage, key->key_id,
				    NULL, NULL, NULL,
				    destination, error_r);
		return ret;
	}

	BIO *key_out = BIO_new(BIO_s_mem());
	if (key_out == NULL)
		return dcrypt_openssl_error(error_r);

	ec = PEM_write_bio_PUBKEY(key_out, pkey);

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

	OSSL_PARAM *params = NULL;
	EVP_PKEY_todata(pkey, EVP_PKEY_PUBLIC_KEY, &params);
	/* keep the key format compressed */
	OSSL_PARAM *param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT);
	OSSL_PARAM_set_utf8_string(param, "compressed");
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
	if (EVP_PKEY_fromdata_init(ctx) < 1 ||
	    EVP_PKEY_fromdata(ctx, &pk, EVP_PKEY_PUBLIC_KEY, params) < 1) {
		i_unreached();
	}
	EVP_PKEY_CTX_free(ctx);
	OSSL_PARAM_free(params);

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
	if (str_begins(key_data, "-----BEGIN ", &key_data)) {
		format = DCRYPT_FORMAT_PEM;
		version = DCRYPT_KEY_VERSION_NA;
		if (str_begins_with(key_data, "RSA ")) {
			*error_r = "RSA private key format not supported, convert it to PKEY format with openssl pkey";
			return FALSE;
		}
		if (str_begins(key_data, "ENCRYPTED ", &key_data))
			encryption_type = DCRYPT_KEY_ENCRYPTION_TYPE_PASSWORD;
		if (str_begins_with(key_data, "PRIVATE KEY-----"))
			kind = DCRYPT_KEY_KIND_PRIVATE;
		else if (str_begins_with(key_data, "PUBLIC KEY-----"))
			kind = DCRYPT_KEY_KIND_PUBLIC;
		else {
			*error_r = "Unknown/invalid PEM key type";
			return FALSE;
		}
	} else if (*key_data == '{') {
		/* possibly a JWK key */
		format = DCRYPT_FORMAT_JWK;
		version = DCRYPT_KEY_VERSION_NA;
		struct json_tree *tree;
		const struct json_tree_node *root, *node;
		const char *value, *error;
		if (parse_jwk_key(key_data, &tree, &error) != 0) {
			*error_r = "Unknown/invalid key data";
			return FALSE;
		}

		/* determine key type */
		root = json_tree_root(tree);
		if ((node = json_tree_find_key(root, "kty")) == NULL ||
		    (value = json_tree_get_value_str(node)) == NULL) {
			json_tree_deinit(&tree);
			*error_r = "Invalid JWK key: Missing kty parameter";
			return FALSE;
		} else if (strcmp(value, "RSA") == 0) {
			if (json_tree_find_key(root, "d") != NULL)
				kind = DCRYPT_KEY_KIND_PRIVATE;
			else
				kind = DCRYPT_KEY_KIND_PUBLIC;
		} else if (strcmp(value, "EC") == 0) {
			if (json_tree_find_key(root, "d") != NULL)
				kind = DCRYPT_KEY_KIND_PRIVATE;
			else
				kind = DCRYPT_KEY_KIND_PUBLIC;
		} else {
			json_tree_deinit(&tree);
			*error_r = "Unsupported JWK key type";
			return FALSE;
		}
		json_tree_deinit(&tree);
	} else {
		if (str_begins_with(key_data, "1:")) {
			*error_r = "Dovecot v1 key format uses tab to separate fields";
			return FALSE;
		} else if (str_begins_with(key_data, "2\t")) {
			*error_r = "Dovecot v2 key format uses colon to separate fields";
			return FALSE;
		}
		const char **fields = t_strsplit(key_data, ":\t");
		int nfields = str_array_length(fields);

		if (nfields < 2) {
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
				*error_r = "Invalid dovecot v2 encoding";
				return FALSE;
			}
		} else {
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
	i_assert(key != NULL);
	struct dcrypt_public_key *_key = *key;
	if (_key == NULL)
		return;
	i_assert(_key->ref > 0);
	*key = NULL;
	if (--_key->ref > 0) return;
	EVP_PKEY_free(_key->key);
	i_free(_key->key_id);
	i_free(_key);
}

static void dcrypt_openssl_unref_private_key(struct dcrypt_private_key **key)
{
	i_assert(key != NULL);
	struct dcrypt_private_key *_key = *key;
	if (_key == NULL)
		return;
	i_assert(_key->ref > 0);
	*key = NULL;
	if (--_key->ref > 0) return;
	EVP_PKEY_free(_key->key);
	i_free(_key->key_id);
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
			   buffer_t *result, enum dcrypt_padding padding,
			   const char **error_r)
{
	i_assert(key != NULL && key->key != NULL);
	int ec, pad = dcrypt_openssl_padding_mode(padding, FALSE, error_r);
	if (pad == -1)
		return FALSE;
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key->key, NULL);
	size_t outl = EVP_PKEY_size(key->key);
	unsigned char buf[outl];

	if (ctx == NULL ||
	    EVP_PKEY_encrypt_init(ctx) < 1 ||
	    EVP_PKEY_CTX_set_rsa_padding(ctx, pad) < 1 ||
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
			   buffer_t *result, enum dcrypt_padding padding,
			   const char **error_r)
{
	i_assert(key != NULL && key->key != NULL);
	int ec, pad = dcrypt_openssl_padding_mode(padding, FALSE, error_r);
	if (pad == -1)
		return FALSE;
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key->key, NULL);
	size_t outl = EVP_PKEY_size(key->key);
	unsigned char buf[outl];

	if (ctx == NULL ||
	    EVP_PKEY_decrypt_init(ctx) < 1 ||
	    EVP_PKEY_CTX_set_rsa_padding(ctx, pad) < 1 ||
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
	if (len == 0) {
		*error_r = "Object has no OID assigned";
		return FALSE;
	}
	len = i2d_ASN1_OBJECT(obj, NULL);
	unsigned char *bufptr = buffer_append_space_unsafe(oid, len);
	i2d_ASN1_OBJECT(obj, &bufptr);
	ASN1_OBJECT_free(obj);
	if (bufptr == NULL)
		return dcrypt_openssl_error(error_r);
	return TRUE;
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
		*error_r = "Only EC key supported";
		return FALSE;
	}

	const char *pub_pt_hex = ec_key_get_pub_point_hex(pub);
	if (pub_pt_hex == NULL)
		return dcrypt_openssl_error(error_r);
	/* digest this */
	SHA256((const void*)pub_pt_hex, strlen(pub_pt_hex), buf);
	buffer_append(result, buf, SHA256_DIGEST_LENGTH);
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
		*error_r = "Only EC key supported";
		return FALSE;
	}

	const char *pub_pt_hex = ec_key_get_pub_point_hex(priv);
	if (pub_pt_hex == NULL)
		return dcrypt_openssl_error(error_r);
	/* digest this */
	SHA256((const void*)pub_pt_hex, strlen(pub_pt_hex), buf);
	buffer_append(result, buf, SHA256_DIGEST_LENGTH);
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
	EVP_PKEY_set_utf8_string_param(key, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, "compressed");
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
		*error_r = t_strdup_printf("Unknown cipher %s", algorithm);
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
		*error_r = t_strdup_printf("Unknown cipher %s", algorithm);
		return FALSE;
	}

	return dcrypt_openssl_public_key_id_evp(priv, md, result, error_r);
}

static void dcrypt_x962_remove_der(buffer_t *signature_r)
{
	const unsigned char *data = signature_r->data;
	size_t sig_len = signature_r->used;
	buffer_t *new_sig = t_buffer_create(sig_len);

	i_assert(data[0] == 0x30 && data[1] < sig_len);
	i_assert(data[2] == 0x2);
	size_t offset_r = 2;
	size_t len_r = data[offset_r + 1];
	offset_r += 2;
	size_t offset_s = 3 + len_r + 1;
	size_t len_s = data[offset_s + 1];
	offset_s += 2;
	if (len_r < len_s)
		buffer_append_c(new_sig, 0x0);
	buffer_append(new_sig, data + offset_r, len_r);
	if (len_s < len_r)
		buffer_append_c(new_sig, 0x0);
	buffer_append(new_sig, data + offset_s, len_s);
	buffer_set_used_size(signature_r, 0);
	buffer_append_buf(signature_r, new_sig, 0, new_sig->used);
}

static bool dcrypt_x962_add_der(buffer_t *signature_r)
{
	const unsigned char *p = signature_r->data;
	size_t len = signature_r->used;
	size_t split = len/2;
	BIGNUM *bn_r = BN_new();
	BIGNUM *bn_s = BN_new();
	if (BN_bin2bn(p, split, bn_r) == NULL ||
	    BN_bin2bn(p+split, split, bn_s) == NULL) {
		BN_free(bn_r);
		BN_free(bn_s);
		return FALSE;
	}
	ASN1_SEQUENCE_ANY *seq = sk_ASN1_TYPE_new_null();
	sk_ASN1_TYPE_reserve(seq, 2);
	ASN1_INTEGER *ai_r = BN_to_ASN1_INTEGER(bn_r, NULL);
	ASN1_INTEGER *ai_s = BN_to_ASN1_INTEGER(bn_s, NULL);
	ASN1_TYPE *t_r = ASN1_TYPE_pack_sequence(ASN1_INTEGER_it(), ai_s, NULL);
	sk_ASN1_TYPE_unshift(seq, t_r);
	ASN1_TYPE *t_s = ASN1_TYPE_pack_sequence(ASN1_INTEGER_it(), ai_r, NULL);
	sk_ASN1_TYPE_unshift(seq, t_s);
	unsigned char *ptr = NULL;
	len = i2d_ASN1_SEQUENCE_ANY(seq, &ptr);
	buffer_set_used_size(signature_r, 0);
	buffer_append(signature_r, ptr, len);
	OPENSSL_free(ptr);
	sk_ASN1_TYPE_free(seq);
	ASN1_INTEGER_free(ai_r);
	ASN1_INTEGER_free(ai_s);
	ASN1_TYPE_free(t_r);
	ASN1_TYPE_free(t_s);
	BN_free(bn_r);
	BN_free(bn_s);
	return TRUE;
}

static bool
dcrypt_openssl_sign(struct dcrypt_private_key *key, const char *algorithm,
		    enum dcrypt_signature_format format,
		    const void *data, size_t data_len, buffer_t *signature_r,
		    enum dcrypt_padding padding, const char **error_r)
{
	switch (format) {
	case DCRYPT_SIGNATURE_FORMAT_DSS:
		break;
	case DCRYPT_SIGNATURE_FORMAT_X962:
		if (EVP_PKEY_base_id(key->key) == EVP_PKEY_RSA) {
			*error_r = "Format does not support RSA";
			return FALSE;
		}
		break;
	default:
		i_unreached();
	}

	bool ret;
	const EVP_MD *md = EVP_get_digestbyname(algorithm);
	size_t siglen;
	int pad = dcrypt_openssl_padding_mode(padding, TRUE, error_r);

	if (pad == -1)
		return FALSE;

	if (md == NULL) {
		*error_r = t_strdup_printf("Unknown digest %s", algorithm);
		return FALSE;
	}

	EVP_MD_CTX *dctx = EVP_MD_CTX_create();
	/* do not preallocate - will cause memory leak */
	EVP_PKEY_CTX *pctx = NULL;

	/* NB! Padding is set only on RSA signatures
	   ECDSA signatures use whatever is default */
	if (EVP_DigestSignInit_ex(dctx, &pctx, algorithm, NULL, NULL, key->key, NULL) != 1 ||
	    (EVP_PKEY_base_id(key->key) == EVP_PKEY_RSA &&
	     EVP_PKEY_CTX_set_rsa_padding(pctx, pad) != 1) ||
	    EVP_DigestSignUpdate(dctx, data, data_len) != 1 ||
	    EVP_DigestSignFinal(dctx, NULL, &siglen) != 1) {
		ret = dcrypt_openssl_error(error_r);
	} else {
		i_assert(siglen > 0);
		/* @UNSAFE */
		unsigned char *buf =
			buffer_append_space_unsafe(signature_r, siglen);
		if (EVP_DigestSignFinal(dctx, buf, &siglen) != 1) {
			ret = dcrypt_openssl_error(error_r);
		} else {
			buffer_set_used_size(signature_r, siglen);
			ret = TRUE;
			if (format == DCRYPT_SIGNATURE_FORMAT_X962) {
				/* remove der container */
				dcrypt_x962_remove_der(signature_r);
			}
		}
	}

	EVP_MD_CTX_free(dctx);

	return ret;
}

static bool
dcrypt_openssl_verify(struct dcrypt_public_key *key, const char *algorithm,
		      enum dcrypt_signature_format format,
		      const void *data, size_t data_len,
		      const unsigned char *signature, size_t signature_len,
		      bool *valid_r, enum dcrypt_padding padding,
		      const char **error_r)
{
	switch (format) {
	case DCRYPT_SIGNATURE_FORMAT_DSS:
		break;
	case DCRYPT_SIGNATURE_FORMAT_X962:
		if (EVP_PKEY_base_id(key->key) == EVP_PKEY_RSA) {
			*error_r = "Format does not support RSA";
			return FALSE;
		}
		if ((signature_len % 2) != 0) {
			*error_r = "Invalid x9.62 signature";
			return FALSE;
		}
		buffer_t *new_sig = t_buffer_create(signature_len);
		buffer_append(new_sig, signature, signature_len);
		if (dcrypt_x962_add_der(new_sig) == FALSE) {
			*error_r = "Invalid x9.62 signature";
			return FALSE;
		}
		signature_len = new_sig->used;
		signature = buffer_free_without_data(&new_sig);
		break;
	default:
		i_unreached();
	}

	bool ret;
	int rc, pad = dcrypt_openssl_padding_mode(padding, TRUE, error_r);

	if (pad == -1)
		return FALSE;

	EVP_MD_CTX *dctx = EVP_MD_CTX_create();
	/* do not preallocate, causes memory leak */
	EVP_PKEY_CTX *pctx = NULL;

	/* NB! Padding is set only on RSA signatures
	   ECDSA signatures use whatever is default */
	if (EVP_DigestVerifyInit_ex(dctx, &pctx, algorithm, NULL, NULL, key->key, NULL) != 1 ||
	    (EVP_PKEY_base_id(key->key) == EVP_PKEY_RSA &&
	     EVP_PKEY_CTX_set_rsa_padding(pctx, pad) != 1) ||
	    EVP_DigestVerifyUpdate(dctx, data, data_len) != 1 ||
	    (rc = EVP_DigestVerifyFinal(dctx, signature, signature_len)) < 0) {
		ret = dcrypt_openssl_error(error_r);
	} else {
		/* return code 1 means valid signature, otherwise invalid */
		*valid_r = (rc == 1);
		ret = TRUE;
	}

	EVP_MD_CTX_free(dctx);

	return ret;
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
	EVP_PKEY *pkey = key->key;
	ARRAY_TYPE(dcrypt_raw_key) keys;
	t_array_init(&keys, 2);

	if (EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA) {
		*error_r = "Key type unsupported";
		return FALSE;
	} else if (EVP_PKEY_base_id(pkey) == EVP_PKEY_EC) {
		*type_r = DCRYPT_KEY_EC;
	} else {
		*error_r = "Key type unsupported";
		return FALSE;
	}

	struct dcrypt_raw_key *item = array_append_space(&keys);
	unsigned char *ptr = NULL;
	int nid = dcrypt_EVP_PKEY_get_nid(pkey);
	ASN1_OBJECT *obj = OBJ_nid2obj(nid);
	int len = i2d_ASN1_OBJECT(obj, &ptr);
	if (len < 1)
		return dcrypt_openssl_error(error_r);
	item->len = len;
	item->parameter = p_memdup(pool, ptr, len);
	OPENSSL_free(ptr);

	item = array_append_space(&keys);
	BIGNUM *bn = NULL;
	if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &bn) != 1) {
		*error_r = "Private key not available";
		return FALSE;
	}
	len = BN_num_bytes(bn);
	item->len = len;
	item->parameter = p_malloc(pool, len);
	BN_bn2lebinpad(bn, (void*)item->parameter, len);
	BN_free(bn);

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
		*error_r = "Key type unsupported";
		return FALSE;
	} else if (EVP_PKEY_base_id(pub) == EVP_PKEY_EC) {
		*type_r = DCRYPT_KEY_EC;
	} else {
		*error_r = "Key type unsupported";
		return FALSE;
	}

	struct dcrypt_raw_key *item = array_append_space(&keys);
	unsigned char *ptr = NULL;
	int nid = dcrypt_EVP_PKEY_get_nid(pub);
	ASN1_OBJECT *obj = OBJ_nid2obj(nid);
	int len = i2d_ASN1_OBJECT(obj, &ptr);
	if (len < 1)
		return dcrypt_openssl_error(error_r);
	item->len = len;
	item->parameter = p_memdup(pool, ptr, len);
	OPENSSL_free(ptr);

	ptr = NULL;
	item = array_append_space(&keys);
	size_t len2;
	if (EVP_PKEY_get_octet_string_param(pub, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &len2) < 0)
		return dcrypt_openssl_error(error_r);
	item->len = len2;
	item->parameter = p_malloc(pool, len2);
	if (EVP_PKEY_get_octet_string_param(pub, OSSL_PKEY_PARAM_PUB_KEY, (void*)item->parameter, len2, &len2) < 0)
		return dcrypt_openssl_error(error_r);
	array_append_array(keys_r, &keys);

	return TRUE;
}

static bool
dcrypt_openssl_key_load_private_raw(struct dcrypt_private_key **key_r,
				    enum dcrypt_key_type type,
				    const ARRAY_TYPE(dcrypt_raw_key) *keys,
				    const char **error_r)
{
	i_assert(keys != NULL && array_is_created(keys) && array_count(keys) > 1);

	if (type == DCRYPT_KEY_RSA) {
		*error_r = "Key type unsupported";
	} else if (type == DCRYPT_KEY_EC) {
		const struct dcrypt_raw_key *item = array_front(keys);
		const unsigned char *ptr = item->parameter;
		/* get nid */
		ASN1_OBJECT *obj = NULL;
		if (d2i_ASN1_OBJECT(&obj, &ptr, item->len) == NULL)
			return dcrypt_openssl_error(error_r);
		int nid = OBJ_obj2nid(obj);
		ASN1_OBJECT_free(obj);

		item = array_idx(keys, 1);
		BIGNUM *point = BN_secure_new();
		if (BN_bin2bn(item->parameter, item->len, point) == NULL) {
			BN_free(point);
			return dcrypt_openssl_error(error_r);
		}

		EVP_PKEY *pkey;
		if (!dcrypt_evp_pkey_from_bn(nid, point, &pkey, error_r)) {
			BN_free(point);
			return FALSE;
		}

		BN_free(point);
		*key_r = i_new(struct dcrypt_private_key, 1);
		(*key_r)->key = pkey;
		(*key_r)->ref++;
		return TRUE;
	} else {
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
	i_assert(keys != NULL && array_is_created(keys) && array_count(keys) > 1);

	if (type == DCRYPT_KEY_RSA) {
		*error_r = "Key type unsupported";
	} else if (type == DCRYPT_KEY_EC) {
		const struct dcrypt_raw_key *item = array_front(keys);
		const unsigned char *ptr = item->parameter;
		/* get nid */
		ASN1_OBJECT *obj = NULL;
		if (d2i_ASN1_OBJECT(&obj, &ptr, item->len) == NULL)
			return dcrypt_openssl_error(error_r);
		int nid = OBJ_obj2nid(obj);
		const char *g = OBJ_nid2sn(nid);
		ASN1_OBJECT_free(obj);

		item = array_idx(keys, 1);

		/* create OSSL PARAMS */
		OSSL_PARAM params[5];
		params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char*)g, 0);
		params[1] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, "named_curve", 0);
		params[2] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, "compressed", 0);
		params[3] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void*)item->parameter, item->len);
		params[4] = OSSL_PARAM_construct_end();

		EVP_PKEY_CTX *ctx =
		    EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
		EVP_PKEY *pkey = EVP_PKEY_new();

		int ec;
		if ((ec = EVP_PKEY_fromdata_init(ctx)) != 1 ||
		    (ec = EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params)) != 1) {
			/* pass */
		}

		EVP_PKEY_CTX_free(ctx);

		if (ec != 1) {
			EVP_PKEY_free(pkey);
			return dcrypt_openssl_error(error_r);
		}

		*key_r = i_new(struct dcrypt_public_key, 1);
		(*key_r)->key = pkey;
		(*key_r)->ref++;
		return TRUE;
	} else {
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

	ASN1_OBJECT *obj = OBJ_nid2obj(dcrypt_EVP_PKEY_get_nid(pkey));

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

static const char *
dcrypt_openssl_key_get_id_public(struct dcrypt_public_key *key)
{
	i_assert(key != NULL);
	return key->key_id;
}

static const char *
dcrypt_openssl_key_get_id_private(struct dcrypt_private_key *key)
{
	i_assert(key != NULL);
	return key->key_id;
}

static void
dcrypt_openssl_key_set_id_public(struct dcrypt_public_key *key, const char *id)
{
	i_assert(key != NULL);
	i_free(key->key_id);
	key->key_id = i_strdup_empty(id);
}

static void
dcrypt_openssl_key_set_id_private(struct dcrypt_private_key *key, const char *id)
{
	i_assert(key != NULL);
	i_free(key->key_id);
	key->key_id = i_strdup_empty(id);
}

static enum dcrypt_key_usage
dcrypt_openssl_key_get_usage_public(struct dcrypt_public_key *key)
{
	i_assert(key != NULL);
	return key->usage;
}

static enum dcrypt_key_usage
dcrypt_openssl_key_get_usage_private(struct dcrypt_private_key *key)
{
	i_assert(key != NULL);
	return key->usage;
}

static void
dcrypt_openssl_key_set_usage_public(struct dcrypt_public_key *key,
				    enum dcrypt_key_usage usage)
{
	i_assert(key != NULL);
	key->usage = usage;
}

static void
dcrypt_openssl_key_set_usage_private(struct dcrypt_private_key *key,
				     enum dcrypt_key_usage usage)
{
	i_assert(key != NULL);
	key->usage = usage;
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
	.key_get_id_public = dcrypt_openssl_key_get_id_public,
	.key_get_id_private = dcrypt_openssl_key_get_id_private,
	.key_set_id_public = dcrypt_openssl_key_set_id_public,
	.key_set_id_private = dcrypt_openssl_key_set_id_private,
	.key_get_usage_public = dcrypt_openssl_key_get_usage_public,
	.key_get_usage_private = dcrypt_openssl_key_get_usage_private,
	.key_set_usage_public = dcrypt_openssl_key_set_usage_public,
	.key_set_usage_private = dcrypt_openssl_key_set_usage_private,
	.sign = dcrypt_openssl_sign,
	.verify = dcrypt_openssl_verify,
	.ecdh_derive_secret = dcrypt_openssl_ecdh_derive_secret,
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

#endif
