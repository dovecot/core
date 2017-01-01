/* Copyright (c) 2016-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "randgen.h"
#include "array.h"
#include "hash-method.h"
#include "pkcs5.h"
#include "module-dir.h"
#include <gnutls/gnutls.h>
#include <gnutls/compat.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>
#include <nettle/version.h>
#include <nettle/hmac.h>
#include <nettle/pbkdf2.h>
#include <nettle/ecc.h>

#include "dcrypt.h"
#include "dcrypt-private.h"

struct dcrypt_context_symmetric {
	pool_t pool;
	gnutls_cipher_hd_t ctx;
	gnutls_cipher_algorithm_t cipher;
	gnutls_datum_t key;
	gnutls_datum_t iv;
	enum dcrypt_sym_mode mode;
};

struct dcrypt_context_hmac {
	pool_t pool;
	gnutls_hmac_hd_t ctx;
	gnutls_mac_algorithm_t md;
	gnutls_datum_t key;
	size_t klen;
};

struct dcrypt_public_key {
	void *ctx;
};

struct dcrypt_private_key {
	void *ctx;
};

static
int dcrypt_gnutls_private_to_public_key(struct dcrypt_private_key *priv_key, struct dcrypt_public_key **pub_key_r, const char **error_r);

static
int dcrypt_gnutls_error(int ec, const char **error_r)
{
	i_assert(ec < 0);
	if(error_r != NULL) {
		*error_r = gnutls_strerror(ec);
	}
	return -1;
}

static
int dcrypt_gnutls_ctx_sym_create(const char *algorithm, enum dcrypt_sym_mode mode, struct dcrypt_context_symmetric **ctx_r, const char **error_r)
{
	gnutls_cipher_algorithm_t cipher = gnutls_cipher_get_id(algorithm);
	if(cipher == GNUTLS_CIPHER_UNKNOWN) return dcrypt_gnutls_error(cipher, error_r);
	pool_t pool = pool_alloconly_create("dcrypt gnutls", 128);
	struct dcrypt_context_symmetric *ctx = p_new(pool, struct dcrypt_context_symmetric, 1);
	ctx->pool = pool;
	ctx->cipher = cipher;
	ctx->mode = mode;
	*ctx_r = ctx;
	return 0;
}

static
int dcrypt_gnutls_ctx_sym_destroy(struct dcrypt_context_symmetric **ctx)
{
	pool_t pool =(*ctx)->pool;
	gnutls_cipher_deinit((*ctx)->ctx);
	pool_unref(&pool);
	*ctx = NULL;
	return 0;
}

static
void dcrypt_gnutls_ctx_sym_set_key(struct dcrypt_context_symmetric *ctx, const unsigned char *key, size_t key_len)
{
	if(ctx->key.data != NULL) p_free(ctx->pool, ctx->key.data);
	ctx->key.size = I_MIN(key_len,(size_t)gnutls_cipher_get_key_size(ctx->cipher));
	ctx->key.data = p_malloc(ctx->pool, ctx->key.size);
	memcpy(ctx->key.data, key, ctx->key.size);
}

static
void dcrypt_gnutls_ctx_sym_set_iv(struct dcrypt_context_symmetric *ctx, const unsigned char *iv, size_t iv_len)
{
	if(ctx->iv.data != NULL) p_free(ctx->pool, ctx->iv.data);
	ctx->iv.size = I_MIN(iv_len,(size_t)gnutls_cipher_get_iv_size(ctx->cipher));
	ctx->iv.data = p_malloc(ctx->pool, ctx->iv.size);
	memcpy(ctx->iv.data, iv, ctx->iv.size);
}

static
void dcrypt_gnutls_ctx_sym_set_key_iv_random(struct dcrypt_context_symmetric *ctx)
{
	if(ctx->key.data != NULL) p_free(ctx->pool, ctx->key.data);
	if(ctx->iv.data != NULL) p_free(ctx->pool, ctx->iv.data);
	ctx->key.data = p_malloc(ctx->pool, gnutls_cipher_get_key_size(ctx->cipher));
	random_fill(ctx->key.data, gnutls_cipher_get_key_size(ctx->cipher));
	ctx->key.size = gnutls_cipher_get_key_size(ctx->cipher);
	ctx->iv.data = p_malloc(ctx->pool, gnutls_cipher_get_iv_size(ctx->cipher));
	random_fill(ctx->iv.data, gnutls_cipher_get_iv_size(ctx->cipher));
	ctx->iv.size = gnutls_cipher_get_iv_size(ctx->cipher);
}

static
int dcrypt_gnutls_ctx_sym_get_key(struct dcrypt_context_symmetric *ctx, buffer_t *key)
{
	if(ctx->key.data == NULL) return -1;
	buffer_append(key, ctx->key.data, ctx->key.size);
	return 0;
}
static
int dcrypt_gnutls_ctx_sym_get_iv(struct dcrypt_context_symmetric *ctx, buffer_t *iv)
{
	if(ctx->iv.data == NULL) return -1;
	buffer_append(iv, ctx->iv.data, ctx->iv.size);
	return 0;
}

static
int dcrypt_gnutls_ctx_sym_get_key_length(struct dcrypt_context_symmetric *ctx)
{
	return gnutls_cipher_get_iv_size(ctx->cipher);
}
static
int dcrypt_gnutls_ctx_sym_get_iv_length(struct dcrypt_context_symmetric *ctx)
{
	return gnutls_cipher_get_iv_size(ctx->cipher);
}
static
int dcrypt_gnutls_ctx_sym_get_block_size(struct dcrypt_context_symmetric *ctx)
{
	return gnutls_cipher_get_block_size(ctx->cipher);
}

static
int dcrypt_gnutls_ctx_sym_init(struct dcrypt_context_symmetric *ctx, const char **error_r)
{
	int ec;
	ec = gnutls_cipher_init(&(ctx->ctx), ctx->cipher, &ctx->key, &ctx->iv);
	if(ec < 0) return dcrypt_gnutls_error(ec, error_r);
	return 0;
}

static
int dcrypt_gnutls_ctx_sym_update(struct dcrypt_context_symmetric *ctx, const unsigned char *data, size_t data_len, buffer_t *result, const char **error_r)
{
	int ec;
	size_t outl = gnutls_cipher_get_block_size(ctx->cipher);
	unsigned char buf[outl];
	ec = gnutls_cipher_encrypt2(ctx->ctx, data, data_len, buf, outl);
	if(ec < 0) return dcrypt_gnutls_error(ec, error_r);
	buffer_append(result, buf, outl);
	return ec;
}

static
int dcrypt_gnutls_ctx_sym_final(struct dcrypt_context_symmetric *ctx, buffer_t *result, const char **error_r)
{
	return dcrypt_gnutls_ctx_sym_update(ctx, (const unsigned char*)"", 0, result, error_r);
}


static
int dcrypt_gnutls_ctx_hmac_create(const char *algorithm, struct dcrypt_context_hmac **ctx_r, const char **error_r)
{
	gnutls_mac_algorithm_t md = gnutls_mac_get_id(algorithm);
	if (md == GNUTLS_MAC_UNKNOWN) return dcrypt_gnutls_error(md, error_r);
	pool_t pool = pool_alloconly_create("dcrypt gnutls", 128);
	struct dcrypt_context_hmac *ctx = p_new(pool, struct dcrypt_context_hmac, 1);
	ctx->pool = pool;
	ctx->md = md;
	*ctx_r = ctx;
	return 0;
}

static
int dcrypt_gnutls_ctx_hmac_destroy(struct dcrypt_context_hmac **ctx)
{
	pool_t pool = (*ctx)->pool;
	gnutls_hmac_deinit((*ctx)->ctx, NULL);
	pool_unref(&pool);
	*ctx = NULL;
	return 0;
}


static
void dcrypt_gnutls_ctx_hmac_set_key(struct dcrypt_context_hmac *ctx, const unsigned char *key, size_t key_len)
{
        if(ctx->key.data != NULL) p_free(ctx->pool, ctx->key.data);
        ctx->key.size = I_MIN(key_len,(size_t)gnutls_hmac_get_len(ctx->md));
        ctx->key.data = p_malloc(ctx->pool, ctx->key.size);
        memcpy(ctx->key.data, key, ctx->key.size);
}

static
int dcrypt_gnutls_ctx_hmac_get_key(struct dcrypt_context_hmac *ctx, buffer_t *key)
{
	if (ctx->key.data == NULL) return -1;
	buffer_append(key, ctx->key.data, ctx->key.size);
	return 0;
}

static
int dcrypt_gnutls_ctx_hmac_init(struct dcrypt_context_hmac *ctx, const char **error_r)
{
	int ec;
	ec = gnutls_hmac_init(&(ctx->ctx), ctx->md, ctx->key.data, ctx->key.size);
	if (ec < 0) return dcrypt_gnutls_error(ec, error_r);
	return 0;
}
static
int dcrypt_gnutls_ctx_hmac_update(struct dcrypt_context_hmac *ctx, const unsigned char *data, size_t data_len, const char **error_r)
{
	int ec;
	if ((ec = gnutls_hmac(ctx->ctx, data, data_len)) != 0)
		return dcrypt_gnutls_error(ec, error_r);
	return 0;
}
static
int dcrypt_gnutls_ctx_hmac_final(struct dcrypt_context_hmac *ctx, buffer_t *result, const char **error_r)
{
	size_t hlen = gnutls_hmac_get_len(ctx->md);
	unsigned char buf[hlen];
	gnutls_hmac_output(ctx->ctx, buf);
	buffer_append(result, buf, hlen);
	return 0;
}

static
int dcrypt_gnutls_ecdh_derive_secret(struct dcrypt_public_key *peer_key, buffer_t *R, buffer_t *S, const char **error_r)
{

}

static
int dcrypt_gnutls_pbkdf2(const unsigned char *password, size_t password_len, const unsigned char *salt, size_t salt_len, const char *algorithm,
	unsigned int rounds, buffer_t *result, unsigned int result_len, const char **error_r)
{
	unsigned char buf[result_len];
	/* only sha1 or sha256 is supported */
	if (strncasecmp(algorithm, "sha1", 4) == 0) {
		pbkdf2_hmac_sha1(password_len, password, rounds, salt_len, salt, result_len, buf);
	} else if (strncasecmp(algorithm, "sha256", 6) == 0) {
		pbkdf2_hmac_sha256(password_len, password, rounds, salt_len, salt, result_len, buf);
	} else if (strncasecmp(algorithm, "sha512", 6) == 0) {
		struct hmac_sha512_ctx ctx;
		hmac_sha512_set_key(&ctx, password_len, password);
		PBKDF2(&ctx, hmac_sha512_update, hmac_sha512_digest, 64, rounds, salt_len, salt, result_len, buf);
		i_zero(&ctx);
	} else {
		*error_r = "Unsupported algorithm";
		return -1;
	}
	buffer_append(result, buf, result_len);
	memset(buf, 0, sizeof(buf));
	return 0;
}

static
int dcrypt_gnutls_generate_keypair(struct dcrypt_keypair *pair_r, enum dcrypt_key_type kind, unsigned int bits, const char *curve, const char **error_r)
{
	gnutls_pk_algorithm_t pk_algo;
	gnutls_ecc_curve_t pk_curve;

        if (kind == DCRYPT_KEY_EC) {
		pk_curve = gnutls_ecc_curve_get_id(curve);
		if (pk_curve == GNUTLS_ECC_CURVE_INVALID) {
			*error_r = "Invalid curve";
			return -1;
		}
		bits = GNUTLS_CURVE_TO_BITS(pk_curve);
#if GNUTLS_VERSION_NUMBER >= 0x030500
		pk_algo = gnutls_curve_get_pk(pk_curve);
#else
		pk_algo = GNUTLS_PK_EC;
#endif 
        } else if (kind == DCRYPT_KEY_RSA) {
                pk_algo = gnutls_pk_get_id("RSA");
        } else {
		*error_r = "Unsupported key type";
		return -1;
	}

	int ec;
	gnutls_privkey_t priv;
	if ((ec = gnutls_privkey_init(&priv)) != GNUTLS_E_SUCCESS) return dcrypt_gnutls_error(ec, error_r);
#if GNUTLS_VERSION_NUMBER >= 0x030500
	gnutls_privkey_set_flags(priv, GNUTLS_PRIVKEY_FLAG_EXPORT_COMPAT);
#endif
	ec = gnutls_privkey_generate(priv, pk_algo, bits, 0);
	if (ec != GNUTLS_E_SUCCESS) {
		gnutls_privkey_deinit(priv);
		return dcrypt_gnutls_error(ec, error_r);
	}

	pair_r->priv = (struct dcrypt_private_key*)priv;

	return dcrypt_gnutls_private_to_public_key(pair_r->priv, &(pair_r->pub), error_r);
} 

static
int dcrypt_gnutls_load_private_key(struct dcrypt_private_key **key_r, const unsigned char *data, size_t data_len, dcrypt_password_cb *cb, void *ctx, const char **error_r)
{

}
static
int dcrypt_gnutls_load_public_key(struct dcrypt_public_key **key_r, const unsigned char *data, size_t data_len, const char **error_r)
{

}

static
int dcrypt_gnutls_store_private_key(struct dcrypt_private_key *key, const char *cipher, buffer_t *destination, dcrypt_password_cb *cb, void *ctx, const char **error_r)
{
	gnutls_privkey_t priv = (gnutls_privkey_t)key;
	gnutls_x509_privkey_t xkey;
	gnutls_privkey_export_x509(priv, &xkey);
	/* then export PEM */
	size_t outl = 0;
	gnutls_x509_privkey_export_pkcs8(xkey, GNUTLS_X509_FMT_PEM, NULL, 0, NULL, &outl);
	char buffer[outl];
	gnutls_x509_privkey_export_pkcs8(xkey, GNUTLS_X509_FMT_PEM, NULL, 0, buffer, &outl);
	buffer_append(destination, buffer, outl);
	memset(buffer, 0, sizeof(buffer));
	return 0;
}

static
int dcrypt_gnutls_store_public_key(struct dcrypt_public_key *key, buffer_t *destination, const char **error_r)
{
	gnutls_pubkey_t pub = (gnutls_pubkey_t)key;
	size_t outl = 0;
	gnutls_pubkey_export(pub, GNUTLS_X509_FMT_PEM, NULL, &outl);
	char buffer[outl];
	gnutls_pubkey_export(pub, GNUTLS_X509_FMT_PEM, buffer, &outl);
	buffer_append(destination, buffer, outl);
	return 0;
}

static
int dcrypt_gnutls_private_to_public_key(struct dcrypt_private_key *priv_key, struct dcrypt_public_key **pub_key_r, const char **error_r)
{
	int ec;

	gnutls_privkey_t priv = (gnutls_privkey_t)priv_key;
	if (gnutls_privkey_get_pk_algorithm(priv, NULL) == GNUTLS_PK_RSA) {
		gnutls_datum_t m,e;
		/* do not extract anything we don't need */
		ec = gnutls_privkey_export_rsa_raw(priv, &m, &e, NULL, NULL, NULL, NULL, NULL, NULL);
		if (ec != GNUTLS_E_SUCCESS) return dcrypt_gnutls_error(ec, error_r);
		gnutls_pubkey_t pub;
		gnutls_pubkey_init(&pub);
		ec = gnutls_pubkey_import_rsa_raw(pub, &m, &e);
		gnutls_free(m.data);
		gnutls_free(e.data);
		if (ec < 0) {
			gnutls_pubkey_deinit(pub);
			return dcrypt_gnutls_error(ec, error_r);
		}
		*pub_key_r = (struct dcrypt_public_key*)pub;
		return 0;
	} else if (gnutls_privkey_get_pk_algorithm(priv, NULL) == GNUTLS_PK_EC) {
		gnutls_ecc_curve_t curve;
		gnutls_datum_t x,y,k;
		ec = gnutls_privkey_export_ecc_raw(priv, &curve, &x, &y, NULL);
		if (ec != GNUTLS_E_SUCCESS) return dcrypt_gnutls_error(ec, error_r);
		gnutls_pubkey_t pub;
		gnutls_pubkey_init(&pub);
		ec = gnutls_pubkey_import_ecc_raw(pub, curve, &x, &y);
		gnutls_free(x.data);
		gnutls_free(y.data);
		if (ec < 0) {
			gnutls_pubkey_deinit(pub);
			return dcrypt_gnutls_error(ec, error_r);
		}
		*pub_key_r = (struct dcrypt_public_key*)pub;
		return 0;
	}

	return -1;
}

static
void dcrypt_gnutls_free_public_key(struct dcrypt_public_key **key)
{
	gnutls_pubkey_deinit((gnutls_pubkey_t)*key);
	*key = NULL;
}
static
void dcrypt_gnutls_free_private_key(struct dcrypt_private_key **key)
{
	gnutls_privkey_deinit((gnutls_privkey_t)*key);
	*key = NULL;
}
static
void dcrypt_gnutls_free_keypair(struct dcrypt_keypair *keypair)
{
	dcrypt_gnutls_free_public_key(&(keypair->pub));
	dcrypt_gnutls_free_private_key(&(keypair->priv));
}

static
int dcrypt_gnutls_rsa_encrypt(struct dcrypt_public_key *key, const unsigned char *data, size_t data_len, buffer_t *result, const char **error_r)
{

}
static
int dcrypt_gnutls_rsa_decrypt(struct dcrypt_private_key *key, const unsigned char *data, size_t data_len, buffer_t *result, const char **error_r)
{

}

static
int dcrypt_gnutls_oid_keytype(const unsigned char *oid, size_t oid_len, enum dcrypt_key_type *key_type, const char **error_r)
{

}
static
int dcrypt_gnutls_keytype_oid(enum dcrypt_key_type key_type, buffer_t *oid, const char **error_r)
{

}

static
const char *dcrypt_gnutls_oid2name(const unsigned char *oid, size_t oid_len, const char **error_r)
{
}

static
int dcrypt_gnutls_name2oid(const char *name, buffer_t *oid, const char **error_r)
{

}

static struct dcrypt_vfs dcrypt_gnutls_vfs = {
	.ctx_sym_create = dcrypt_gnutls_ctx_sym_create,
	.ctx_sym_destroy = dcrypt_gnutls_ctx_sym_destroy,
	.ctx_sym_set_key = dcrypt_gnutls_ctx_sym_set_key,
	.ctx_sym_set_iv = dcrypt_gnutls_ctx_sym_set_iv,
	.ctx_sym_set_key_iv_random = dcrypt_gnutls_ctx_sym_set_key_iv_random,
	.ctx_sym_get_key = dcrypt_gnutls_ctx_sym_get_key,
	.ctx_sym_get_iv = dcrypt_gnutls_ctx_sym_get_iv,
	.ctx_sym_get_key_length = dcrypt_gnutls_ctx_sym_get_key_length,
	.ctx_sym_get_iv_length = dcrypt_gnutls_ctx_sym_get_iv_length,
	.ctx_sym_init = dcrypt_gnutls_ctx_sym_init,
	.ctx_sym_update = dcrypt_gnutls_ctx_sym_update,
	.ctx_sym_final = dcrypt_gnutls_ctx_sym_final,
	.ctx_hmac_create = dcrypt_gnutls_ctx_hmac_create,
	.ctx_hmac_destroy = dcrypt_gnutls_ctx_hmac_destroy,
	.ctx_hmac_set_key = dcrypt_gnutls_ctx_hmac_set_key,
	.ctx_hmac_get_key = dcrypt_gnutls_ctx_hmac_get_key,
	.ctx_hmac_init = dcrypt_gnutls_ctx_hmac_init,
	.ctx_hmac_update = dcrypt_gnutls_ctx_hmac_update,
	.ctx_hmac_final = dcrypt_gnutls_ctx_hmac_final,
//	.ecdh_derive_secret = dcrypt_gnutls_ecdh_derive_secret,
	.pbkdf2 = dcrypt_gnutls_pbkdf2,
	.generate_keypair = dcrypt_gnutls_generate_keypair,
	.load_private_key = dcrypt_gnutls_load_private_key,
	.load_public_key = dcrypt_gnutls_load_public_key,
	.store_private_key = dcrypt_gnutls_store_private_key,
	.store_public_key = dcrypt_gnutls_store_public_key,
	.private_to_public_key = dcrypt_gnutls_private_to_public_key,
	.free_keypair = dcrypt_gnutls_free_keypair,
	.free_public_key = dcrypt_gnutls_free_public_key,
	.free_private_key = dcrypt_gnutls_free_private_key,
	.rsa_encrypt = dcrypt_gnutls_rsa_encrypt,
	.rsa_decrypt = dcrypt_gnutls_rsa_decrypt,
	.oid_keytype = dcrypt_gnutls_oid_keytype,
	.keytype_oid = dcrypt_gnutls_keytype_oid,
	.oid2name = dcrypt_gnutls_oid2name,
	.name2oid = dcrypt_gnutls_name2oid
};

void dcrypt_gnutls_init(struct module *module ATTR_UNUSED)
{
	gnutls_global_init();
	dcrypt_set_vfs(&dcrypt_gnutls_vfs);
}

void dcrypt_gnutls_deinit(void)
{
	gnutls_global_deinit();
}
