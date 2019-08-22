/*
 * HMAC (RFC-2104) implementation.
 *
 * Copyright (c) 2004 Andrey Panin <pazke@donpac.ru>
 * Copyright (c) 2011-2016 Florian Zeitz <florob@babelmonkeys.de>
 *
 * This software is released under the MIT license.
 */

#include "lib.h"
#include "hmac.h"
#include "safe-memset.h"
#include "buffer.h"

#include "hex-binary.h"

void hmac_init(struct hmac_context *_ctx, const unsigned char *key,
		size_t key_len, const struct hash_method *meth)
{
	struct hmac_context_priv *ctx = &_ctx->u.priv;
	int i;
	unsigned char k_ipad[64];
	unsigned char k_opad[64];
	unsigned char hashedkey[meth->digest_size];

	i_assert(meth->context_size <= HMAC_MAX_CONTEXT_SIZE);

	ctx->hash = meth;

	if (key_len > 64) {
		meth->init(ctx->ctx);
		meth->loop(ctx->ctx, key, key_len);
		meth->result(ctx->ctx, hashedkey);
		key = hashedkey;
		key_len = meth->digest_size;
	}

	memcpy(k_ipad, key, key_len);
	memset(k_ipad + key_len, 0, 64 - key_len);
	memcpy(k_opad, k_ipad, 64);

	for (i = 0; i < 64; i++) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	meth->init(ctx->ctx);
	meth->loop(ctx->ctx, k_ipad, 64);
	meth->init(ctx->ctxo);
	meth->loop(ctx->ctxo, k_opad, 64);

	safe_memset(k_ipad, 0, 64);
	safe_memset(k_opad, 0, 64);
}

void hmac_final(struct hmac_context *_ctx, unsigned char *digest)
{
	struct hmac_context_priv *ctx = &_ctx->u.priv;

	ctx->hash->result(ctx->ctx, digest);

	ctx->hash->loop(ctx->ctxo, digest, ctx->hash->digest_size);
	ctx->hash->result(ctx->ctxo, digest);
}

buffer_t *t_hmac_data(const struct hash_method *meth,
		      const unsigned char *key, size_t key_len,
		      const void *data, size_t data_len)
{
	struct hmac_context ctx;
	i_assert(meth != NULL);
	i_assert(key != NULL && key_len > 0);
	i_assert(data != NULL || data_len == 0);

	buffer_t *res = t_buffer_create(meth->digest_size);
	hmac_init(&ctx, key, key_len, meth);
	if (data_len > 0)
		hmac_update(&ctx, data, data_len);
	unsigned char *buf = buffer_get_space_unsafe(res, 0, meth->digest_size);
	hmac_final(&ctx, buf);
	return res;
}

buffer_t *t_hmac_buffer(const struct hash_method *meth,
			const unsigned char *key, size_t key_len,
			const buffer_t *data)
{
	return t_hmac_data(meth, key, key_len, data->data, data->used);
}

buffer_t *t_hmac_str(const struct hash_method *meth,
		     const unsigned char *key, size_t key_len,
		     const char *data)
{
	return t_hmac_data(meth, key, key_len, data, strlen(data));
}

void hmac_hkdf(const struct hash_method *method,
	       const unsigned char *salt, size_t salt_len,
	       const unsigned char *ikm, size_t ikm_len,
	       const unsigned char *info, size_t info_len,
	       buffer_t *okm_r, size_t okm_len)
{
	i_assert(method != NULL);
	i_assert(okm_len < 255*method->digest_size);
	struct hmac_context key_mac;
	struct hmac_context info_mac;
	size_t remain = okm_len;
	unsigned char prk[method->digest_size];
	unsigned char okm[method->digest_size];
	/* N = ceil(L/HashLen) */
	unsigned int rounds = (okm_len + method->digest_size - 1)/method->digest_size;

	/* salt and info can be NULL */
	i_assert(salt != NULL || salt_len == 0);
	i_assert(info != NULL || info_len == 0);

	i_assert(ikm != NULL && ikm_len > 0);
	i_assert(okm_r != NULL && okm_len > 0);

	/* but they still need valid pointer, reduces
	   complains from static analysers */
	if (salt == NULL)
		salt = &uchar_nul;
	if (info == NULL)
		info = &uchar_nul;

	/* extract */
	hmac_init(&key_mac, salt, salt_len, method);
	hmac_update(&key_mac, ikm, ikm_len);
	hmac_final(&key_mac, prk);

	/* expand */
	for (unsigned int i = 0; remain > 0 && i < rounds; i++) {
		unsigned char round = (i+1);
		size_t amt = remain;
		if (amt > method->digest_size)
			amt = method->digest_size;
		hmac_init(&info_mac, prk, method->digest_size, method);
		if (i > 0)
			hmac_update(&info_mac, okm, method->digest_size);
		hmac_update(&info_mac, info, info_len);
		hmac_update(&info_mac, &round, 1);
		memset(okm, 0, method->digest_size);
		hmac_final(&info_mac, okm);
		buffer_append(okm_r, okm, amt);
		remain -= amt;
	}

	safe_memset(prk, 0, sizeof(prk));
	safe_memset(okm, 0, sizeof(okm));
}
