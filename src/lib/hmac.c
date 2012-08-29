/*
 * HMAC (RFC-2104) implementation.
 *
 * Copyright (c) 2004 Andrey Panin <pazke@donpac.ru>
 * Copyright (c) 2011-2012 Florian Zeitz <florob@babelmonkeys.de>
 *
 * This software is released under the MIT license.
 */

#include "lib.h"
#include "hmac.h"
#include "safe-memset.h"

void hmac_init(struct hmac_context *ctx, const unsigned char *key,
		size_t key_len, const struct hash_method *meth)
{
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

void hmac_final(struct hmac_context *ctx, unsigned char *digest)
{
	ctx->hash->result(ctx->ctx, digest);

	ctx->hash->loop(ctx->ctxo, digest, ctx->hash->digest_size);
	ctx->hash->result(ctx->ctxo, digest);
}
