/*
 * HMAC-SHA1 (RFC-2104) implementation.
 *
 * Copyright (c) 2004 Andrey Panin <pazke@donpac.ru>
 * Copyright (c) 2011 Florian Zeitz <florob@babelmonkeys.de>
 *
 * This software is released under the MIT license.
 */

#include "lib.h"
#include "hmac-sha1.h"
#include "safe-memset.h"

void hmac_sha1_init(struct hmac_sha1_context *ctx,
		   const unsigned char *key, size_t key_len)
{
	int i;
	unsigned char sha1key[20];
	unsigned char k_ipad[64];
	unsigned char k_opad[64];

	if (key_len > 64) {
		sha1_get_digest(key, key_len, sha1key);
		key = sha1key;
		key_len = 20;
	}

	memcpy(k_ipad, key, key_len);
	memset(k_ipad + key_len, 0, 64 - key_len);
	memcpy(k_opad, k_ipad, 64);

	for (i = 0; i < 64; i++) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	sha1_init(&ctx->ctx);
	sha1_loop(&ctx->ctx, k_ipad, 64);
	sha1_init(&ctx->ctxo);
	sha1_loop(&ctx->ctxo, k_opad, 64);

	safe_memset(k_ipad, 0, 64);
	safe_memset(k_opad, 0, 64);
}

void hmac_sha1_final(struct hmac_sha1_context *ctx, unsigned char *digest)
{
	sha1_result(&ctx->ctx, digest);

	sha1_loop(&ctx->ctxo, digest, 20);
	sha1_result(&ctx->ctxo, digest);
}
