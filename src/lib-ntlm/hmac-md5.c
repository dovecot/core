/*
 * HMAC-MD5 (RFC-2104) implementation.
 *
 * Copyright (c) 2004 Andrey Panin <pazke@donpac.ru>
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published 
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "lib.h"
#include "hmac-md5.h"

void hmac_md5_init(struct hmac_md5_context *ctx,
		   const unsigned char * key, size_t key_len)
{
	int i;
	unsigned char md5key[16];

	if (key_len > 64) {
		md5_get_digest(key, key_len, md5key);
		key = md5key;
		key_len = 16;
	}

	memcpy(ctx->k_ipad, key, key_len);
	memset(ctx->k_ipad + key_len, 0, 64 - key_len);
	memcpy(ctx->k_opad, ctx->k_ipad, 64);

	for (i = 0; i < 64; i++) {
		ctx->k_ipad[i] ^= 0x36;
		ctx->k_opad[i] ^= 0x5c;
	}

	md5_init(&ctx->ctx);
	md5_update(&ctx->ctx, ctx->k_ipad, 64);  
}

void hmac_md5_final(struct hmac_md5_context *ctx, unsigned char *digest)
{
	md5_final(&ctx->ctx, digest);

	md5_init(&ctx->ctx);
	md5_update(&ctx->ctx, ctx->k_opad, 64);   
	md5_update(&ctx->ctx, digest, 16); 
	md5_final(&ctx->ctx, digest);
}
