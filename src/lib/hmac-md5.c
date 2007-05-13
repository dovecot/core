/*
 * HMAC-MD5 (RFC-2104) implementation.
 *
 * Copyright (c) 2004 Andrey Panin <pazke@donpac.ru>
 *
 * CRAM-MD5 (RFC 2195) compatibility code
 * Copyright (c) 2003 Joshua Goodall <joshua@roughtrade.net>
 *
 * This software is released under the MIT license.
 */

#include "lib.h"
#include "hmac-md5.h"
#include "safe-memset.h"

void hmac_md5_init(struct hmac_md5_context *ctx,
		   const unsigned char *key, size_t key_len)
{
	int i;
	unsigned char md5key[16];
	unsigned char k_ipad[64];
	unsigned char k_opad[64];

	if (key_len > 64) {
		md5_get_digest(key, key_len, md5key);
		key = md5key;
		key_len = 16;
	}

	memcpy(k_ipad, key, key_len);
	memset(k_ipad + key_len, 0, 64 - key_len);
	memcpy(k_opad, k_ipad, 64);

	for (i = 0; i < 64; i++) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	md5_init(&ctx->ctx);
	md5_update(&ctx->ctx, k_ipad, 64);  
	md5_init(&ctx->ctxo);
	md5_update(&ctx->ctxo, k_opad, 64);   

	safe_memset(k_ipad, 0, 64);
	safe_memset(k_opad, 0, 64);
}

void hmac_md5_final(struct hmac_md5_context *ctx, unsigned char *digest)
{
	md5_final(&ctx->ctx, digest);

	md5_update(&ctx->ctxo, digest, 16); 
	md5_final(&ctx->ctxo, digest);
}

void hmac_md5_get_cram_context(struct hmac_md5_context *ctx,
			unsigned char context_digest[CRAM_MD5_CONTEXTLEN])
{
	unsigned char *cdp;

#define CDPUT(p, c) STMT_START {   \
	*(p)++ = (c) & 0xff;       \
	*(p)++ = (c) >> 8 & 0xff;  \
	*(p)++ = (c) >> 16 & 0xff; \
	*(p)++ = (c) >> 24 & 0xff; \
} STMT_END
	cdp = context_digest;
	CDPUT(cdp, ctx->ctxo.a);
	CDPUT(cdp, ctx->ctxo.b);
	CDPUT(cdp, ctx->ctxo.c);
	CDPUT(cdp, ctx->ctxo.d);
	CDPUT(cdp, ctx->ctx.a);
	CDPUT(cdp, ctx->ctx.b);
	CDPUT(cdp, ctx->ctx.c);
	CDPUT(cdp, ctx->ctx.d);
}

void hmac_md5_set_cram_context(struct hmac_md5_context *ctx,
			const unsigned char context_digest[CRAM_MD5_CONTEXTLEN])
{
	const unsigned char *cdp;

#define CDGET(p, c) STMT_START { \
	(c)  = (*p++);           \
	(c) += (*p++ << 8);      \
	(c) += (*p++ << 16);     \
	(c) += (*p++ << 24);     \
} STMT_END
	cdp = context_digest;
	CDGET(cdp, ctx->ctxo.a);
	CDGET(cdp, ctx->ctxo.b);
	CDGET(cdp, ctx->ctxo.c);
	CDGET(cdp, ctx->ctxo.d);
	CDGET(cdp, ctx->ctx.a);
	CDGET(cdp, ctx->ctx.b);
	CDGET(cdp, ctx->ctx.c);
	CDGET(cdp, ctx->ctx.d);

	ctx->ctxo.lo = ctx->ctx.lo = 64;
	ctx->ctxo.hi = ctx->ctx.hi = 0;
}
