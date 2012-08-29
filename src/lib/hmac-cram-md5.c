/*
 * CRAM-MD5 (RFC 2195) compatibility code
 * Copyright (c) 2003 Joshua Goodall <joshua@roughtrade.net>
 *
 * This software is released under the MIT license.
 */

#include "lib.h"
#include "md5.h"
#include "hmac-cram-md5.h"

void hmac_md5_get_cram_context(struct hmac_context *hmac_ctx,
			unsigned char context_digest[CRAM_MD5_CONTEXTLEN])
{
	unsigned char *cdp;

	struct md5_context *ctx = (void*)hmac_ctx->ctx;
	struct md5_context *ctxo = (void*)hmac_ctx->ctxo;

#define CDPUT(p, c) STMT_START {   \
	*(p)++ = (c) & 0xff;       \
	*(p)++ = (c) >> 8 & 0xff;  \
	*(p)++ = (c) >> 16 & 0xff; \
	*(p)++ = (c) >> 24 & 0xff; \
} STMT_END
	cdp = context_digest;
	CDPUT(cdp, ctxo->a);
	CDPUT(cdp, ctxo->b);
	CDPUT(cdp, ctxo->c);
	CDPUT(cdp, ctxo->d);
	CDPUT(cdp, ctx->a);
	CDPUT(cdp, ctx->b);
	CDPUT(cdp, ctx->c);
	CDPUT(cdp, ctx->d);
}

void hmac_md5_set_cram_context(struct hmac_context *hmac_ctx,
			const unsigned char context_digest[CRAM_MD5_CONTEXTLEN])
{
	const unsigned char *cdp;

	struct md5_context *ctx = (void*)hmac_ctx->ctx;
	struct md5_context *ctxo = (void*)hmac_ctx->ctxo;

#define CDGET(p, c) STMT_START { \
	(c)  = (*p++);           \
	(c) += (*p++ << 8);      \
	(c) += (*p++ << 16);     \
	(c) += (*p++ << 24);     \
} STMT_END
	cdp = context_digest;
	CDGET(cdp, ctxo->a);
	CDGET(cdp, ctxo->b);
	CDGET(cdp, ctxo->c);
	CDGET(cdp, ctxo->d);
	CDGET(cdp, ctx->a);
	CDGET(cdp, ctx->b);
	CDGET(cdp, ctx->c);
	CDGET(cdp, ctx->d);

	ctxo->lo = ctx->lo = 64;
	ctxo->hi = ctx->hi = 0;
}
