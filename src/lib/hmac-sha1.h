#ifndef HMAC_SHA1_H
#define HMAC_SHA1_H

#include "sha1.h"

struct hmac_sha1_context {
	struct sha1_ctxt ctx, ctxo;
};

void hmac_sha1_init(struct hmac_sha1_context *ctx,
		   const unsigned char *key, size_t key_len);
void hmac_sha1_final(struct hmac_sha1_context *ctx,
		    unsigned char digest[SHA1_RESULTLEN]);


static inline void
hmac_sha1_update(struct hmac_sha1_context *ctx, const void *data, size_t size)
{
	sha1_loop(&ctx->ctx, data, size);
}

#endif
