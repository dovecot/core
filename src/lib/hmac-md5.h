#ifndef HMAC_MD5_H
#define HMAC_MD5_H

#include "md5.h"

#define CRAM_MD5_CONTEXTLEN 32

struct hmac_md5_context {
	struct md5_context ctx, ctxo;
};

void hmac_md5_init(struct hmac_md5_context *ctx,
		   const unsigned char *key, size_t key_len);
void hmac_md5_final(struct hmac_md5_context *ctx,
		    unsigned char digest[MD5_RESULTLEN]);

void hmac_md5_get_cram_context(struct hmac_md5_context *ctx,
		unsigned char context_digest[CRAM_MD5_CONTEXTLEN]);
void hmac_md5_set_cram_context(struct hmac_md5_context *ctx,
		const unsigned char context_digest[CRAM_MD5_CONTEXTLEN]);


static inline void
hmac_md5_update(struct hmac_md5_context *ctx, const void *data, size_t size)
{
	md5_update(&ctx->ctx, data, size);
}

#endif
