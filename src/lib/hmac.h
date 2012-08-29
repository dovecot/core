#ifndef HMAC_H
#define HMAC_H

#include "hash-method.h"
#include "sha1.h"

#define HMAC_MAX_CONTEXT_SIZE 256

struct hmac_context {
	char ctx[HMAC_MAX_CONTEXT_SIZE];
	char ctxo[HMAC_MAX_CONTEXT_SIZE];
	const struct hash_method *hash;
};

void hmac_init(struct hmac_context *ctx, const unsigned char *key,
		size_t key_len, const struct hash_method *meth);
void hmac_final(struct hmac_context *ctx, unsigned char *digest);


static inline void
hmac_update(struct hmac_context *ctx, const void *data, size_t size)
{
	ctx->hash->loop(ctx->ctx, data, size);
}

#endif
