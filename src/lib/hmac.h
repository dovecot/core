#ifndef HMAC_H
#define HMAC_H

#include "hash-method.h"
#include "sha1.h"

#define HMAC_MAX_CONTEXT_SIZE 256

struct hmac_context_priv {
	char ctx[HMAC_MAX_CONTEXT_SIZE];
	char ctxo[HMAC_MAX_CONTEXT_SIZE];
	const struct hash_method *hash;
};

struct hmac_context {
	union {
		struct hmac_context_priv priv;
		uint64_t padding_requirement;
	} u;
};

void hmac_init(struct hmac_context *ctx, const unsigned char *key,
		size_t key_len, const struct hash_method *meth);
void hmac_final(struct hmac_context *ctx, unsigned char *digest);


static inline void
hmac_update(struct hmac_context *_ctx, const void *data, size_t size)
{
	struct hmac_context_priv *ctx = &_ctx->u.priv;

	ctx->hash->loop(ctx->ctx, data, size);
}

buffer_t *t_hmac_data(const struct hash_method *meth,
		      const unsigned char *key, size_t key_len,
		      const void *data, size_t data_len);
buffer_t *t_hmac_buffer(const struct hash_method *meth,
			const unsigned char *key, size_t key_len,
			const buffer_t *data);
buffer_t *t_hmac_str(const struct hash_method *meth,
		     const unsigned char *key, size_t key_len,
		     const char *data);

#endif
