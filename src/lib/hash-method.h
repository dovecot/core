#ifndef HASH_METHOD_H
#define HASH_METHOD_H

#include "buffer.h"
#include "sha2.h"

#define HASH_METHOD_MAX_CONTEXT_SIZE sizeof(struct sha512_ctx)

struct hash_method {
	const char *name;
	/* Block size for the algorithm */
	unsigned int block_size;
	/* Number of bytes that must be allocated for context */
	unsigned int context_size;
	/* Number of bytes that must be allocated for result()'s digest */
	unsigned int digest_size;

	void (*init)(void *context);
	void (*loop)(void *context, const void *data, size_t size);
	void (*result)(void *context, unsigned char *digest_r);
};

struct hash_method_context {
	char ctx[HASH_METHOD_MAX_CONTEXT_SIZE];
	const struct hash_method *hash;
};

const struct hash_method *hash_method_lookup(const char *name);

/* NULL-terminated list of all hash methods */
extern const struct hash_method *hash_methods[];

static inline void
hash_method_init(struct hash_method_context *ctx,
		 const struct hash_method *meth)
{
	i_assert(meth->context_size <= HASH_METHOD_MAX_CONTEXT_SIZE);

	i_zero(ctx);
	ctx->hash = meth;

	ctx->hash->init(ctx->ctx);
}

static inline void
hash_method_loop(struct hash_method_context *ctx, const void *data, size_t size)
{
	ctx->hash->loop(ctx->ctx, data, size);
}

static inline void
hash_method_result(struct hash_method_context *ctx, unsigned char *digest_r)
{
	ctx->hash->result(ctx->ctx, digest_r);
}

void hash_method_get_digest(const struct hash_method *meth,
			    const void *data, size_t data_len,
			    unsigned char *result_r);

/** Simple datastack helpers for digesting (hashing)

 * USAGE:

 buffer_t *result = t_hash_str(hash_method_lookup("sha256"), "hello world");
 const char *hex = binary_to_hex(result->data, result->used);

*/

buffer_t *t_hash_data(const struct hash_method *meth,
		      const void *data, size_t data_len);

static inline
buffer_t *t_hash_buffer(const struct hash_method *meth,
			const buffer_t *data)
{
	return t_hash_data(meth, data->data, data->used);
}

static inline
buffer_t *t_hash_str(const struct hash_method *meth,
		     const char *data)
{
	return t_hash_data(meth, data, strlen(data));
}

#endif
