#ifndef HASH_METHOD_H
#define HASH_METHOD_H

#include "buffer.h"

struct hash_method {
	const char *name;
	/* Number of bytes that must be allocated for context */
	unsigned int context_size;
	/* Number of bytes that must be allocated for result()'s digest */
	unsigned int digest_size;

	void (*init)(void *context);
	void (*loop)(void *context, const void *data, size_t size);
	void (*result)(void *context, unsigned char *digest_r);
};

const struct hash_method *hash_method_lookup(const char *name);

/* NULL-terminated list of all hash methods */
extern const struct hash_method *hash_methods[];

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
