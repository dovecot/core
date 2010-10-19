#ifndef HASH_METHOD_H
#define HASH_METHOD_H

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

#endif
