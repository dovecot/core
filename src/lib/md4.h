/*
 * This is an OpenSSL-compatible implementation of the RSA Data Security,
 * Inc. MD4 Message-Digest Algorithm.
 *
 * Written by Solar Designer <solar@openwall.com> in 2001, and placed in
 * the public domain.  See md4.c for more information.
 */

#ifndef MD4_H
#define MD4_H

#include "hash-method.h"

#define	MD4_RESULTLEN (128/8)

struct md4_context {
	uint_fast32_t lo, hi;
	uint_fast32_t a, b, c, d;
	unsigned char buffer[64];
	uint_fast32_t block[MD4_RESULTLEN];
};

void md4_init(struct md4_context *ctx);
void md4_update(struct md4_context *ctx, const void *data, size_t size);
void md4_final(struct md4_context *ctx, unsigned char result[MD4_RESULTLEN]);

void md4_get_digest(const void *data, size_t size,
		    unsigned char result[MD4_RESULTLEN]);

extern const struct hash_method hash_method_md4;

#endif
