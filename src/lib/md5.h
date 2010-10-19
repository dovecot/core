/*
 * This is an OpenSSL-compatible implementation of the RSA Data Security,
 * Inc. MD5 Message-Digest Algorithm.
 *
 * Written by Solar Designer <solar@openwall.com> in 2001, and placed in
 * the public domain.  See md5.c for more information.
 */

#ifndef MD5_H
#define MD5_H

#include "hash-method.h"

#define	MD5_RESULTLEN (128/8)

struct md5_context {
	uint_fast32_t lo, hi;
	uint_fast32_t a, b, c, d;
	unsigned char buffer[64];
	uint_fast32_t block[MD5_RESULTLEN];
};

void md5_init(struct md5_context *ctx);
void md5_update(struct md5_context *ctx, const void *data, size_t size);
void md5_final(struct md5_context *ctx, unsigned char result[MD5_RESULTLEN]);

void md5_get_digest(const void *data, size_t size,
		    unsigned char result[MD5_RESULTLEN]);

extern const struct hash_method hash_method_md5;

#endif
