/*
 * This is an OpenSSL-compatible implementation of the RSA Data Security,
 * Inc. MD4 Message-Digest Algorithm.
 *
 * Written by Solar Designer <solar@openwall.com> in 2001, and placed in
 * the public domain.  See md4.c for more information.
 */

#ifndef __MD4_H
#define __MD4_H

struct md4_context {
	uint_fast32_t lo, hi;
	uint_fast32_t a, b, c, d;
	unsigned char buffer[64];
	uint_fast32_t block[16];
};

void md4_init(struct md4_context *ctx);
void md4_update(struct md4_context *ctx, const void *data, size_t size);
void md4_final(struct md4_context *ctx, unsigned char result[16]);

void md4_get_digest(const void *data, size_t size, unsigned char result[16]);

#endif
