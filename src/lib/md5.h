/*
 * This is an OpenSSL-compatible implementation of the RSA Data Security,
 * Inc. MD5 Message-Digest Algorithm.
 *
 * Written by Solar Designer <solar@openwall.com> in 2001, and placed in
 * the public domain.  See md5.c for more information.
 */

#ifndef __MD5_H
#define __MD5_H

/* Any 32-bit or wider integer data type will do */
typedef unsigned long MD5_u32plus;

typedef struct {
	MD5_u32plus lo, hi;
	MD5_u32plus a, b, c, d;
	unsigned char buffer[64];
	MD5_u32plus block[16];
} MD5Context;

void md5_init(MD5Context *ctx);
void md5_update(MD5Context *ctx, const void *data, unsigned int size);
void md5_final(MD5Context *ctx, unsigned char result[16]);

void md5_get_digest(const void *data, unsigned int size,
		    unsigned char result[16]);

#endif
