/*
 * FIPS 180-2 SHA-224/256/384/512 implementation
 * Last update: 02/02/2007
 * Issue date:  04/30/2005
 *
 * Copyright (C) 2005, 2007 Olivier Gay <olivier.gay@a3.epfl.ch>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef SHA2_H
#define SHA2_H

#include "hash-method.h"

#define SHA256_RESULTLEN (256 / 8)
#define SHA256_BLOCK_SIZE (512 / 8)

#define SHA512_RESULTLEN (512 / 8)
#define SHA512_BLOCK_SIZE (1024 / 8)

struct sha256_ctx {
	size_t tot_len;
	size_t len;
	unsigned char block[2 * SHA256_BLOCK_SIZE];
	uint32_t h[8];
};

struct sha512_ctx {
	size_t tot_len;
	size_t len;
	unsigned char block[2 * SHA512_BLOCK_SIZE];
	uint64_t h[8];
};

void sha256_init(struct sha256_ctx *ctx);
void sha256_loop(struct sha256_ctx *ctx, const void *data, size_t len);
void sha256_result(struct sha256_ctx *ctx,
		   unsigned char digest[SHA256_RESULTLEN]);

void sha256_get_digest(const void *data, size_t size,
		       unsigned char digest[SHA256_RESULTLEN]);

void sha512_init(struct sha512_ctx *ctx);
void sha512_loop(struct sha512_ctx *ctx, const void *data, size_t len);
void sha512_result(struct sha512_ctx *ctx,
		   unsigned char digest[SHA512_RESULTLEN]);

void sha512_get_digest(const void *data, size_t size,
		       unsigned char digest[SHA512_RESULTLEN]);

extern const struct hash_method hash_method_sha256;
extern const struct hash_method hash_method_sha512;

#endif /* !SHA2_H */
