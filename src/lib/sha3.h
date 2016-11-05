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

#ifndef SHA3_H
#define SHA3_H

#include "hash-method.h"
#include "sha-common.h"

#define SHA3_KECCAK_SPONGE_WORDS \
	(((1600)/8/*bits to byte*/)/sizeof(uint64_t))

struct sha3_ctx {
	uint64_t saved;	 /* the portion of the input message that we
			  * didn't consume yet */
	union {		 /* Keccak's state */
		uint64_t s[SHA3_KECCAK_SPONGE_WORDS];
		uint8_t sb[SHA3_KECCAK_SPONGE_WORDS * 8];
	};
	unsigned byteIndex; /* 0..7--the next byte after the set one
			     * (starts from 0; 0--none are buffered) */
	unsigned wordIndex; /* 0..24--the next word to integrate input
			     * (starts from 0) */
	unsigned capacityWords; /* the double size of the hash output in
				 * words (e.g. 16 for Keccak 512) */
};

void sha3_256_init(void *context);
void sha3_256_result(void *context,
		   unsigned char digest[STATIC_ARRAY SHA256_RESULTLEN]);
void sha3_256_get_digest(const void *data, size_t size,
		       unsigned char digest[STATIC_ARRAY SHA256_RESULTLEN]);

void sha3_512_init(void *context);
void sha3_512_result(void *context,
		   unsigned char digest[STATIC_ARRAY SHA512_RESULTLEN]);
void sha3_512_get_digest(const void *data, size_t size,
		       unsigned char digest[STATIC_ARRAY SHA512_RESULTLEN]);

void sha3_loop(void *context, const void *data, size_t len);

extern const struct hash_method hash_method_sha3_256;
extern const struct hash_method hash_method_sha3_512;

#endif
