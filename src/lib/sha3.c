/* -------------------------------------------------------------------------
 * Works when compiled for either 32-bit or 64-bit targets, optimized for
 * 64 bit.
 *
 * Canonical implementation of Init/Update/Finalize for SHA-3 byte input.
 *
 * SHA3-256, SHA3-384, SHA-512 are implemented. SHA-224 can easily be added.
 *
 * Based on code from http://keccak.noekeon.org/ .
 *
 * I place the code that I wrote into public domain, free to use.
 *
 * I would appreciate if you give credits to this work if you used it to
 * write or test * your code.
 *
 * Aug 2015. Andrey Jivsov. crypto@brainhub.org
 *
 * Modified for Dovecot oy use
 * Oct 2016. Aki Tuomi <aki.tuomi@dovecot.fi>

 * ---------------------------------------------------------------------- */
#include "lib.h"
#include "sha3.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#if defined(_MSC_VER)
#define SHA3_CONST(x) x
#else
#define SHA3_CONST(x) x##L
#endif

/* The following state definition should normally be in a separate
 * header file
 */

#ifndef SHA3_ROTL64
#define SHA3_ROTL64(x, y) \
	(((x) << (y)) | ((x) >> ((sizeof(uint64_t)*8) - (y))))
#endif

static const uint64_t keccakf_rndc[24] = {
	SHA3_CONST(0x0000000000000001UL), SHA3_CONST(0x0000000000008082UL),
	SHA3_CONST(0x800000000000808aUL), SHA3_CONST(0x8000000080008000UL),
	SHA3_CONST(0x000000000000808bUL), SHA3_CONST(0x0000000080000001UL),
	SHA3_CONST(0x8000000080008081UL), SHA3_CONST(0x8000000000008009UL),
	SHA3_CONST(0x000000000000008aUL), SHA3_CONST(0x0000000000000088UL),
	SHA3_CONST(0x0000000080008009UL), SHA3_CONST(0x000000008000000aUL),
	SHA3_CONST(0x000000008000808bUL), SHA3_CONST(0x800000000000008bUL),
	SHA3_CONST(0x8000000000008089UL), SHA3_CONST(0x8000000000008003UL),
	SHA3_CONST(0x8000000000008002UL), SHA3_CONST(0x8000000000000080UL),
	SHA3_CONST(0x000000000000800aUL), SHA3_CONST(0x800000008000000aUL),
	SHA3_CONST(0x8000000080008081UL), SHA3_CONST(0x8000000000008080UL),
	SHA3_CONST(0x0000000080000001UL), SHA3_CONST(0x8000000080008008UL)
};

static const unsigned keccakf_rotc[24] = {
	1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62,
	18, 39, 61, 20, 44
};

static const unsigned keccakf_piln[24] = {
	10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20,
	14, 22, 9, 6, 1
};

/* generally called after SHA3_KECCAK_SPONGE_WORDS-ctx->capacityWords words
 * are XORed into the state s
 */
static void ATTR_UNSIGNED_WRAPS
keccakf(uint64_t s[25])
{
	int i, j, round;
	uint64_t t, bc[5];
#define KECCAK_ROUNDS 24

	for(round = 0; round < KECCAK_ROUNDS; round++) {

		/* Theta */
		for(i = 0; i < 5; i++)
			bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];

		for(i = 0; i < 5; i++) {
			t = bc[(i + 4) % 5] ^ SHA3_ROTL64(bc[(i + 1) % 5], 1);
			for(j = 0; j < 25; j += 5)
				s[j + i] ^= t;
		}

		/* Rho Pi */
		t = s[1];
		for(i = 0; i < 24; i++) {
			j = keccakf_piln[i];
			bc[0] = s[j];
			s[j] = SHA3_ROTL64(t, keccakf_rotc[i]);
			t = bc[0];
		}

		/* Chi */
		for(j = 0; j < 25; j += 5) {
			for(i = 0; i < 5; i++)
				bc[i] = s[j + i];
			for(i = 0; i < 5; i++)
				s[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
		}

		/* Iota */
		s[0] ^= keccakf_rndc[round];
	}
}

/* *************************** Public Interface ************************ */

void sha3_256_init(void *context)
{
	struct sha3_ctx *ctx = context;
	i_zero(ctx);
	ctx->capacityWords = 2 * 256 / (8 * sizeof(uint64_t));
}

void sha3_512_init(void *context)
{
	struct sha3_ctx *ctx = context;
	i_zero(ctx);
	ctx->capacityWords = 2 * 512 / (8 * sizeof(uint64_t));
}

void sha3_loop(void *context, const void *data, size_t len)
{
	struct sha3_ctx *ctx = context;
	/* 0...7 -- how much is needed to have a word */
	unsigned old_tail = (8 - ctx->byteIndex) & 7;

	size_t words;
	unsigned tail;
	size_t i;

	const uint8_t *buf = data;

	i_assert(ctx->byteIndex < 8);
	i_assert(ctx->wordIndex < sizeof(ctx->s) / sizeof(ctx->s[0]));

	if(len < old_tail) { /* have no complete word or haven't started
			      * the word yet */
		/* endian-independent code follows: */
		while (len > 0) {
			len--;
			ctx->saved |= (uint64_t) (*(buf++)) <<
					((ctx->byteIndex++) * 8);
		}
		i_assert(ctx->byteIndex < 8);
		return;
	}

	if(old_tail != 0) { /* will have one word to process */
		/* endian-independent code follows: */
		len -= old_tail;
		while (old_tail > 0) {
			old_tail--;
			ctx->saved |= (uint64_t) (*(buf++)) <<
				((ctx->byteIndex++) * 8);
		}

		/* now ready to add saved to the sponge */
		ctx->s[ctx->wordIndex] ^= ctx->saved;
		i_assert(ctx->byteIndex == 8);
		ctx->byteIndex = 0;
		ctx->saved = 0;
		if(++ctx->wordIndex ==
				(SHA3_KECCAK_SPONGE_WORDS -
				ctx->capacityWords)) {
			keccakf(ctx->s);
			ctx->wordIndex = 0;
		}
	}

	/* now work in full words directly from input */

	i_assert(ctx->byteIndex == 0);

	words = len / sizeof(uint64_t);
	tail = len - words * sizeof(uint64_t);

	for(i = 0; i < words; i++, buf += sizeof(uint64_t)) {
		const uint64_t t = (uint64_t) (buf[0]) |
				((uint64_t) (buf[1]) << 8 * 1) |
				((uint64_t) (buf[2]) << 8 * 2) |
				((uint64_t) (buf[3]) << 8 * 3) |
				((uint64_t) (buf[4]) << 8 * 4) |
				((uint64_t) (buf[5]) << 8 * 5) |
				((uint64_t) (buf[6]) << 8 * 6) |
				((uint64_t) (buf[7]) << 8 * 7);
#if defined(__x86_64__ ) || defined(__i386__)
		i_assert(memcmp(&t, buf, 8) == 0);
#endif
		ctx->s[ctx->wordIndex] ^= t;
		if(++ctx->wordIndex ==
				(SHA3_KECCAK_SPONGE_WORDS - ctx->capacityWords)) {
			keccakf(ctx->s);
			ctx->wordIndex = 0;
		}
	}

	/* finally, save the partial word */
	i_assert(ctx->byteIndex == 0 && tail < 8);
	while (tail > 0) {
		tail--;
		ctx->saved |= (uint64_t) (*(buf++)) << ((ctx->byteIndex++) * 8);
	}
	i_assert(ctx->byteIndex < 8);
}

/* This is simply the 'update' with the padding block.
 * The padding block is 0x01 || 0x00* || 0x80. First 0x01 and last 0x80
 * bytes are always present, but they can be the same byte.
 */
static void
sha3_finalize(struct sha3_ctx *ctx)
{
	/* Append 2-bit suffix 01, per SHA-3 spec. Instead of 1 for padding we
	 * use 1<<2 below. The 0x02 below corresponds to the suffix 01.
	 * Overall, we feed 0, then 1, and finally 1 to start padding. Without
	 * M || 01, we would simply use 1 to start padding. */

	/* SHA3 version */
	ctx->s[ctx->wordIndex] ^=
			(ctx->saved ^ ((uint64_t) ((uint64_t) (0x02 | (1 << 2)) <<
							((ctx->byteIndex) * 8))));

	ctx->s[SHA3_KECCAK_SPONGE_WORDS - ctx->capacityWords - 1] ^=
			SHA3_CONST(0x8000000000000000UL);
	keccakf(ctx->s);

#ifdef WORDS_BIGENDIAN
	{
		unsigned i;
		for(i = 0; i < SHA3_KECCAK_SPONGE_WORDS; i++) {
			const unsigned t1 = (uint32_t) ctx->s[i];
			const unsigned t2 = (uint32_t) ((ctx->s[i] >> 16) >> 16);
			ctx->sb[i * 8 + 0] = (uint8_t) (t1);
			ctx->sb[i * 8 + 1] = (uint8_t) (t1 >> 8);
			ctx->sb[i * 8 + 2] = (uint8_t) (t1 >> 16);
			ctx->sb[i * 8 + 3] = (uint8_t) (t1 >> 24);
			ctx->sb[i * 8 + 4] = (uint8_t) (t2);
			ctx->sb[i * 8 + 5] = (uint8_t) (t2 >> 8);
			ctx->sb[i * 8 + 6] = (uint8_t) (t2 >> 16);
			ctx->sb[i * 8 + 7] = (uint8_t) (t2 >> 24);
		}
	}
#endif
}

void sha3_256_result(void *context,
		     unsigned char digest[STATIC_ARRAY SHA256_RESULTLEN])
{
	struct sha3_ctx *ctx = context;
	sha3_finalize(ctx);
	memcpy(digest, ctx->sb, SHA256_RESULTLEN);
}


void sha3_512_result(void *context,
		     unsigned char digest[STATIC_ARRAY SHA512_RESULTLEN])
{
	struct sha3_ctx *ctx = context;
	sha3_finalize(ctx);
	memcpy(digest, ctx->sb, SHA512_RESULTLEN);
}


void sha3_256_get_digest(const void *data, size_t size,
			 unsigned char digest[STATIC_ARRAY SHA256_RESULTLEN])
{
	struct sha3_ctx ctx;
	sha3_256_init(&ctx);
	sha3_loop(&ctx, data, size);
	sha3_256_result(&ctx, digest);
}

void sha3_512_get_digest(const void *data, size_t size,
			 unsigned char digest[STATIC_ARRAY SHA512_RESULTLEN])
{
	struct sha3_ctx ctx;
	sha3_512_init(&ctx);
	sha3_loop(&ctx, data, size);
	sha3_512_result(&ctx, digest);
}

static void hash_method_init_sha3_256(void *context)
{
	sha3_256_init(context);
}

static void hash_method_loop_sha3(void *context, const void *data, size_t size)
{
	sha3_loop(context, data, size);
}

static void hash_method_result_sha3_256(void *context, unsigned char *result_r)
{
	sha3_256_result(context, result_r);
}

const struct hash_method hash_method_sha3_256 = {
	.name = "sha3-256",
	.block_size = SHA256_BLOCK_SIZE,
	.context_size = sizeof(struct sha3_ctx),
	.digest_size = SHA256_RESULTLEN,

	.init = hash_method_init_sha3_256,
	.loop = hash_method_loop_sha3,
	.result = hash_method_result_sha3_256,
};

static void hash_method_init_sha3_512(void *context)
{
	sha3_512_init(context);
}

static void hash_method_result_sha3_512(void *context, unsigned char *result_r)
{
	sha3_512_result(context, result_r);
}

const struct hash_method hash_method_sha3_512 = {
	.name = "sha3-512",
	.block_size = SHA512_BLOCK_SIZE,
	.context_size = sizeof(struct sha3_ctx),
	.digest_size = SHA512_RESULTLEN,

	.init = hash_method_init_sha3_512,
	.loop = hash_method_loop_sha3,
	.result = hash_method_result_sha3_512,
};
