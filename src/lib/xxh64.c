/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

/* XXHash64 - Fast non-cryptographic hash function.
 * Based on Yann Collet's public domain XXHash64 algorithm.
 * Reference: https://github.com/Cyan4973/xxHash/blob/dev/doc/xxhash_spec.md
 */

#include "lib.h"
#include "xxh64.h"

#define XXH64_PRIME1  UINT64_C(0x9E3779B185EBCA87)
#define XXH64_PRIME2  UINT64_C(0xC2B2AE3D27D4EB4F)
#define XXH64_PRIME3  UINT64_C(0x165667B19E3779F9)
#define XXH64_PRIME4  UINT64_C(0x85EBCA77C2B27589)
#define XXH64_PRIME5  UINT64_C(0x27D4EB2F165667C5)

#define XXH64_ROTL(x, r) (((x) << (r)) | ((x) >> (64 - (r))))

static inline uint64_t xxh64_read64(const void *p)
{
	uint64_t v;
	memcpy(&v, p, sizeof(v));
	return v;
}

static inline uint32_t xxh64_read32(const void *p)
{
	uint32_t v;
	memcpy(&v, p, sizeof(v));
	return v;
}

static uint64_t ATTR_UNSIGNED_WRAPS xxh64_round(uint64_t acc, uint64_t input)
{
	acc += input * XXH64_PRIME2;
	acc = XXH64_ROTL(acc, 31);
	acc *= XXH64_PRIME1;
	return acc;
}

static uint64_t ATTR_UNSIGNED_WRAPS xxh64_merge_acc(uint64_t h64, uint64_t acc)
{
	acc = xxh64_round(0, acc);
	h64 ^= acc;
	h64 = h64 * XXH64_PRIME1 + XXH64_PRIME4;
	return h64;
}

void ATTR_UNSIGNED_WRAPS xxh64_init(struct xxh64_context *ctx, uint64_t seed)
{
	ctx->seed = seed;
	ctx->v1 = seed + XXH64_PRIME1 + XXH64_PRIME2;
	ctx->v2 = seed + XXH64_PRIME2;
	ctx->v3 = seed;
	ctx->v4 = seed - XXH64_PRIME1;
	ctx->total_len = 0;
	ctx->buf_used = 0;
}

void ATTR_UNSIGNED_WRAPS xxh64_loop(struct xxh64_context *ctx, const void *data, size_t size)
{
	const unsigned char *p = data;
	const unsigned char *end = p + size;

	ctx->total_len += size;

	if (ctx->buf_used + size < 32) {
		memcpy(ctx->buf + ctx->buf_used, p, size);
		ctx->buf_used += size;
		return;
	}

	if (ctx->buf_used > 0) {
		size_t fill = 32 - ctx->buf_used;
		memcpy(ctx->buf + ctx->buf_used, p, fill);
		p += fill;
		ctx->v1 = xxh64_round(ctx->v1, xxh64_read64(ctx->buf));
		ctx->v2 = xxh64_round(ctx->v2, xxh64_read64(ctx->buf + 8));
		ctx->v3 = xxh64_round(ctx->v3, xxh64_read64(ctx->buf + 16));
		ctx->v4 = xxh64_round(ctx->v4, xxh64_read64(ctx->buf + 24));
		ctx->buf_used = 0;
	}

	while (p + 32 <= end) {
		ctx->v1 = xxh64_round(ctx->v1, xxh64_read64(p));
		ctx->v2 = xxh64_round(ctx->v2, xxh64_read64(p + 8));
		ctx->v3 = xxh64_round(ctx->v3, xxh64_read64(p + 16));
		ctx->v4 = xxh64_round(ctx->v4, xxh64_read64(p + 24));
		p += 32;
	}

	if (p < end) {
		ctx->buf_used = (unsigned int)(end - p);
		memcpy(ctx->buf, p, ctx->buf_used);
	}
}

uint64_t ATTR_UNSIGNED_WRAPS xxh64_result(struct xxh64_context *ctx)
{
	const unsigned char *p = ctx->buf;
	const unsigned char *end = p + ctx->buf_used;
	uint64_t h64;

	if (ctx->total_len >= 32) {
		h64 = XXH64_ROTL(ctx->v1,  1) + XXH64_ROTL(ctx->v2,  7) +
		      XXH64_ROTL(ctx->v3, 12) + XXH64_ROTL(ctx->v4, 18);
		h64 = xxh64_merge_acc(h64, ctx->v1);
		h64 = xxh64_merge_acc(h64, ctx->v2);
		h64 = xxh64_merge_acc(h64, ctx->v3);
		h64 = xxh64_merge_acc(h64, ctx->v4);
	} else {
		h64 = ctx->seed + XXH64_PRIME5;
	}

	h64 += ctx->total_len;

	while (p + 8 <= end) {
		h64 ^= xxh64_round(0, xxh64_read64(p));
		h64 = XXH64_ROTL(h64, 27) * XXH64_PRIME1 + XXH64_PRIME4;
		p += 8;
	}
	if (p + 4 <= end) {
		h64 ^= (uint64_t)xxh64_read32(p) * XXH64_PRIME1;
		h64 = XXH64_ROTL(h64, 23) * XXH64_PRIME2 + XXH64_PRIME3;
		p += 4;
	}
	while (p < end) {
		h64 ^= (uint64_t)*p * XXH64_PRIME5;
		h64 = XXH64_ROTL(h64, 11) * XXH64_PRIME1;
		p++;
	}

	/* Avalanche */
	h64 ^= h64 >> 33;
	h64 *= XXH64_PRIME2;
	h64 ^= h64 >> 29;
	h64 *= XXH64_PRIME3;
	h64 ^= h64 >> 32;

	return h64;
}

uint64_t xxh64_data(const void *data, size_t size, uint64_t seed)
{
	struct xxh64_context ctx;

	xxh64_init(&ctx, seed);
	xxh64_loop(&ctx, data, size);
	return xxh64_result(&ctx);
}

static void xxh64_hash_init(void *context)
{
	xxh64_init(context, 0);
}

static void xxh64_hash_loop(void *context, const void *data, size_t size)
{
	xxh64_loop(context, data, size);
}

static void xxh64_hash_result(void *context, unsigned char *digest_r)
{
	uint64_t hash = xxh64_result(context);

	digest_r[0] = (hash >> 56) & 0xff;
	digest_r[1] = (hash >> 48) & 0xff;
	digest_r[2] = (hash >> 40) & 0xff;
	digest_r[3] = (hash >> 32) & 0xff;
	digest_r[4] = (hash >> 24) & 0xff;
	digest_r[5] = (hash >> 16) & 0xff;
	digest_r[6] = (hash >>  8) & 0xff;
	digest_r[7] = (hash >>  0) & 0xff;
}

const struct hash_method hash_method_xxh64 = {
	.name = "xxh64",
	.block_size = 32,
	.context_size = sizeof(struct xxh64_context),
	.digest_size = XXH64_RESULTLEN,
	.init = xxh64_hash_init,
	.loop = xxh64_hash_loop,
	.result = xxh64_hash_result,
};
