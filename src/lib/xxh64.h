#ifndef XXH64_H
#define XXH64_H

#include "hash-method.h"

#define XXH64_RESULTLEN 8

struct xxh64_context {
	uint64_t seed;
	uint64_t v1, v2, v3, v4;
	uint64_t total_len;
	unsigned char buf[32];
	unsigned int buf_used;
};

void xxh64_init(struct xxh64_context *ctx, uint64_t seed);
void xxh64_loop(struct xxh64_context *ctx, const void *data, size_t size);
uint64_t xxh64_result(struct xxh64_context *ctx);

uint64_t xxh64_data(const void *data, size_t size, uint64_t seed) ATTR_PURE;

/* XOR-fold the 64-bit hash to 32 bits */
static inline uint32_t xxh64_to_32(uint64_t hash)
{
	return (uint32_t)(hash ^ (hash >> 32));
}

extern const struct hash_method hash_method_xxh64;

#endif
