#include "lib.h"
#include "bloomfilter.h"
#include "murmurhash3.h"
#include "md5.h"
#include "randgen.h"

#include <math.h>

struct bloomfilter {
	pool_t pool;
	int refcount;
	size_t size;
	size_t total_added;
	unsigned int nk;
	uint32_t seed;

	bloomfilter_hash_func_t *const *k;

	uint8_t *bitmap;
};

#define BITMAP_HAS_BIT(map, idx) (((map)[((idx)/CHAR_BIT)] & (0x1<<((idx)%CHAR_BIT))) != 0)
#define BITMAP_SET_BIT(map, idx) ((map)[((idx)/CHAR_BIT)] |= (0x1<<((idx)%CHAR_BIT)))
#define BLOOMFILTER_HASH_BYTES 16

/* use only murmurhash3 by default */
bloomfilter_hash_func_t *const bloomfilter_default_functions[] = {
	bloomfilter_murmur3_hash,
	NULL
};

static inline size_t
bloomfilter_hash_fold(unsigned char result[STATIC_ARRAY BLOOMFILTER_HASH_BYTES],
		      uint32_t seed)
{
#ifdef _LP64
	/* rolls 128 bit result into a 64 bit result by xoring the first 64 bits
	   and seed, and remaining 64 bits. */
	return be64_to_cpu_unaligned(&result[0]) ^
	       be64_to_cpu_unaligned(&result[8]) ^
	       (((size_t)seed) << 32);
#else
	/* rolls 128 bit result into a 32 bit result by folding
	   all the successive 32 bit values into one together with seed. */
	return be32_to_cpu_unaligned(&result[0]) ^
	       be32_to_cpu_unaligned(&result[4]) ^
	       be32_to_cpu_unaligned(&result[8]) ^
	       be32_to_cpu_unaligned(&result[12]) ^
	       seed;
#endif
}

size_t bloomfilter_murmur3_hash(const void *data, size_t len, uint32_t seed)
{
	unsigned char result[MURMURHASH3_128_RESULTBYTES];
	murmurhash3_128(data, len, seed, result);
	/* murmur includes seed already */
	return bloomfilter_hash_fold(result, 0);
}

size_t bloomfilter_md5_hash(const void *data, size_t len, uint32_t seed)
{
	unsigned char result[MD5_RESULTLEN];
	md5_get_digest(data, len, result);
	return bloomfilter_hash_fold(result, seed);
}

struct bloomfilter *
bloomfilter_create(pool_t pool, size_t size,
		   bloomfilter_hash_func_t *const *hash_functions)
{
	struct bloomfilter *bf = p_new(pool, struct bloomfilter, 1);
	i_assert(size > 0);
	bf->pool = pool;
	/* allocate extra byte to round up result */
	bf->bitmap = p_malloc(pool, size/CHAR_BIT + 1);
	bf->k = hash_functions;
	bf->size = size;
	while(*hash_functions != NULL) {
		bf->nk++;
		hash_functions++;
	}
	i_assert(bf->nk > 0);
	random_fill(&bf->seed, sizeof(bf->seed));
	bf->refcount = 1;
	return bf;
}

void bloomfilter_ref(struct bloomfilter *bf)
{
	i_assert(bf->refcount > 0);
	bf->refcount++;
}

void bloomfilter_unref(struct bloomfilter **_bf)
{
	struct bloomfilter *bf = *_bf;
	if (*_bf == NULL)
		return;
	*_bf = NULL;
	i_assert(bf->refcount > 0);

	if (--bf->refcount > 0)
		return;
	/* in case system pool was used .. */
	p_free(bf->pool, bf->bitmap);
	p_free(bf->pool, bf);
}

size_t bloomfilter_estimated_item_count(struct bloomfilter *bf)
{
	return bf->total_added;
}

bool bloomfilter_has_data(struct bloomfilter *bf, const void *data, size_t len)
{
	i_assert(data != NULL || len == 0);
	bloomfilter_hash_func_t *const *k = bf->k;
	for(;*k != NULL; k++) {
		size_t result;
		result = (*k)(data, len, bf->seed) % bf->size;
		if (!BITMAP_HAS_BIT(bf->bitmap, result))
			return FALSE;
	}
	return TRUE;
}

void bloomfilter_set_data(struct bloomfilter *bf, const void *data, size_t len)
{
	i_assert(data != NULL || len == 0);
	bloomfilter_hash_func_t *const *k = bf->k;
	/* total added will cap at size_t, because it's an estimate */
	if (bf->total_added < (size_t)-1)
		bf->total_added++;
	for(;*k != NULL; k++) {
		size_t result;
		result = (*k)(data, len, bf->seed) % bf->size;
		BITMAP_SET_BIT(bf->bitmap, result);
	}
}
