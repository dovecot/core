#ifndef BLOOMFILTER_H
#define BLOOMFILTER_H

#include "buffer.h"

/* Short explanation of bloom filter:

Bloom filter is a space-efficient probabilistic filter. The idea is
that each element that gets added, is hashed thru one or more hashing
functions and the resulting hash modulo table size bit is set.

When seeing if there is an element set, it will check that each
hashing function result modulo table size bit is set. If any of them
is not set, the element is missing. If all of them are set, the
element is probably present.

A bloom filter will never report a false negative, but it might
report a false positive value.

Elements cannot be removed from this bloom filter.
*/

struct bloomfilter;

typedef size_t bloomfilter_hash_func_t(const void *data, size_t len, uint32_t seed);

/* create bloomfilter of size with hash functions */
struct bloomfilter *
bloomfilter_create(pool_t pool, size_t size,
		   bloomfilter_hash_func_t *const *hash_functions) ATTR_RETURNS_NONNULL;

/* Some helpers */
#define p_bloomfilter_create(pool, size) \
	bloomfilter_create(pool, size, bloomfilter_default_functions)
#define i_bloomfilter_create(size) p_bloomfilter_create(default_pool, size)
#define t_bloomfilter_create(size) \
	p_bloomfilter_create(pool_datastack_create(), size)

/* Reference counting */
void bloomfilter_ref(struct bloomfilter *bf);
void bloomfilter_unref(struct bloomfilter **_bf);

/* Returns estimated number of items in this filter */
size_t bloomfilter_estimated_item_count(struct bloomfilter *bf);

/* Returns TRUE if the element is probably in the filter */
bool bloomfilter_has_data(struct bloomfilter *bf, const void *data, size_t len) ATTR_NULL(2);

/* Inserts element into filter */
void bloomfilter_set_data(struct bloomfilter *bf, const void *data, size_t len) ATTR_NULL(2);

static inline bool
bloomfilter_has_string(struct bloomfilter *bf, const char *data)
{
	return bloomfilter_has_data(bf, data, strlen(data));
}

static inline void
bloomfilter_set_string(struct bloomfilter *bf, const char *data)
{
        bloomfilter_set_data(bf, data, strlen(data));
}

static inline void
bloomfilter_set_strings(struct bloomfilter *bf, const char *const *datum)
{
	while(*datum != NULL) {
		bloomfilter_set_data(bf, *datum, strlen(*datum));
		datum++;
	}
}

static inline bool
bloomfilter_has_buffer(struct bloomfilter *bf, const buffer_t *data)
{
	return bloomfilter_has_data(bf, data->data, data->used);
}

static inline void
bloomfilter_set_buffer(struct bloomfilter *bf, const buffer_t *data)
{
        bloomfilter_set_data(bf, data->data, data->used);
}

static inline bool
bloomfilter_has_int(struct bloomfilter *bf, intmax_t value)
{
	return bloomfilter_has_data(bf, &value, sizeof(value));
}

static inline void
bloomfilter_set_int(struct bloomfilter *bf, intmax_t value)
{
        bloomfilter_set_data(bf, &value, sizeof(value));
}

static inline bool
bloomfilter_has_uint(struct bloomfilter *bf, uintmax_t value)
{
	return bloomfilter_has_data(bf, &value, sizeof(value));
}

static inline void
bloomfilter_set_uint(struct bloomfilter *bf, uintmax_t value)
{
        bloomfilter_set_data(bf, &value, sizeof(value));
}

size_t
bloomfilter_murmur3_hash(const void *data, size_t len, uint32_t seed) ATTR_PURE;
size_t
bloomfilter_md5_hash(const void *data, size_t len, uint32_t seed) ATTR_PURE;

/* By default, only murmur3 is used. */
extern bloomfilter_hash_func_t *const bloomfilter_default_functions[];

#endif
