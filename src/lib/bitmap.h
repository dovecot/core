#ifndef BITMAP_H
#define BITMAP_H

#include "bits.h"

/* Fixed-size bit set sized at creation time. The size does not grow.
   The underlying storage is a uint64_t word array, so per-word bulk
   operations like memset() and pointer-swap are valid. */
struct bitmap {
	uint64_t *words;
	unsigned int n_bits;
	unsigned int n_words;
};

/* Initialize bitmap with all bits cleared, allocated from pool. */
void bitmap_init(struct bitmap *bitmap, pool_t pool, unsigned int n_bits);
/* Same, but allocated from the data stack via t_new(). */
void t_bitmap_init(struct bitmap *bitmap, unsigned int n_bits);

static inline bool bitmap_get(const struct bitmap *bitmap, unsigned int idx)
{
	i_assert(idx < bitmap->n_bits);
	return bit64_get(bitmap->words, idx);
}

static inline void bitmap_set(struct bitmap *bitmap, unsigned int idx)
{
	i_assert(idx < bitmap->n_bits);
	bit64_set(bitmap->words, idx);
}

static inline void bitmap_unset(struct bitmap *bitmap, unsigned int idx)
{
	i_assert(idx < bitmap->n_bits);
	bitmap->words[idx / 64] &= ~(1ULL << (idx % 64));
}

/* Clear all bits. */
void bitmap_reset_all(struct bitmap *bitmap);

/* Swap the contents of two bitmaps in-place. They must have the same
   n_bits. */
void bitmap_swap(struct bitmap *a, struct bitmap *b);

#endif
