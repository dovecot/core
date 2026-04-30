/* Copyright (c) 2026 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "bitmap.h"

void bitmap_init(struct bitmap *bitmap, pool_t pool, unsigned int n_bits)
{
	bitmap->n_bits = n_bits;
	bitmap->n_words = (n_bits + 63) / 64;
	bitmap->words = bitmap->n_words == 0 ? NULL :
		p_new(pool, uint64_t, bitmap->n_words);
}

void t_bitmap_init(struct bitmap *bitmap, unsigned int n_bits)
{
	bitmap->n_bits = n_bits;
	bitmap->n_words = (n_bits + 63) / 64;
	bitmap->words = bitmap->n_words == 0 ? NULL :
		t_new(uint64_t, bitmap->n_words);
}

void bitmap_reset_all(struct bitmap *bitmap)
{
	if (bitmap->n_words > 0) {
		memset(bitmap->words, 0,
		       bitmap->n_words * sizeof(*bitmap->words));
	}
}

void bitmap_swap(struct bitmap *a, struct bitmap *b)
{
	i_assert(a->n_bits == b->n_bits);

	struct bitmap tmp = *a;
	*a = *b;
	*b = tmp;
}
