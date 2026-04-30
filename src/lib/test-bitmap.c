/* Copyright (c) 2026 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "bitmap.h"

static void test_bitmap_basic(void)
{
	struct bitmap b;

	test_begin("bitmap basic set/get/unset");

	bitmap_init(&b, default_pool, 200);
	test_assert(b.n_bits == 200);
	test_assert(b.n_words == 4);

	for (unsigned int i = 0; i < b.n_bits; i++)
		test_assert_idx(!bitmap_get(&b, i), i);

	bitmap_set(&b, 0);
	bitmap_set(&b, 63);
	bitmap_set(&b, 64);
	bitmap_set(&b, 199);

	test_assert(bitmap_get(&b, 0));
	test_assert(bitmap_get(&b, 63));
	test_assert(bitmap_get(&b, 64));
	test_assert(bitmap_get(&b, 199));
	test_assert(!bitmap_get(&b, 1));
	test_assert(!bitmap_get(&b, 62));
	test_assert(!bitmap_get(&b, 65));
	test_assert(!bitmap_get(&b, 198));

	bitmap_unset(&b, 63);
	test_assert(!bitmap_get(&b, 63));
	test_assert(bitmap_get(&b, 64));
	test_assert(bitmap_get(&b, 0));

	bitmap_reset_all(&b);
	for (unsigned int i = 0; i < b.n_bits; i++)
		test_assert_idx(!bitmap_get(&b, i), i);

	p_free(default_pool, b.words);
	test_end();
}

static void test_bitmap_zero(void)
{
	struct bitmap b;

	test_begin("bitmap zero size");

	bitmap_init(&b, default_pool, 0);
	test_assert(b.n_bits == 0);
	test_assert(b.n_words == 0);
	test_assert(b.words == NULL);
	bitmap_reset_all(&b);

	test_end();
}

static void test_bitmap_swap(void)
{
	struct bitmap a, c;

	test_begin("bitmap_swap");

	bitmap_init(&a, default_pool, 128);
	bitmap_init(&c, default_pool, 128);

	bitmap_set(&a, 1);
	bitmap_set(&a, 100);
	bitmap_set(&c, 2);
	bitmap_set(&c, 64);

	uint64_t *a_words = a.words;
	uint64_t *c_words = c.words;
	bitmap_swap(&a, &c);
	test_assert(a.words == c_words);
	test_assert(c.words == a_words);
	test_assert(bitmap_get(&a, 2));
	test_assert(bitmap_get(&a, 64));
	test_assert(!bitmap_get(&a, 1));
	test_assert(bitmap_get(&c, 1));
	test_assert(bitmap_get(&c, 100));
	test_assert(!bitmap_get(&c, 2));

	p_free(default_pool, a.words);
	p_free(default_pool, c.words);
	test_end();
}

static void test_t_bitmap_init(void)
{
	test_begin("t_bitmap_init");

	T_BEGIN {
		struct bitmap b;
		t_bitmap_init(&b, 100);
		test_assert(b.n_bits == 100);
		test_assert(b.n_words == 2);
		bitmap_set(&b, 99);
		test_assert(bitmap_get(&b, 99));
		test_assert(!bitmap_get(&b, 0));
	} T_END;

	test_end();
}

void test_bitmap(void)
{
	test_bitmap_basic();
	test_bitmap_zero();
	test_bitmap_swap();
	test_t_bitmap_init();
}
