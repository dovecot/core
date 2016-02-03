/* Copyright (c) 2001-2016 Dovecot authors, see the included COPYING file */

/* Unit tests for bit twiddles library */

#include "test-lib.h"

#include <stdio.h>

/* nearest_power(0) = error      bits_requiredXX(0) = 0
   nearest_power(1) = 1 = 1<<0   bits_requiredXX(1) = 1
   nearest_power(2) = 2 = 1<<1   bits_requiredXX(2) = 2
   nearest_power(3) = 4 = 1<<2   bits_requiredXX(3) = 2
   nearest_power(4) = 4	= 1<<2   bits_requiredXX(4) = 3
   nearest_power(5) = 8 = 1<<3   bits_requiredXX(5) = 3
   nearest_power(7) = 8 = 1<<3   bits_requiredXX(7) = 3
   nearest_power(8) = 8 = 1<<3   bits_requiredXX(8) = 4
*/

/* nearest_power(num) == 1ULL << bits_required64(num-1) */
static void test_nearest_power(void) 
{
	unsigned int b;
	size_t num;
	test_begin("nearest_power()");
	test_assert(nearest_power(1)==1);
	test_assert(nearest_power(2)==2);
	for (b = 2; b < CHAR_BIT*sizeof(size_t) - 1; ++b) {
		/* b=2 tests 3,4,5; b=3 tests 7,8,9; ... b=30 tests ~1G */
		num = (size_t)1 << b;
		test_assert_idx(nearest_power(num-1) == num,    b);
		test_assert_idx(nearest_power(num  ) == num,    b);
		test_assert_idx(nearest_power(num+1) == num<<1, b);
	}
	/* With 32-bit size_t, now: b=31 tests 2G-1, 2G, not 2G+1. */
	num = (size_t)1 << b;
	test_assert_idx(nearest_power(num-1) == num,    b);
	test_assert_idx(nearest_power(num  ) == num,    b);
	/* i_assert()s: test_assert_idx(nearest_power(num+1) == num<<1, b); */
	test_end();
}

static void test_bits_requiredXX(void) 
{
	/* As ..64 depends on ..32 and tests it twice,
	 * and ..32 depends on ..16 and tests it twice,
	 * etc., we only test ..64
	 */
	unsigned int b;
	test_begin("bits_requiredXX()");
	test_assert(bits_required64(0) == 0);
	test_assert(bits_required64(1) == 1);
	test_assert(bits_required64(2) == 2);
	for (b = 2; b < 64; ++b) {
		/* b=2 tests 3,4,5; b=3 tests 7,8,9; ... */
		uint64_t num = 1ULL << b;
		test_assert_idx(bits_required64(num-1) == b,   b);
		test_assert_idx(bits_required64(num  ) == b+1, b);
		test_assert_idx(bits_required64(num+1) == b+1, b);
	}
	test_end();
}

static void test_sum_overflows(void)
{
#define MAX64 (uint64_t)-1
	static const struct {
		uint64_t a, b;
		bool overflows;
	} tests[] = {
		{ MAX64-1, 1, FALSE },
		{ MAX64, 1, TRUE },
		{ MAX64-1, 1, FALSE },
		{ MAX64-1, 2, TRUE },
		{ MAX64-1, MAX64-1, TRUE },
		{ MAX64-1, MAX64, TRUE },
		{ MAX64, MAX64, TRUE }
	};
	unsigned int i;

	test_begin("UINT64_SUM_OVERFLOWS");
	for (i = 0; i < N_ELEMENTS(tests); i++)
		test_assert(UINT64_SUM_OVERFLOWS(tests[i].a, tests[i].b) == tests[i].overflows);
	test_end();
}

static void test_bits_fraclog(void)
{
	unsigned int fracbits;
	for (fracbits = 0; fracbits < 6; fracbits++) {
		static char name[] = "fraclog x-bit";
		name[8] = '0'+ fracbits;
		test_begin(name);

		unsigned int i;
		unsigned int last_end = ~0u;
		for (i = 0; i < BITS_FRACLOG_BUCKETS(fracbits); i++) {
			unsigned int start = bits_fraclog_bucket_start(i, fracbits);
			unsigned int end = bits_fraclog_bucket_end(i, fracbits);
			test_assert_idx(start == last_end + 1, i);
			last_end = end;
			test_assert_idx(bits_fraclog(start, fracbits) == i, i);
			test_assert_idx(bits_fraclog(end, fracbits) == i, i);
		}
		test_assert_idx(last_end == ~0u, fracbits);

		test_end();
	}
}

void test_bits(void)
{
	test_nearest_power();
	test_bits_requiredXX();
	test_bits_fraclog();
	test_sum_overflows();
}
