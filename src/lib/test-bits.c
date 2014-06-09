/* Copyright (c) 2001-2014 Dovecot authors, see the included COPYING file */

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
	test_begin("nearest_power()");
	test_assert(nearest_power(1)==1);
	test_assert(nearest_power(2)==2);
	for (b = 2; b < 63; ++b) {
		/* b=2 tests 3,4,5; b=3 tests 7,8,9; ... */
		uint64_t num = 1ULL << b;
		test_assert_idx(nearest_power(num-1) == num,    b);
		test_assert_idx(nearest_power(num  ) == num,    b);
		test_assert_idx(nearest_power(num+1) == num<<1, b);
	}
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

void test_bits()
{
	test_nearest_power();
	test_bits_requiredXX();
}
