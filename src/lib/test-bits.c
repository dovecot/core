/* Copyright (c) 2001-2018 Dovecot authors, see the included COPYING file */

/* Unit tests for bit twiddles library */

#include "test-lib.h"

#include <stdio.h>

static void test_bits_unsigned_minus(void)
{
	test_begin("bits_unsigned_minus()");

	// 32 bit
	test_assert(UNSIGNED_MINUS(0x00000000U) == 0x00000000U);

	test_assert(UNSIGNED_MINUS(0x00000001U) == 0xffffffffU);
	test_assert(UNSIGNED_MINUS(0x00000002U) == 0xfffffffeU);
	test_assert(UNSIGNED_MINUS(0x00000003U) == 0xfffffffdU);
	//..
	test_assert(UNSIGNED_MINUS(0x7fffffffU) == 0x80000001U);
	test_assert(UNSIGNED_MINUS(0x80000000U) == 0x80000000U);
	test_assert(UNSIGNED_MINUS(0x80000001U) == 0x7fffffffU);
	//..
	test_assert(UNSIGNED_MINUS(0xffffffffU) == 0x00000001U);
	test_assert(UNSIGNED_MINUS(0xfffffffeU) == 0x00000002U);
	test_assert(UNSIGNED_MINUS(0xfffffffdU) == 0x00000003U);

	// 64 bit
	test_assert(UNSIGNED_MINUS(0x0000000000000000ULL) == 0x0000000000000000ULL);

	test_assert(UNSIGNED_MINUS(0x0000000000000001ULL) == 0xffffffffffffffffULL);
	test_assert(UNSIGNED_MINUS(0x0000000000000002ULL) == 0xfffffffffffffffeULL);
	test_assert(UNSIGNED_MINUS(0x0000000000000003ULL) == 0xfffffffffffffffdULL);
	//..
	test_assert(UNSIGNED_MINUS(0x7fffffffffffffffULL) == 0x8000000000000001ULL);
	test_assert(UNSIGNED_MINUS(0x8000000000000000ULL) == 0x8000000000000000ULL);
	test_assert(UNSIGNED_MINUS(0x8000000000000001ULL) == 0x7fffffffffffffffULL);
	//..
	test_assert(UNSIGNED_MINUS(0xffffffffffffffffULL) == 0x0000000000000001ULL);
	test_assert(UNSIGNED_MINUS(0xfffffffffffffffeULL) == 0x0000000000000002ULL);
	test_assert(UNSIGNED_MINUS(0xfffffffffffffffdULL) == 0x0000000000000003ULL);

	test_end();
}


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

static void test_bits_is_power_of_two(void)
{
	test_begin("bits_is_power_of_two()");
	for (unsigned int i = 0; i < 64; i++)
		test_assert_idx(bits_is_power_of_two(1ULL << i), i);
	for (unsigned int i = 2; i < 64; i++) {
		test_assert_idx(!bits_is_power_of_two((1ULL << i) - 1), i);
		test_assert_idx(!bits_is_power_of_two((1ULL << i) + 1), i);
	}
	test_assert(!bits_is_power_of_two(0));
	test_assert(!bits_is_power_of_two(0xffffffffffffffffULL));
	test_assert( bits_is_power_of_two(0x8000000000000000ULL));
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

static void ATTR_NO_SANITIZE_INTEGER ATTR_NO_SANITIZE_IMPLICIT_CONVERSION
test_bits_fraclog(void)
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

/* The compiler *should* generate different code when the fracbits parameter
   is a compile-time constant, so we also need to check that's the case.
*/
static void ATTR_NO_SANITIZE_INTEGER ATTR_NO_SANITIZE_IMPLICIT_CONVERSION
test_bits_fraclog_const(void)
{
#define FRACBITS 2
#define STR2(s) #s
#define STR(s) STR2(s)
	test_begin("fraclog constant " STR(FRACBITS) " bit");

	unsigned int i;
	unsigned int last_end = ~0u;
	for (i = 0; i < BITS_FRACLOG_BUCKETS(FRACBITS); i++) {
		unsigned int start = bits_fraclog_bucket_start(i, FRACBITS);
		unsigned int end = bits_fraclog_bucket_end(i, FRACBITS);
		test_assert_idx(start == last_end + 1, i);
		last_end = end;
		test_assert_idx(bits_fraclog(start, FRACBITS) == i, i);
		test_assert_idx(bits_fraclog(end, FRACBITS) == i, i);
	}
	test_assert(last_end == ~0u);

	test_end();
}

static void test_bits_rotl32(void)
{
	test_begin("bits_rotl32");

	test_assert(bits_rotl32(0x1c00000eU, 3) == 0xe0000070U);
	test_assert(bits_rotl32(0xe0000070U, 5) == 0x00000e1cU);
	test_assert(bits_rotl32(0x00000e1cU, 0) == 0x00000e1cU);
	test_assert(bits_rotl32(0x1c00000eU, 3 + 32) == 0xe0000070U);

	test_end();
}

static void test_bits_rotl64(void)
{
	test_begin("bits_rotl64");

        test_assert(bits_rotl64(0x1c0000000000000eUL, 3) == 0xe000000000000070UL);
        test_assert(bits_rotl64(0xe000000000000070UL, 5) == 0x0000000000000e1cUL);
        test_assert(bits_rotl64(0x0000000000000e1cUL, 0) == 0x0000000000000e1cUL);
        test_assert(bits_rotl64(0x1c0000000000000eUL, 3 + 64) == 0xe000000000000070UL);

	test_end();
}

static void test_bits_rotr32(void)
{
	test_begin("bits_rotr32");

	test_assert(bits_rotr32(0x1c00000eU, 3) == 0xc3800001U);
	test_assert(bits_rotr32(0xc3800001U, 5) == 0x0e1c0000U);
	test_assert(bits_rotr32(0x00000e1cU, 0) == 0x00000e1cU);
	test_assert(bits_rotr32(0x1c00000eU, 3 + 32) == 0xc3800001U);

	test_end();
}

static void test_bits_rotr64(void)
{
	test_begin("bits_rotr64");

	test_assert(bits_rotr64(0x1c0000000000000eUL, 3) == 0xc380000000000001UL);
	test_assert(bits_rotr64(0xc380000000000001UL, 5) == 0x0e1c000000000000UL);
	test_assert(bits_rotr64(0x0000000000000e1cUL, 0) == 0x0000000000000e1cUL);
	test_assert(bits_rotr64(0x1c0000000000000eUL, 3 + 64) == 0xc380000000000001UL);

	test_end();
}

static void test_bit_tests(void)
{
	test_begin("HAS_..._BITS() macro tests");

	test_assert(HAS_NO_BITS(1,0));
	test_assert(HAS_NO_BITS(2,~2U));
	test_assert(!HAS_NO_BITS(2,2));

	/* OUCH - this vacuously true expression fails. However, if you are
	   dumb enough to use 0 as bits, then it will also fail in the verbose
	   case that this macro replaces, it's not a regression. */
	/* test_assert(HAS_ANY_BITS(6,0)); */
	test_assert(HAS_ANY_BITS(3,1));
	test_assert(HAS_ANY_BITS(2,3));
	test_assert(!HAS_ANY_BITS(7,~(7U|128U)));

	test_assert(HAS_ALL_BITS(0,0));
	test_assert(HAS_ALL_BITS(30,14));
	test_assert(!HAS_ALL_BITS(~1U,~0U));

	/* Trap double-evaluation */
	unsigned int v=10,b=2;
	test_assert(!HAS_NO_BITS(v++, b++) && v==11 && b==3);
	test_assert(HAS_ANY_BITS(v++, b++) && v==12 && b==4);
	test_assert(HAS_ALL_BITS(v++, b++) && v==13 && b==5);

	test_end();
}

void test_bits(void)
{
	test_bits_unsigned_minus();
	test_nearest_power();
	test_bits_is_power_of_two();
	test_bits_requiredXX();
	test_bits_fraclog();
	test_bits_fraclog_const();
	test_bits_rotl32();
	test_bits_rotr32();
	test_bits_rotl64();
	test_bits_rotr64();
	test_sum_overflows();
	test_bit_tests();
}
