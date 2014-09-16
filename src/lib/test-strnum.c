/* Copyright (c) 2014-2014 Dovecot authors, see the included COPYING file */

#include "test-lib.h"

#include <stdlib.h>

#define INVALID(n) { #n, -1, 0 }
#define VALID(n) { #n, 0, n }

static void test_str_to_u64(void)
{
	unsigned int i;
	const struct {
		const char *input;
		int ret;
		uint64_t val;
	} u64tests[] = {
		INVALID(-1),
		INVALID(foo),
		VALID(0),
		VALID(000000000000000000000000000000000000000000000000000000000000000),
		{ "000000000000000000000000000000000000000000000000000001000000001", 0, 1000000001 },
		{ "18446744073709551615", 0, 18446744073709551615ULL },
		INVALID(18446744073709551616),
		INVALID(20496382304121724010), /* 2^64*10/9 doesn't wrap */
		INVALID(20496382304121724017), /* 2^64*10/9 wraps only after addition */
		INVALID(20496382304121724020), /* 2^64*10/9 wraps on multiply*/
	};
	test_begin("str_to_uint64");
	for (i = 0; i < N_ELEMENTS(u64tests); ++i) {
		uint64_t val = 0xBADBEEF15BADF00D;
		int ret = str_to_uint64(u64tests[i].input, &val);
		test_assert_idx(ret == u64tests[i].ret, i);
		if (ret == 0)
			test_assert_idx(val == u64tests[i].val, i);
		else
			test_assert_idx(val == 0xBADBEEF15BADF00D, i);

		if (ret == 0)
			T_BEGIN {
				const char *longer = t_strconcat(u64tests[i].input, "x", NULL);
				ret = str_to_uint64(longer, &val);
				test_assert_idx(ret < 0, i);
			} T_END;
	}
	test_end();
}

static void test_str_to_u32(void)
{
	unsigned int i;
	const struct {
		const char *input;
		int ret;
		uint32_t val;
	} u32tests[] = {
		VALID(0),
		INVALID(-0),
		VALID(4294967295),
		INVALID(4294967296),
		INVALID(4772185880),
		INVALID(4772185884),
		INVALID(4772185890),
	};
	test_begin("str_to_uint32");
	for (i = 0; i < N_ELEMENTS(u32tests); ++i) {
		uint32_t val = 0xDEADF00D;
		int ret = str_to_uint32(u32tests[i].input, &val);
		test_assert_idx(ret == u32tests[i].ret, i);
		if (ret == 0)
			test_assert_idx(val == u32tests[i].val, i);
		else
			test_assert_idx(val == 0xDEADF00D, i);
	}
	test_end();
}

/* Assumes long long is 64 bit, 2's complement */
static void test_str_to_llong(void)
{
	unsigned int i;
	const struct {
		const char *input;
		int ret;
		long long val;
	} i64tests[] = {
		VALID(0),
		VALID(-0),
		INVALID(--0),
		VALID(2147483648),
		VALID(-2147483649),
		VALID(9223372036854775807),
		{ "-9223372036854775808", 0, -9223372036854775807-1 },
		INVALID(9223372036854775808),
		INVALID(-9223372036854775809),
	};
	test_begin("str_to_llong");
	for (i = 0; i < N_ELEMENTS(i64tests); ++i) {
		long long val = 123456789;
		int ret = str_to_llong(i64tests[i].input, &val);
		test_assert_idx(ret == i64tests[i].ret, i);
		if (ret == 0)
			test_assert_idx(val == i64tests[i].val, i);
		else
			test_assert_idx(val == 123456789, i);
	}
	test_end();
}

/* Assumes int is 32 bit, 2's complement */
static void test_str_to_i32(void)
{
	unsigned int i;
	const struct {
		const char *input;
		int ret;
		int val;
	} i32tests[] = {
		VALID(0),
		VALID(-0),
		INVALID(--0),
		VALID(2147483647),
		VALID(-2147483648),
		INVALID(2147483648),
		INVALID(-2147483649),
	};
	test_begin("str_to_int");
	for (i = 0; i < N_ELEMENTS(i32tests); ++i) {
		int val = 123456789;
		int ret = str_to_int(i32tests[i].input, &val);
		test_assert_idx(ret == i32tests[i].ret, i);
		if (ret == 0)
			test_assert_idx(val == i32tests[i].val, i);
		else
			test_assert_idx(val == 123456789, i);
	}
	test_end();
}

void test_strnum(void)
{
	/* If the above isn't true, then we do expect some failures possibly */
	test_str_to_u64();
	test_str_to_u32();
	test_str_to_llong();
	test_str_to_i32();
}
