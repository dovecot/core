/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "test-lib.h"
#include "hex-dec.h"

static void test_hex2dec_case(void)
{
	static const struct {
		const char *input;
		enum hex_allowed_case allowed_case;
		int ret;
		uintmax_t value;
	} tests[] = {
		{ "", HEX_ALLOWED_CASE_BOTH, 0, 0 },
		{ "0", HEX_ALLOWED_CASE_BOTH, 0, 0 },
		{ "19", HEX_ALLOWED_CASE_BOTH, 0, 0x19 },
		{ "abcdef", HEX_ALLOWED_CASE_BOTH, 0, 0xabcdef },
		{ "ABCDEF", HEX_ALLOWED_CASE_BOTH, 0, 0xabcdef },
		{ "aBcDeF", HEX_ALLOWED_CASE_BOTH, 0, 0xabcdef },
		{ "abcdef", HEX_ALLOWED_CASE_LOWER, 0, 0xabcdef },
		{ "ABCDEF", HEX_ALLOWED_CASE_UPPER, 0, 0xabcdef },
		{ "ABCDEF", HEX_ALLOWED_CASE_LOWER, -1, 0 },
		{ "abcdef", HEX_ALLOWED_CASE_UPPER, -1, 0 },
		{ "aBcDeF", HEX_ALLOWED_CASE_LOWER, -1, 0 },
		{ "aBcDeF", HEX_ALLOWED_CASE_UPPER, -1, 0 },
		{ "12g4", HEX_ALLOWED_CASE_BOTH, -1, 0 },
		{ "12 4", HEX_ALLOWED_CASE_BOTH, -1, 0 },
		{ "0x12", HEX_ALLOWED_CASE_BOTH, -1, 0 },
	};

	test_begin("hex2dec_case()");
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		uintmax_t value = 0;
		int ret = hex2dec_case(tests[i].input,
				       strlen(tests[i].input),
				       tests[i].allowed_case, &value);

		test_assert_cmp_idx(ret, ==, tests[i].ret, i);
		if (tests[i].ret == 0)
			test_assert_ucmp_idx(value, ==, tests[i].value, i);
	}
	test_end();
}

static void test_hex2dec_case_overflow(void)
{
	static const struct {
		const char *input;
		int ret;
		uintmax_t value;
	} tests[] = {
		{ "FFFFFFFFFFFFFFFF", 0, UINT64_MAX },
		{ "0000000000000000FFFFFFFFFFFFFFFF", 0, UINT64_MAX },
		{ "10000000000000000", -1, 0 },
		{ "FFFFFFFFFFFFFFFFF", -1, 0 },
	};

	test_begin("hex2dec_case() overflow");
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		uintmax_t value = 0;
		int ret = hex2dec_case(tests[i].input,
				       strlen(tests[i].input),
				       HEX_ALLOWED_CASE_BOTH, &value);

		test_assert_cmp_idx(ret, ==, tests[i].ret, i);
		if (tests[i].ret == 0)
			test_assert_ucmp_idx(value, ==, tests[i].value, i);
	}
	test_end();
}

static void test_hex2dec(void)
{
	test_begin("hex2dec()");
	test_assert_ucmp(hex2dec("FFFFFFFFFFFFFFFF", 16),
			==, UINT64_MAX);
	test_assert_ucmp(hex2dec("10000000000000001", 17),
			==, 0);
	test_assert_ucmp(hex2dec("zz", 2), ==, 0);
	test_end();
}

static void test_dec2hex(void)
{
	unsigned char hex[16];

	test_begin("dec2hex()");
	DEC2HEX(hex, UINT64_MAX);
	test_assert_memcmp(hex, sizeof(hex), "FFFFFFFFFFFFFFFF", 16);
	DEC2HEX(hex, 0x1234abcd);
	test_assert_memcmp(hex, sizeof(hex), "000000001234ABCD", 16);
	test_end();
}

void test_hex_dec(void)
{
	test_hex2dec_case();
	test_hex2dec_case_overflow();
	test_hex2dec();
	test_dec2hex();
}
