/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "base64.h"


static void test_base64_encode(void)
{
	const struct {
		const char *input;
		const char *output;
	} tests[] = {
		{ "hello world", "aGVsbG8gd29ybGQ=" },
		{ "foo barits", "Zm9vIGJhcml0cw==" },
		{ "just niin", "anVzdCBuaWlu" },
	};
	string_t *str;
	unsigned int i;

	test_begin("base64_encode()");
	str = t_str_new(256);
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		str_truncate(str, 0);
		base64_encode(tests[i].input, strlen(tests[i].input), str);
		test_assert(strcmp(tests[i].output, str_c(str)) == 0);
		test_assert(
			str_len(str) == MAX_BASE64_ENCODED_SIZE(
				strlen(tests[i].input)));
	}
	test_end();
}

struct test_base64_decode {
	const char *input;
	const char *output;
	int ret;
	unsigned int src_pos;
};

static void test_base64_decode(void)
{
	static const struct test_base64_decode tests[] = {
		{ "\taGVsbG8gd29ybGQ=",
		  "hello world", 0, UINT_MAX },
		{ "\nZm9v\n \tIGJh  \t\ncml0cw==",
		  "foo barits", 0, UINT_MAX },
		{ "  anVzdCBuaWlu  \n",
		  "just niin", 1, UINT_MAX },
		{ "aGVsb",
		  "hel", 1, 4 },
		{ "aGVsb!!!!!",
		  "hel", -1, 4 },
		{ "aGVs!!!!!",
		  "hel", -1, 4 },
	};
	string_t *str;
	unsigned int i;
	size_t src_pos;
	int ret;

	test_begin("base64_decode()");
	str = t_str_new(256);
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		str_truncate(str, 0);

		src_pos = 0;
		ret = base64_decode(tests[i].input, strlen(tests[i].input),
				    &src_pos, str);

		test_assert(tests[i].ret == ret &&
			    strcmp(tests[i].output, str_c(str)) == 0 &&
			    (src_pos == tests[i].src_pos ||
			     (tests[i].src_pos == UINT_MAX &&
			      src_pos == strlen(tests[i].input))));
		if (ret >= 0) {
			test_assert(
				str_len(str) <= MAX_BASE64_DECODED_SIZE(
					strlen(tests[i].input)));
		}
	}
	test_end();
}

static void test_base64_random(void)
{
	string_t *str, *dest;
	char buf[10];
	unsigned int i, j, max;

	str = t_str_new(256);
	dest = t_str_new(256);

	test_begin("base64 encode/decode with random input");
	for (i = 0; i < 1000; i++) {
		max = i_rand_limit(sizeof(buf));
		for (j = 0; j < max; j++)
			buf[j] = i_rand();

		str_truncate(str, 0);
		str_truncate(dest, 0);
		base64_encode(buf, max, str);
		test_assert(base64_decode(str_data(str), str_len(str), NULL, dest) >= 0);
		test_assert(str_len(dest) == max &&
			    memcmp(buf, str_data(dest), max) == 0);
	}
	test_end();
}

void test_base64(void)
{
	test_base64_encode();
	test_base64_decode();
	test_base64_random();
}
