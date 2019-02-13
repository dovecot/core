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
		{ "\xe7\x8c\xbf\xe3\x82\x82\xe6\x9c\xa8\xe3\x81\x8b"
		  "\xe3\x82\x89\xe8\x90\xbd\xe3\x81\xa1\xe3\x82\x8b",
		  "54y/44KC5pyo44GL44KJ6JC944Gh44KL" },
		{ "\xe8\xa7\x92\xe3\x82\x92\xe7\x9f\xaf\xe3\x82\x81\xe3\x81"
		  "\xa6\xe7\x89\x9b\xe3\x82\x92\xe6\xae\xba\xe3\x81\x99",
		  "6KeS44KS55+v44KB44Gm54mb44KS5q6644GZ" },
	};
	string_t *str;
	unsigned int i;

	test_begin("base64_encode()");
	str = t_str_new(256);
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		str_truncate(str, 0);
		base64_encode(tests[i].input, strlen(tests[i].input), str);
		test_assert_idx(strcmp(tests[i].output, str_c(str)) == 0, i);
		test_assert_idx(
			str_len(str) ==	MAX_BASE64_ENCODED_SIZE(
				strlen(tests[i].input)), i);
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
		{ "0JPQvtCy0L7RgNGPzIHRgiwg0YfRgt"
		  "C+INC60YPRgCDQtNC+0Y/MgdGCLg==",
		  "\xd0\x93\xd0\xbe\xd0\xb2\xd0\xbe\xd1\x80\xd1\x8f\xcc"
		  "\x81\xd1\x82\x2c\x20\xd1\x87\xd1\x82\xd0\xbe\x20\xd0"
		  "\xba\xd1\x83\xd1\x80\x20\xd0\xb4\xd0\xbe\xd1\x8f\xcc"
		  "\x81\xd1\x82\x2e", 0, UINT_MAX },
	};
	string_t *str;
	buffer_t buf;
	unsigned int i;
	size_t src_pos;
	int ret;

	test_begin("base64_decode()");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		/* Some of the base64_decode() callers use fixed size buffers.
		   Use a fixed size buffer here as well to test that
		   base64_decode() can't allocate any extra space even
		   temporarily. */
		size_t max_decoded_size =
			MAX_BASE64_DECODED_SIZE(strlen(tests[i].input));

		buffer_create_from_data(&buf, t_malloc0(max_decoded_size),
					max_decoded_size);
		str = &buf;
		src_pos = 0;
		ret = base64_decode(tests[i].input, strlen(tests[i].input),
				    &src_pos, str);

		test_assert_idx(tests[i].ret == ret, i);
		test_assert_idx(strlen(tests[i].output) == str_len(str) &&
				memcmp(tests[i].output, str_data(str),
				       str_len(str)) == 0, i);
		test_assert_idx(src_pos == tests[i].src_pos ||
				(tests[i].src_pos == UINT_MAX &&
				 src_pos == strlen(tests[i].input)), i);
		if (ret >= 0) {
			test_assert_idx(
				str_len(str) <= MAX_BASE64_DECODED_SIZE(
					strlen(tests[i].input)), i);
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
		test_assert_idx(base64_decode(str_data(str), str_len(str),
					      NULL, dest) >= 0, i);
		test_assert_idx(str_len(dest) == max &&
				memcmp(buf, str_data(dest), max) == 0, i);
	}
	test_end();
}

static void test_base64url_encode(void)
{
	const struct {
		const char *input;
		const char *output;
	} tests[] = {
		{ "hello world", "aGVsbG8gd29ybGQ=" },
		{ "foo barits", "Zm9vIGJhcml0cw==" },
		{ "just niin", "anVzdCBuaWlu" },
		{ "\xe7\x8c\xbf\xe3\x82\x82\xe6\x9c\xa8\xe3\x81\x8b"
		  "\xe3\x82\x89\xe8\x90\xbd\xe3\x81\xa1\xe3\x82\x8b",
		  "54y_44KC5pyo44GL44KJ6JC944Gh44KL" },
		{ "\xe8\xa7\x92\xe3\x82\x92\xe7\x9f\xaf\xe3\x82\x81\xe3\x81"
		  "\xa6\xe7\x89\x9b\xe3\x82\x92\xe6\xae\xba\xe3\x81\x99",
		  "6KeS44KS55-v44KB44Gm54mb44KS5q6644GZ" },
	};
	string_t *str;
	unsigned int i;

	test_begin("base64url_encode()");
	str = t_str_new(256);
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		str_truncate(str, 0);
		base64url_encode(tests[i].input, strlen(tests[i].input), str);
		test_assert_idx(strcmp(tests[i].output, str_c(str)) == 0, i);
		test_assert_idx(
			str_len(str) ==	MAX_BASE64_ENCODED_SIZE(
				strlen(tests[i].input)), i);
	}
	test_end();
}

struct test_base64url_decode {
	const char *input;
	const char *output;
	int ret;
	unsigned int src_pos;
};

static void test_base64url_decode(void)
{
	static const struct test_base64url_decode tests[] = {
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
		{ "0JPQvtCy0L7RgNGPzIHRgiwg0YfRgt"
		  "C-INC60YPRgCDQtNC-0Y_MgdGCLg==",
		  "\xd0\x93\xd0\xbe\xd0\xb2\xd0\xbe\xd1\x80\xd1\x8f\xcc"
		  "\x81\xd1\x82\x2c\x20\xd1\x87\xd1\x82\xd0\xbe\x20\xd0"
		  "\xba\xd1\x83\xd1\x80\x20\xd0\xb4\xd0\xbe\xd1\x8f\xcc"
		  "\x81\xd1\x82\x2e", 0, UINT_MAX },
	};
	string_t *str;
	buffer_t buf;
	unsigned int i;
	size_t src_pos;
	int ret;

	test_begin("base64url_decode()");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		/* Some of the base64_decode() callers use fixed size buffers.
		   Use a fixed size buffer here as well to test that
		   base64_decode() can't allocate any extra space even
		   temporarily. */
		size_t max_decoded_size =
			MAX_BASE64_DECODED_SIZE(strlen(tests[i].input));

		buffer_create_from_data(&buf, t_malloc0(max_decoded_size),
					max_decoded_size);
		str = &buf;
		src_pos = 0;
		ret = base64url_decode(tests[i].input, strlen(tests[i].input),
				       &src_pos, str);

		test_assert_idx(tests[i].ret == ret, i);
		test_assert_idx(strlen(tests[i].output) == str_len(str) &&
				memcmp(tests[i].output, str_data(str),
				       str_len(str)) == 0, i);
		test_assert_idx(src_pos == tests[i].src_pos ||
				(tests[i].src_pos == UINT_MAX &&
				 src_pos == strlen(tests[i].input)), i);
		if (ret >= 0) {
			test_assert_idx(
				str_len(str) <= MAX_BASE64_DECODED_SIZE(
					strlen(tests[i].input)), i);
		}
	}
	test_end();
}

static void test_base64url_random(void)
{
	string_t *str, *dest;
	char buf[10];
	unsigned int i, j, max;

	str = t_str_new(256);
	dest = t_str_new(256);

	test_begin("base64url encode/decode with random input");
	for (i = 0; i < 1000; i++) {
		max = i_rand_limit(sizeof(buf));
		for (j = 0; j < max; j++)
			buf[j] = i_rand();

		str_truncate(str, 0);
		str_truncate(dest, 0);
		base64url_encode(buf, max, str);
		test_assert_idx(base64url_decode(str_data(str), str_len(str),
						 NULL, dest) >= 0, i);
		test_assert_idx(str_len(dest) == max &&
				memcmp(buf, str_data(dest), max) == 0, i);
	}
	test_end();
}

void test_base64(void)
{
	test_base64_encode();
	test_base64_decode();
	test_base64_random();
	test_base64url_encode();
	test_base64url_decode();
	test_base64url_random();
}
