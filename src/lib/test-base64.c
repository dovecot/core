/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "base64.h"

#include <stdlib.h>

static void test_base64_encode(void)
{
	static const char *input[] = {
		"hello world",
		"foo barits",
		"just niin"
	};
	static const char *output[] = {
		"aGVsbG8gd29ybGQ=",
		"Zm9vIGJhcml0cw==",
		"anVzdCBuaWlu"
	};
	string_t *str;
	unsigned int i;

	test_begin("base64_encode()");
	str = t_str_new(256);
	for (i = 0; i < N_ELEMENTS(input); i++) {
		str_truncate(str, 0);
		base64_encode(input[i], strlen(input[i]), str);
		test_assert(strcmp(output[i], str_c(str)) == 0);
	}
	test_end();
}

struct test_base64_decode_output {
	const char *text;
	int ret;
	unsigned int src_pos;
};

static void test_base64_decode(void)
{
	static const char *input[] = {
		"\taGVsbG8gd29ybGQ=",
		"\nZm9v\n \tIGJh  \t\ncml0cw==",
		"  anVzdCBuaWlu  \n",
		"aGVsb",
		"aGVsb!!!!!",
		"aGVs!!!!!"
	};
	static const struct test_base64_decode_output output[] = {
		{ "hello world", 0, -1 },
		{ "foo barits", 0, -1 },
		{ "just niin", 1, -1 },
		{ "hel", 1, 4 },
		{ "hel", -1, 4 },
		{ "hel", -1, 4 }
	};
	string_t *str;
	unsigned int i;
	size_t src_pos;
	int ret;

	test_begin("base64_decode()");
	str = t_str_new(256);
	for (i = 0; i < N_ELEMENTS(input); i++) {
		str_truncate(str, 0);

		src_pos = 0;
		ret = base64_decode(input[i], strlen(input[i]), &src_pos, str);

		test_assert(output[i].ret == ret &&
			    strcmp(output[i].text, str_c(str)) == 0 &&
			    (src_pos == output[i].src_pos ||
			     (output[i].src_pos == (unsigned int)-1 &&
			      src_pos == strlen(input[i]))));
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
		max = rand() % sizeof(buf);
		for (j = 0; j < max; j++)
			buf[j] = rand();

		str_truncate(str, 0);
		str_truncate(dest, 0);
		base64_encode(buf, max, str);
		base64_decode(str_data(str), str_len(str), NULL, dest);
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
