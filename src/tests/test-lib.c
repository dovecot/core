/* Copyright (c) 2007 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "base64.h"
#include "bsearch-insert-pos.h"

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
	bool success;

	str = t_str_new(256);
	for (i = 0; i < N_ELEMENTS(input); i++) {
		str_truncate(str, 0);
		base64_encode(input[i], strlen(input[i]), str);
		success = strcmp(output[i], str_c(str)) == 0;
		test_out(t_strdup_printf("base64_encode(%d)", i), success);
	}
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
	bool success;

	str = t_str_new(256);
	for (i = 0; i < N_ELEMENTS(input); i++) {
		str_truncate(str, 0);

		src_pos = 0;
		ret = base64_decode(input[i], strlen(input[i]), &src_pos, str);

		success = output[i].ret == ret &&
			strcmp(output[i].text, str_c(str)) == 0 &&
			(src_pos == output[i].src_pos ||
			 (output[i].src_pos == (unsigned int)-1 &&
			  src_pos == strlen(input[i])));
		test_out(t_strdup_printf("base64_decode(%d)", i), success);
	}
}

static int cmp_uint(const void *p1, const void *p2)
{
	const unsigned int *i1 = p1, *i2 = p2;

	return *i1 - *i2;
}

static void test_bsearch_insert_pos(void)
{
	static const unsigned int input[] = {
		1, 5, 9, 15, 16, -1,
		1, 5, 9, 15, 16, 17, -1,
		-1
	};
	static const unsigned int max_key = 18;
	const unsigned int *cur;
	unsigned int key, len, i, idx;
	bool success;

	cur = input;
	for (i = 0; cur[0] != -1U; i++) {
		for (len = 0; cur[len] != -1U; len++) ;
		for (key = 0; key < max_key; key++) {
			if (bsearch_insert_pos(&key, cur, len, sizeof(*cur),
					       cmp_uint, &idx))
				success = cur[idx] == key;
			else if (idx == 0)
				success = cur[0] > key;
			else if (idx == len)
				success = cur[len-1] < key;
			else {
				success = cur[idx-1] < key &&
					cur[idx+1] > key;
			}
			if (!success)
				break;
		}
		cur += len + 1;

		test_out(t_strdup_printf("bsearch_insert_pos(%d,%d)", i, key),
			 success);
	}
}

int main(void)
{
	test_init();

	test_base64_encode();
	test_base64_decode();
	test_bsearch_insert_pos();
	test_istreams();
	return test_deinit();
}
