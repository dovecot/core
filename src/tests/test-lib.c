/* Copyright (c) 2007 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "array.h"
#include "str.h"
#include "base64.h"
#include "bsearch-insert-pos.h"
#include "seq-range-array.h"
#include "str-sanitize.h"

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

static void test_seq_range_array(void)
{
	static const unsigned int input_min = 1, input_max = 5;
	static const unsigned int input[] = {
		1, 2, 3, 4, 5, -1U,
		2, 3, 4, -1U,
		1, 2, 4, 5, -1U,
		1, 3, 5, -1U,
		1, -1U,
		5, -1U,
		-1U
	};
	ARRAY_TYPE(seq_range) range = ARRAY_INIT;
	unsigned int i, j, seq, start, num;
	bool old_exists, success;

	for (i = num = 0; input[i] != -1U; num++, i++) {
		success = TRUE;
		start = i;
		for (; input[i] != -1U; i++) {
			seq_range_array_add(&range, 32, input[i]);
			for (j = start; j < i; j++) {
				if (!seq_range_exists(&range, input[j]))
					success = FALSE;
			}
		}

		seq_range_array_invert(&range, input_min, input_max);
		for (seq = input_min; seq <= input_max; seq++) {
			for (j = start; input[j] != -1U; j++) {
				if (input[j] == seq)
					break;
			}
			old_exists = input[j] != -1U;
			if (seq_range_exists(&range, seq) == old_exists)
				success = FALSE;
		}
		test_out(t_strdup_printf("seq_range_array_invert(%u)", num),
			 success);
		array_free(&range);
	}
}

struct str_sanitize_input {
	const char *str;
	unsigned int max_len;
};
static void test_str_sanitize(void)
{
	static struct str_sanitize_input input[] = {
		{ NULL, 2 },
		{ "", 2 },
		{ "a", 2 },
		{ "ab", 2 },
		{ "abc", 2 },
		{ "abcd", 3 },
		{ "abcde", 4 }
	};
	static const char *output[] = {
		NULL,
		"",
		"a",
		"ab",
		"...",
		"...",
		"a..."
	};
	const char *str;
	unsigned int i;
	bool success;

	for (i = 0; i < N_ELEMENTS(input); i++) {
		str = str_sanitize(input[i].str, input[i].max_len);
		success = null_strcmp(output[i], str) == 0;
		test_out(t_strdup_printf("str_sanitize(%d)", i), success);
	}
}

int main(void)
{
	test_init();

	test_base64_encode();
	test_base64_decode();
	test_bsearch_insert_pos();
	test_seq_range_array();
	test_str_sanitize();
	test_istreams();
	return test_deinit();
}
