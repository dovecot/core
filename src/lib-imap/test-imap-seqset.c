/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "imap-seqset.h"
#include "imap-util.h"
#include "seq-range-array.h"
#include "test-common.h"

static void imap_write_seq_range_star_one(string_t *dest, uint32_t seq)
{
	if (seq == UINT32_MAX)
		str_append_c(dest, '*');
	else
		str_printfa(dest, "%u", seq);
}

static void
imap_write_seq_range_star(string_t *dest, const ARRAY_TYPE(seq_range) *array)
{
	const struct seq_range *range;
	unsigned int i, count;

	range = array_get(array, &count);
	for (i = 0; i < count; i++) {
		if (i > 0)
			str_append_c(dest, ',');
		imap_write_seq_range_star_one(dest, range[i].seq1);
		if (range[i].seq1 != range[i].seq2) {
			str_append_c(dest, ':');
			imap_write_seq_range_star_one(dest, range[i].seq2);
		}
	}
}

static void test_imap_seq_set_parse(void)
{
	static const struct {
		const char *input;
		const char *output;
		int ret;
	} tests[] = {
		{ "0", "", -1 },
		{ "1", "1", 0 },
		{ "2:4", "2:4", 0 },
		{ "5:*", "5:*", 0 },
		{ "1,3,5", "1,3,5", 0 },
		{ "1,3:5,7:*", "1,3:5,7:*", 0 },
		{ "1,2,3,4,5", "1:5", 0 },
		{ "1,2,4,5", "1:2,4:5", 0 },
		{ "1,3,2,5,4", "1:5", 0 },
		/* Comma at the end is not actually valid, but for now at least
		   we allow it. At least imapc used to send UID STORE commands
		   with uidsets ending with comma. */
		{ "1,2,", "1:2", 0 },
		{ "4294967296", "", -1 },
		{ "4294967295", "4294967294", 0 },
		{ "4294967294:4294967295", "4294967294", 0 },
		{ "4294967293:4294967295", "4294967293:4294967294", 0 },
		{ "", "", -1 },
		{ ",", "", -1 },
		{ "1,,5", "", -1 },
		{ "1:2,3,,5", "", -1 },
		{ "a", "", -1 },
		{ "1:a", "", -1 },
		{ "1:2a", "", -1 },
	};
	ARRAY_TYPE(seq_range) ranges;

	test_begin("imap_seq_set_parse()");
	t_array_init(&ranges, 4);

	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		array_clear(&ranges);
		int ret = imap_seq_set_parse(tests[i].input, &ranges);
		test_assert_idx(ret == tests[i].ret, i);
		if (ret == 0) {
			string_t *str = t_str_new(128);
			imap_write_seq_range_star(str, &ranges);
			test_assert_strcmp_idx(str_c(str), tests[i].output, i);
		}
	}
	test_end();
}

static void test_imap_seq_set_nostar_parse(void)
{
	static const struct {
		const char *input;
		const char *output;
		int ret;
	} tests[] = {
		{ "1", "1", 0 },
		{ "2:4", "2:4", 0 },
		{ "1,3,5", "1,3,5", 0 },
		{ "1,3:5", "1,3:5", 0 },
		{ "1,2,3,4,5", "1:5", 0 },
		{ "1,2,4,5", "1:2,4:5", 0 },
		{ "1,3,2,5,4", "1:5", 0 },
		{ "5:*", "", -1 },
		{ "1,3:5,7:*", "", -1 },
		{ "*", "", -1 },
	};
	ARRAY_TYPE(seq_range) ranges;

	test_begin("imap_seq_set_nostar_parse()");
	t_array_init(&ranges, 4);

	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		array_clear(&ranges);
		int ret = imap_seq_set_nostar_parse(tests[i].input, &ranges);
		test_assert_idx(ret == tests[i].ret, i);
		if (ret == 0) {
			string_t *str = t_str_new(128);
			imap_write_seq_range_star(str, &ranges);
			test_assert_strcmp_idx(str_c(str), tests[i].output, i);
		}
	}
	test_end();
}

static void test_imap_seq_range_parse(void)
{
	static const struct {
		const char *input;
		uint32_t seq1, seq2;
		int ret;
	} tests[] = {
		{ "1", 1, 1, 0 },
		{ "2:4", 2, 4, 0 },
		{ "5:*", 5, (uint32_t)-1, 0 },
		{ "*", (uint32_t)-1, (uint32_t)-1, 0 },
		{ "0", 0, 0, -1 },
		{ "1:0", 0, 0, -1 },
		{ "", 0, 0, -1 },
		{ ":", 0, 0, -1 },
		{ "1:", 0, 0, -1 },
		{ ":5", 0, 0, -1 },
		{ "a", 0, 0, -1 },
		{ "1a", 0, 0, -1 },
		{ "1:a", 0, 0, -1 },
	};
	uint32_t seq1, seq2;

	test_begin("imap_seq_range_parse()");

	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		int ret = imap_seq_range_parse(tests[i].input, &seq1, &seq2);
		test_assert_idx(ret == tests[i].ret, i);
		if (ret == 0) {
			test_assert_idx(seq1 == tests[i].seq1 &&
					seq2 == tests[i].seq2, i);
		}
	}
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_imap_seq_set_parse,
		test_imap_seq_set_nostar_parse,
		test_imap_seq_range_parse,
		NULL
	};
	return test_run(test_functions);
}
