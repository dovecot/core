/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "quota-private.h"
#include "test-common.h"

struct test {
	uint64_t limit, initial_size;
	int64_t transaction_diff;
	uint64_t new_size;
	bool is_over;
};

static void test_quota_transaction_is_over(void)
{
	static const struct test tests[] = {
		/* first test only with new_size=1. these are used for both
		   count and bytes tests: */

		/*         limit,           init, diff,            new */
		{              1,              0,    0,              1, FALSE },
		{     UINT64_MAX,     UINT64_MAX,    0,              1, TRUE },
		{     UINT64_MAX, UINT64_MAX - 1,    0,              1, FALSE },
		{     UINT64_MAX, UINT64_MAX - 1,    1,              1, TRUE },
		{ UINT64_MAX - 1, UINT64_MAX - 1,    0,              1, TRUE },
		{ UINT64_MAX - 1, UINT64_MAX - 1,   -1,              1, FALSE },
		{ UINT64_MAX - 2, UINT64_MAX - 1,   -1,              1, TRUE },
		{ UINT64_MAX - 2, UINT64_MAX - 1,   -2,              1, FALSE },

		/* these are for bytes tests: */

		/*         limit,           init, diff,            new */
		{     UINT64_MAX,     UINT64_MAX,    0,              0, FALSE },
		{     UINT64_MAX, UINT64_MAX - 1,    1,              0, FALSE },
		{ UINT64_MAX - 1,     UINT64_MAX,    1,              0, TRUE },
		{ UINT64_MAX - 1,     UINT64_MAX,    0,              0, TRUE },
		{ UINT64_MAX - 1,     UINT64_MAX,   -1,              0, FALSE },
		{     UINT64_MAX,     UINT64_MAX,    0,              1, TRUE },
		{     UINT64_MAX,              0,    0,     UINT64_MAX, FALSE },
		{     UINT64_MAX,              1,    0,     UINT64_MAX, TRUE },
		{     UINT64_MAX,              0,    1,     UINT64_MAX, TRUE },
		{ UINT64_MAX - 1,              0,    0,     UINT64_MAX, TRUE },
		{ UINT64_MAX - 1,              0,    0, UINT64_MAX - 1, FALSE },
		{ UINT64_MAX - 1,              1,    0, UINT64_MAX - 1, TRUE },
		{ UINT64_MAX - 1,              1,   -1, UINT64_MAX - 1, FALSE },
		{     UINT64_MAX,     UINT64_MAX,    0,     UINT64_MAX, TRUE },
	};
	struct quota_transaction_context ctx;
	unsigned int i;

	test_begin("quota transaction is over (count)");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		if (tests[i].new_size != 1)
			continue;

		i_zero(&ctx);
		ctx.count_used = tests[i].transaction_diff;
		if (tests[i].initial_size > tests[i].limit)
			ctx.count_over = tests[i].initial_size - tests[i].limit;
		else {
			ctx.count_ceil = tests[i].limit - tests[i].initial_size;
			i_assert(ctx.count_used < 0 ||
				 (uint64_t)ctx.count_used <= ctx.count_ceil); /* test is broken otherwise */
		}
		test_assert_idx(quota_transaction_is_over(&ctx, 0) == tests[i].is_over, i);
	}
	test_end();

	test_begin("quota transaction is over (bytes)");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		i_zero(&ctx);
		ctx.count_ceil = 1;
		ctx.bytes_used = tests[i].transaction_diff;
		if (tests[i].initial_size > tests[i].limit)
			ctx.bytes_over = tests[i].initial_size - tests[i].limit;
		else {
			ctx.bytes_ceil = tests[i].limit - tests[i].initial_size;
			i_assert(ctx.bytes_used < 0 ||
				 (uint64_t)ctx.bytes_used <= ctx.bytes_ceil); /* test is broken otherwise */
		}
		test_assert_idx(quota_transaction_is_over(&ctx, tests[i].new_size) == tests[i].is_over, i);
	}
	test_end();
}

static void test_maildirsize_sum_lines(void)
{
	static const struct {
		const char *input;
		int ret;
		long long bytes;
		int count;
	} tests[] = {
		{ "100 2\n50 1", 0, 150, 3 },
		{ "  100 \t 2  \n\t-50\t-1", 0, 50, 1 },
		{ "100 2 trailing data", 0, 100, 2 },
		{ "-5 -3", 0, -5, -3 },
		{ "5", -1, 0, 0 },
		{ "5 ", -1, 0, 0 },
		{ "abc 5", -1, 0, 0 },
		{ "5 abc", -1, 0, 0 },
		{ "100 2\nbad", -1, 0, 0 },
		{ "99999999999999999999 1", -1, 0, 0 },
		{ "1 99999999999", -1, 0, 0 },
	};

	test_begin("maildirsize sum lines");
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) T_BEGIN {
		long long bytes = 0;
		int count = 0;
		const int ret = quota_maildirsize_sum_lines(
			t_strsplit(tests[i].input, "\n"), &bytes, &count);

		test_assert_idx(ret == tests[i].ret, i);
		if (ret == 0) {
			test_assert_idx(bytes == tests[i].bytes, i);
			test_assert_idx(count == tests[i].count, i);
		}
	} T_END;
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_quota_transaction_is_over,
		test_maildirsize_sum_lines,
		NULL
	};
	return test_run(test_functions);
}
