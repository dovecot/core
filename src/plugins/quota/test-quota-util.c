/* Copyright (c) 2014-2016 Dovecot authors, see the included COPYING file */

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
#define MAXU64 (uint64_t)-1
#define MAXS64 9223372036854775807LL
#define MINS64 (-MAXS64 - 1LL)
	static const struct test tests[] = {
		/* first test only with new_size=1. these are used for both
		   count and bytes tests: */

		/* limit,     init,     diff, new */
		{      1,        0,        0,   1, FALSE },
		{ MAXU64,   MAXU64,        0,   1, TRUE },
		{ MAXU64, MAXU64-1,        0,   1, FALSE },
		{ MAXU64, MAXU64-1,        1,   1, TRUE },
		{ MAXU64-1, MAXU64-1,      0,   1, TRUE },
		{ MAXU64-1, MAXU64-1,     -1,   1, FALSE },
		{ MAXU64-2, MAXU64-1,     -1,   1, TRUE },
		{ MAXU64-2, MAXU64-1,     -2,   1, FALSE },

		/* these are for bytes tests: */

		/* limit,   init,   diff,    new */
		{ MAXU64, MAXU64,      0,      0, FALSE },
		{ MAXU64, MAXU64-1,    1,      0, FALSE },
		{ MAXU64-1, MAXU64,    1,      0, TRUE },
		{ MAXU64-1, MAXU64,    0,      0, TRUE },
		{ MAXU64-1, MAXU64,   -1,      0, FALSE },
		{ MAXU64, MAXU64,      0,      1, TRUE },
		{ MAXU64,      0,      0, MAXU64, FALSE },
		{ MAXU64,      1,      0, MAXU64, TRUE },
		{ MAXU64,      0,      1, MAXU64, TRUE },
		{ MAXU64-1,    0,      0, MAXU64, TRUE },
		{ MAXU64-1,    0,      0, MAXU64-1, FALSE },
		{ MAXU64-1,    1,      0, MAXU64-1, TRUE },
		{ MAXU64-1,    1,     -1, MAXU64-1, FALSE },
		{ MAXU64, MAXU64,      0, MAXU64, TRUE },
	};
	struct quota_transaction_context ctx;
	unsigned int i;

	test_begin("quota transcation is over (count)");
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

	test_begin("quota transcation is over (bytes)");
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

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_quota_transaction_is_over,
		NULL
	};
	return test_run(test_functions);
}
