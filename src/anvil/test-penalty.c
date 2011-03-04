/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "penalty.h"
#include "test-common.h"

static void test_penalty_checksum(void)
{
	struct penalty *penalty;
	struct ioloop *ioloop;
	time_t t;
	unsigned int i, j;

	test_begin("penalty");

	ioloop = io_loop_create();
	penalty = penalty_init();

	test_assert(penalty_get(penalty, "foo", &t) == 0);
	for (i = 1; i <= 10; i++) {
		ioloop_time = 12345678 + i;
		penalty_inc(penalty, "foo", i, 5+i);

		for (j = I_MIN(1, i-1); j <= i; j++) {
			test_assert(penalty_get(penalty, "foo", &t) == 5+i);
			test_assert(t == (time_t)(12345678 + i));
			test_assert(penalty_has_checksum(penalty, "foo", i));
		}
		test_assert(penalty_get(penalty, "foo", &t) == 5+i);
		test_assert(t == (time_t)(12345678 + i));
		test_assert(!penalty_has_checksum(penalty, "foo", j));
	}
	test_assert(penalty_get(penalty, "foo2", &t) == 0);

	/* overflows checksum array */
	ioloop_time = 12345678 + i;
	penalty_inc(penalty, "foo", i, 5 + i);
	penalty_inc(penalty, "foo", i, 5 + i);
	penalty_inc(penalty, "foo", 0, 5 + i);

	test_assert(penalty_get(penalty, "foo", &t) == 5+i);
	test_assert(t == (time_t)(12345678 + i));
	test_assert(!penalty_has_checksum(penalty, "foo", 1));

	for (j = 2; j <= i; j++) {
		test_assert(penalty_get(penalty, "foo", &t) == 5+i);
		test_assert(t == (time_t)(12345678 + i));
		test_assert(penalty_has_checksum(penalty, "foo", i));
	}

	penalty_deinit(&penalty);
	io_loop_destroy(&ioloop);
	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_penalty_checksum,
		NULL
	};
	return test_run(test_functions);
}
