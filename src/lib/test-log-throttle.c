/* Copyright (c) 2016 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "ioloop.h"
#include "log-throttle.h"

static unsigned int test_log_throttle_new_events_count;

static void test_log_throttle_callback(unsigned int new_events_count,
				       struct ioloop *ioloop)
{
	test_log_throttle_new_events_count = new_events_count;
	io_loop_stop(ioloop);
}

void test_log_throttle(void)
{
	const struct log_throttle_settings set = {
		.throttle_at_max_per_interval = 10,
		.unthrottle_at_max_per_interval = 5,
		.interval_msecs = 10,
	};
	struct log_throttle *throttle;
	struct ioloop *ioloop;
	unsigned int i;

	test_begin("log throttle");

	ioloop = io_loop_create();
	throttle = log_throttle_init(&set, test_log_throttle_callback, ioloop);

	/* throttle once and drop out just below */
	for (i = 0; i < 10; i++)
		test_assert_idx(log_throttle_accept(throttle), i);
	for (i = 0; i < 4; i++)
		test_assert_idx(!log_throttle_accept(throttle), i);

	io_loop_run(ioloop);
	test_assert(test_log_throttle_new_events_count == 4);

	/* throttle and continue just above */
	for (i = 0; i < 10; i++)
		test_assert_idx(log_throttle_accept(throttle), i);
	for (i = 0; i < 5; i++)
		test_assert_idx(!log_throttle_accept(throttle), i);

	io_loop_run(ioloop);
	test_assert(test_log_throttle_new_events_count == 5);

	/* we should be still throttled */
	test_assert(!log_throttle_accept(throttle));

	log_throttle_deinit(&throttle);
	io_loop_destroy(&ioloop);

	test_end();
}
