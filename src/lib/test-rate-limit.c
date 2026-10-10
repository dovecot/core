/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "test-lib.h"
#include "ioloop.h"
#include "time-util.h"
#include "rate-limit.h"

static const struct rate_limit_settings test_set = {
	.interval_msecs = 500,
	.burst = 3,
};
static const struct timeval test_base = { .tv_sec = 1000000, .tv_usec = 0 };

/* Set the current time relative to test_base */
static void test_set_time(int msecs)
{
	ioloop_timeval = test_base;
	if (msecs >= 0)
		timeval_add_msecs(&ioloop_timeval, msecs);
	else
		timeval_sub_msecs(&ioloop_timeval, -msecs);
}

static unsigned int test_delay(const struct rate_limit *limit, int msecs)
{
	test_set_time(msecs);
	return rate_limit_get_delay_msecs(limit);
}

static void test_add(struct rate_limit *limit, int msecs)
{
	test_set_time(msecs);
	rate_limit_add(limit);
}

static void test_rate_limit_burst(void)
{
	struct rate_limit limit;
	unsigned int i;

	test_begin("rate limit burst");
	rate_limit_init(&limit, &test_set);
	/* the full burst is available initially */
	for (i = 0; i < test_set.burst; i++) {
		test_assert_idx(test_delay(&limit, 0) == 0, i);
		test_add(&limit, 0);
	}
	/* burst is used up */
	test_assert_ucmp(test_delay(&limit, 0), ==, 500);
	test_assert_ucmp(test_delay(&limit, 200), ==, 300);
	test_assert_ucmp(test_delay(&limit, 499), ==, 1);
	test_assert_ucmp(test_delay(&limit, 500), ==, 0);

	/* one event refilled after 500 ms */
	test_add(&limit, 500);
	test_assert_ucmp(test_delay(&limit, 500), ==, 500);

	/* full burst is available again after idling long enough */
	for (i = 0; i < test_set.burst; i++) {
		test_assert_idx(test_delay(&limit, 2000) == 0, i);
		test_add(&limit, 2000);
	}
	test_assert_ucmp(test_delay(&limit, 2000), ==, 500);
	test_end();
}

static void test_rate_limit_partial_refill(void)
{
	struct rate_limit limit;
	unsigned int i;

	test_begin("rate limit partial refill");
	rate_limit_init(&limit, &test_set);
	for (i = 0; i < test_set.burst; i++)
		test_add(&limit, 0);
	/* one event has been refilled and 100 ms of the next one */
	test_assert_ucmp(test_delay(&limit, 600), ==, 0);
	test_add(&limit, 600);
	test_assert_ucmp(test_delay(&limit, 600), ==, 400);
	test_end();
}

static void test_rate_limit_steady_rate(void)
{
	struct rate_limit limit;
	unsigned int i, delay;
	int msecs = 0;

	test_begin("rate limit steady rate");
	rate_limit_init(&limit, &test_set);
	/* events that keep arriving as soon as they are allowed are delayed
	   by one interval each after the burst */
	for (i = 0; i < 20; i++) {
		delay = test_delay(&limit, msecs);
		if (i < test_set.burst)
			test_assert_idx(delay == 0, i);
		else
			test_assert_idx(delay == test_set.interval_msecs, i);
		msecs += delay;
		test_add(&limit, msecs);
	}
	test_end();
}

static void test_rate_limit_usecs(void)
{
	struct rate_limit limit;
	unsigned int i;

	test_begin("rate limit usecs");
	rate_limit_init(&limit, &test_set);
	for (i = 0; i < test_set.burst; i++)
		test_add(&limit, 0);
	/* less than 1 ms remaining is rounded up */
	test_set_time(0);
	timeval_add_usecs(&ioloop_timeval, 499999);
	test_assert_ucmp(rate_limit_get_delay_msecs(&limit), ==, 1);
	timeval_add_usecs(&ioloop_timeval, 1);
	test_assert_ucmp(rate_limit_get_delay_msecs(&limit), ==, 0);
	test_end();
}

static void test_rate_limit_add_without_waiting(void)
{
	struct rate_limit limit;
	struct timeval full_time = test_base;
	unsigned int i;

	test_begin("rate limit add without waiting");
	rate_limit_init(&limit, &test_set);
	/* adding events beyond the burst doesn't increase the delay */
	for (i = 0; i < 100; i++)
		test_add(&limit, 0);
	test_assert_ucmp(test_delay(&limit, 0), ==, 500);
	test_assert_ucmp(test_delay(&limit, 500), ==, 0);
	/* full burst is available after burst*interval */
	timeval_add_msecs(&full_time, 1500);
	test_assert(timeval_cmp(&limit.refill_time, &full_time) == 0);
	test_end();
}

static void test_rate_limit_time_moved_backwards(void)
{
	struct rate_limit limit;
	unsigned int i;

	test_begin("rate limit time moved backwards");
	rate_limit_init(&limit, &test_set);
	for (i = 0; i < test_set.burst; i++)
		test_add(&limit, 0);
	/* the delay is never longer than one interval */
	test_assert_ucmp(test_delay(&limit, -3600 * 1000), ==, 500);
	/* adding an event resets the burst relative to the new time */
	test_add(&limit, -3600 * 1000 + 500);
	test_assert_ucmp(test_delay(&limit, -3600 * 1000 + 500), ==, 500);
	for (i = 0; i < test_set.burst; i++) {
		test_assert_idx(test_delay(&limit, -3600 * 1000 + 2000) == 0,
				i);
		test_add(&limit, -3600 * 1000 + 2000);
	}
	test_end();
}

void test_rate_limit(void)
{
	struct timeval saved_ioloop_timeval = ioloop_timeval;

	test_rate_limit_burst();
	test_rate_limit_partial_refill();
	test_rate_limit_steady_rate();
	test_rate_limit_usecs();
	test_rate_limit_add_without_waiting();
	test_rate_limit_time_moved_backwards();

	ioloop_timeval = saved_ioloop_timeval;
}
