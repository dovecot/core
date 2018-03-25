/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "stats-dist.h"
#include "randgen.h"
#include <math.h>

#define TEST_RAND_SIZE_MEDIAN 100000.0

static void test_random_median(void)
{
	uint64_t tmp;
	double median, average;

	struct stats_dist *s = stats_dist_init_with_size(TEST_RAND_SIZE_MEDIAN);
	test_begin("test_random (median & average)");
	for(unsigned int i = 0; i < TEST_RAND_SIZE_MEDIAN; i++) {
		uint64_t value;
		value = i_rand_limit(TEST_RAND_SIZE_MEDIAN);
		stats_dist_add(s, value);
	}
	tmp = stats_dist_get_median(s);

	/* median should be 0.5 +-2% */
	median = (double)tmp / TEST_RAND_SIZE_MEDIAN;
	test_assert(fabs(median - 0.5) < 0.01);

	/* average should be 0.5 +- %2 */
	average = stats_dist_get_avg(s) / TEST_RAND_SIZE_MEDIAN;

	test_assert(fabs(average - 0.5) < 0.01);

	stats_dist_deinit(&s);
	test_end();
}

void test_random(void)
{
	test_random_median();
}
