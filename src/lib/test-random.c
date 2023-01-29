/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "hash.h"
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

static void test_random_limits(void)
{
	test_begin("random limits");
	test_assert(i_rand_limit(1) == 0);
	test_assert(i_rand_minmax(0, 0) == 0);
	test_assert(i_rand_minmax(UINT32_MAX, UINT32_MAX) == UINT32_MAX);
	test_end();
}

static void test_random_fill(void)
{
	test_begin("random_fill()");
	unsigned int hash = 0;
	for (unsigned int i = 0; i <= (2*RANDOM_READ_BUFFER_SIZE)+1; i++) {
		/* Rely on valgrind to verify that there are no uninitialized
		   bytes, so don't use i_malloc(). */
		unsigned char *buf = malloc(i);
		random_fill(buf, i);
		hash ^= mem_hash(buf, i);
		free(buf);
	}
	/* Try also with some random small numbers */
	for (unsigned int i = 0; i < 100; i++) {
		/* 32 = RANDOM_READ_BUFFER_SIZE */
		unsigned int size = i_rand_minmax(1, RANDOM_READ_BUFFER_SIZE);
		unsigned char *buf = malloc(size);
		random_fill(buf, size);
		hash ^= mem_hash(buf, size);
		free(buf);
	}
	test_out_reason("hash", TRUE, dec2str(hash));
	test_end();
}

void test_random(void)
{
	test_random_median();
	test_random_limits();
	test_random_fill();
}

enum fatal_test_state fatal_random(unsigned int stage)
{
	switch (stage) {
	case 0:
		test_begin("random fatals");
		test_expect_fatal_string("min_val <= max_val");
		(void)i_rand_minmax(1, 0);
		return FATAL_TEST_FAILURE;
	case 1:
		test_expect_fatal_string("upper_bound > 0");
		(void)i_rand_limit(0);
		return FATAL_TEST_FAILURE;
	}
	test_end();
	return FATAL_TEST_FINISHED;
}
