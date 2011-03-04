/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "time-util.h"

static void test_timeval_cmp(void)
{
	static struct timeval input[] = {
		{ 0, 0 }, { 0, 0 },
		{ INT_MAX, 999999 }, { INT_MAX, 999999 },
		{ 0, 0 }, { 0, 1 },
		{ 0, 0 }, { 1, 0 },
		{ 0, 999999 }, { 1, 0 },
		{ 1, 0 }, { 1, 1 },
		{ -INT_MAX, 0 }, { INT_MAX, 0 }
	};
	static int output[] = {
		0,
		0,
		-1,
		-1,
		-1,
		-1,
		-1
	};
	unsigned int i;

	test_begin("timeval_cmp()");
	for (i = 0; i < N_ELEMENTS(input); i += 2) {
		test_assert(timeval_cmp(&input[i], &input[i+1]) == output[i/2]);
		test_assert(timeval_cmp(&input[i+1], &input[i]) == -output[i/2]);
	}
	test_end();
}

static void test_timeval_diff(void)
{
	static struct timeval input[] = {
		{ 1, 0 }, { 0, 999999 },
		{ 1, 0 }, { 0, 999001 },
		{ 1, 1 }, { 0, 999001 },
		{ 2, 1 }, { 1, 0 },
		{ INT_MAX, 0 }, { INT_MAX-1, 1 }
	};
	static int output[] = {
		1,
		999,
		1000,
		1000001,
		999999
	};
	unsigned int i;
	long long udiff;
	int mdiff;

	test_begin("timeval_diff_*()");
	for (i = 0; i < N_ELEMENTS(input); i += 2) {
		udiff = timeval_diff_usecs(&input[i], &input[i+1]);
		mdiff = timeval_diff_msecs(&input[i], &input[i+1]);
		test_assert(udiff == output[i/2]);
		test_assert(mdiff == udiff/1000);

		udiff = timeval_diff_usecs(&input[i+1], &input[i]);
		mdiff = timeval_diff_msecs(&input[i+1], &input[i]);
		test_assert(udiff == -output[i/2]);
		test_assert(mdiff == udiff/1000);
	}
	test_end();
}

void test_time_util(void)
{
	test_timeval_cmp();
	test_timeval_diff();
}
