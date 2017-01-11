/* Copyright (c) 2009-2017 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "time-util.h"

#include <time.h>

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

static void test_timestamp(const char *ts, int idx)
{
	/* %G:%H:%M:%S */
	const char **t = t_strsplit(ts, ":");
	unsigned len = str_array_length(t);
	test_assert_idx(len == 4, idx);

	/* %G - ISO 8601 year */
	test_assert_idx(strlen(t[0]) == 4, idx);
	unsigned v;
	test_assert_idx(str_to_uint(t[0], &v) == 0, idx);
	test_assert_idx(1000 <= v, idx);
	test_assert_idx(v <= 3000, idx);

	/* %H - hour from 00 to 23 */
	test_assert_idx(strlen(t[1]) == 2, idx);
	test_assert_idx(str_to_uint(t[1], &v) == 0, idx);
	test_assert_idx(v <= 23, idx);

	/* %M - minute from 00 to 59 */
	test_assert_idx(strlen(t[2]) == 2, idx);
	test_assert_idx(str_to_uint(t[2], &v) == 0, idx);
	test_assert_idx(v <= 59, idx);

	/* %S - second from 00 to 60 */
	test_assert_idx(strlen(t[3]) == 2, idx);
	test_assert_idx(str_to_uint(t[3], &v) == 0, idx);
	test_assert_idx(v <= 60, idx);
}

#define TS_FMT "%G:%H:%M:%S"
static void test_strftime_now(void)
{
	test_begin("t_strftime and variants now");

	time_t now = time(NULL);
	test_timestamp(t_strftime(TS_FMT, gmtime(&now)), 0);
	test_timestamp(t_strfgmtime(TS_FMT, now), 1);
	test_timestamp(t_strflocaltime(TS_FMT, now), 2);

	test_end();
}

#define RFC2822_FMT "%a, %d %b %Y %T %z"
static void test_strftime_fixed(void)
{
	test_begin("t_strftime and variants fixed timestamp");

	time_t ts = 1481222536;
	const char *exp = "Thu, 08 Dec 2016 18:42:16 +0000";
	test_assert(strcmp(t_strftime(RFC2822_FMT, gmtime(&ts)), exp) == 0);
	test_assert(strcmp(t_strfgmtime(RFC2822_FMT, ts), exp) == 0);

	test_end();
}

void test_time_util(void)
{
	test_timeval_cmp();
	test_timeval_diff();
	test_strftime_now();
	test_strftime_fixed();
}
