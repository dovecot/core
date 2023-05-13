/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "env-util.h"
#include "imap-date.h"
#include "test-common.h"

#include <time.h>

static void test_imap_date(void)
{
	const struct {
		const char *str;
		time_t timestamp;
	} tests[] = {
		{ "01-Jan-1970", 0 },
		{ "19-Jan-2038", 2147472000 },
#if TIME_T_MAX_BITS >= 32
		{ "07-Feb-2106", 4294944000 },
#endif
#if TIME_T_MAX_BITS >= 37
		{ "08-Apr-6325", 137438899200LL },
#endif
#if TIME_T_MAX_BITS >= 38
		{ "31-Dec-9999", 253402214400LL },
#endif
		/* conversions to maximum values */
#if TIME_T_MAX_BITS == 31
		{ "20-Jan-2038", 2147483647 },
		{ "31-Dec-9999", 2147483647 },
#elif TIME_T_MAX_BITS == 32
		{ "08-Feb-2106", 4294967295 },
		{ "31-Dec-9999", 4294967295 },
#endif
	};
	const char *invalid_tests[] = {
		"32-Jan-2023",
		"29-Feb-2023",
		"31-Apr-2023",
	};
	time_t ts;

	test_begin("imap_parse_date()");
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		test_assert_idx(imap_parse_date(tests[i].str, &ts), i);
		test_assert_cmp_idx(tests[i].timestamp, ==, ts, i);
	}
	for (unsigned int i = 0; i < N_ELEMENTS(invalid_tests); i++)
		test_assert_idx(!imap_parse_date(invalid_tests[i], &ts), i);
	test_end();
}

static void test_imap_datetime(void)
{
	const struct {
		const char *str;
		time_t timestamp;
		int tz;
	} tests[] = {
		{ "01-Jan-1970 00:00:00 +0000", 0, 0 },
		{ "19-Jan-2038 03:14:07 +0000", 2147483647, 0 },
		{ "19-Jan-2038 05:14:07 +0200", 2147483647, 2*60 },
#if TIME_T_MAX_BITS >= 32
		{ "07-Feb-2106 06:28:15 +0000", 4294967295, 0 },
#endif
#if TIME_T_MAX_BITS >= 37
		{ "08-Apr-6325 15:04:31 +0000", 137438953471LL, 0 },
#endif
#if TIME_T_MAX_BITS >= 38
		{ "31-Dec-9999 23:59:59 +2359", 253402300799LL - 23*60*60 - 59*60, 23*60 + 59 },
		{ "31-Dec-9999 23:59:59 -2359", 253402300799LL + 23*60*60 + 59*60, -23*60 - 59 },
#endif
		/* conversions to maximum values */
#if TIME_T_MAX_BITS == 31
		{ "19-Jan-2038 03:14:08 +0000", 2147483647, 0 },
		{ "31-Dec-9999 23:59:59 -2359", 2147483647, -23*60 - 59 },
#elif TIME_T_MAX_BITS == 32
		{ "07-Feb-2106 06:28:16 +0000", 4294967295, 0 },
		{ "31-Dec-9999 23:59:59 -2359", 4294967295, -23*60 - 59 },
#endif
	};
	const char *invalid_tests[] = {
		"02-Jan-2023 24:00:00",
		"02-Jan-2023 23:60:00",
		"02-Jan-2023 23:00:60",
	};
	time_t ts;
	int tz;

	test_begin("imap_parse_date()");
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		test_assert_idx(imap_parse_datetime(tests[i].str, &ts, &tz), i);
		test_assert_cmp_idx(tests[i].timestamp, ==, ts, i);
		test_assert_idx(tests[i].tz == tz, i);
	}
	for (unsigned int i = 0; i < N_ELEMENTS(invalid_tests); i++)
		test_assert_idx(!imap_parse_datetime(invalid_tests[i], &ts, &tz), i);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_imap_date,
		test_imap_datetime,
		NULL
	};
	env_put("TZ", "UTC");
	tzset();
	return test_run(test_functions);
}
