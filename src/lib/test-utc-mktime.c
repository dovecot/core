/* Copyright (c) 2007-2017 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "utc-mktime.h"

struct test_utc_mktime {
	int year, month, day, hour, min, sec;
	time_t out;
};

void test_utc_mktime(void)
{
	static const struct test_utc_mktime tests[] = {
#ifdef TIME_T_SIGNED
		{ 1969, 12, 31, 23, 59, 59, -1 },
		{ 1901, 12, 13, 20, 45, 53, -2147483647 },
#endif
#if (TIME_T_MAX_BITS > 32 || !defined(TIME_T_SIGNED))
		{ 2106, 2, 7, 6, 28, 15, 4294967295 },
#endif
		{ 2007, 11, 7, 1, 7, 20, 1194397640 },
		{ 1970, 1, 1, 0, 0, 0, 0 },
		{ 2038, 1, 19, 3, 14, 7, 2147483647 },
		{ INT_MAX, INT_MAX, INT_MAX, INT_MAX, INT_MAX, INT_MAX, -1 },
		{ 2038, 1, 19, 3, 14, 8, 2147483648 },
		{ 2106, 2, 7, 6, 28, 15, 4294967295 },
		{ 2106, 2, 7, 6, 28, 16, 4294967296 },
		/* June leap second */
		{ 2015, 6, 30, 23, 59, 59, 1435708799 },
		{ 2015, 6, 30, 23, 59, 60, 1435708799 },
		{ 2015, 7, 1, 0, 0, 0, 1435708800 },
		/* Invalid leap second */
		{ 2017, 1, 24, 16, 40, 60, 1485276059 },
		/* Dec leap second */
		{ 2016, 12, 31, 23, 59, 59, 1483228799 },
		{ 2016, 12, 31, 23, 59, 60, 1483228799 },
		{ 2017, 1, 1, 0, 0, 0, 1483228800 },
	};
	struct tm tm;
	unsigned int i;
	time_t t;
	bool success;

	for (i = 0; i < N_ELEMENTS(tests); i++) {
		const struct test_utc_mktime *test = &tests[i];
		i_zero(&tm);
		tm.tm_year = test->year - 1900;
		tm.tm_mon = test->month - 1;
		tm.tm_mday = test->day;
		tm.tm_hour = test->hour;
		tm.tm_min = test->min;
		tm.tm_sec = test->sec;

		t = utc_mktime(&tm);
		success = t == test->out;
		test_out_reason(t_strdup_printf("utc_mktime(%d)", i), success,
				success ? NULL : t_strdup_printf("%ld != %ld",
							(long)t, (long)test->out));
	}
}
