/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "utc-mktime.h"

struct test_utc_mktime_input {
	int year, month, day, hour, min, sec;
};

void test_utc_mktime(void)
{
	static struct test_utc_mktime_input input[] = {
#ifdef TIME_T_SIGNED
		{ 1969, 12, 31, 23, 59, 59 },
		{ 1901, 12, 13, 20, 45, 53 },
#endif
#if (TIME_T_MAX_BITS > 32 || !defined(TIME_T_SIGNED))
		{ 2106, 2, 7, 6, 28, 15 },
#endif
		{ 2007, 11, 7, 1, 7, 20 },
		{ 1970, 1, 1, 0, 0, 0 },
		{ 2038, 1, 19, 3, 14, 7 }
	};
	static time_t output[] = {
#ifdef TIME_T_SIGNED
		-1,
		-2147483647,
#endif
#if (TIME_T_MAX_BITS > 32 || !defined(TIME_T_SIGNED))
		4294967295,
#endif
		1194397640,
		0,
		2147483647
	};
	struct tm tm;
	unsigned int i;
	time_t t;
	bool success;

	for (i = 0; i < N_ELEMENTS(input); i++) {
		memset(&tm, 0, sizeof(tm));
		tm.tm_year = input[i].year - 1900;
		tm.tm_mon = input[i].month - 1;
		tm.tm_mday = input[i].day;
		tm.tm_hour = input[i].hour;
		tm.tm_min = input[i].min;
		tm.tm_sec = input[i].sec;

		t = utc_mktime(&tm);
		success = t == output[i];
		test_out_reason(t_strdup_printf("utc_mktime(%d)", i), success,
				success ? NULL : t_strdup_printf("%ld != %ld",
						     (long)t, (long)output[i]));
	}
}
