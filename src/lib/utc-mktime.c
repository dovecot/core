/* Copyright (c) 2007-2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "utc-mktime.h"

static int tm_cmp(const struct tm *tm1, const struct tm *tm2)
{
	int diff;

	if ((diff = tm1->tm_year - tm2->tm_year) != 0)
		return diff;
	if ((diff = tm1->tm_mon - tm2->tm_mon) != 0)
		return diff;
	if ((diff = tm1->tm_mday - tm2->tm_mday) != 0)
		return diff;
	if ((diff = tm1->tm_hour - tm2->tm_hour) != 0)
		return diff;
	if ((diff = tm1->tm_min - tm2->tm_min) != 0)
		return diff;
	return tm1->tm_sec - tm2->tm_sec;
}

time_t utc_mktime(const struct tm *tm)
{
	const struct tm *try_tm;
	time_t t;
	int bits, dir;

	/* we'll do a binary search across the entire valid time_t range.
	   when gmtime()'s output matches the tm parameter, we've found the
	   correct time_t value. this also means that if tm contains invalid
	   values, -1 is returned. */
#ifdef TIME_T_SIGNED
	t = 0;
#else
	t = (time_t)1 << (TIME_T_MAX_BITS - 1);
#endif
	for (bits = TIME_T_MAX_BITS - 2;; bits--) {
		try_tm = gmtime(&t);
		dir = tm_cmp(tm, try_tm);
		if (dir == 0)
			return t;
		if (bits < 0)
			break;

		if (dir < 0)
			t -= (time_t)1 << bits;
		else
			t += (time_t)1 << bits;
	}

	return (time_t)-1;
}
