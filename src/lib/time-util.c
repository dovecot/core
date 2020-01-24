/* Copyright (c) 2008-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "time-util.h"

#include <time.h>

#define STRFTIME_MAX_BUFSIZE (1024*64)

void i_gettimeofday(struct timeval *tv_r)
{
	if (gettimeofday(tv_r, NULL) < 0)
		i_fatal("gettimeofday() failed: %m");
}

int timeval_cmp(const struct timeval *tv1, const struct timeval *tv2)
{
	if (tv1->tv_sec < tv2->tv_sec)
		return -1;
	if (tv1->tv_sec > tv2->tv_sec)
		return 1;
	if (tv1->tv_usec < tv2->tv_usec)
		return -1;
	if (tv1->tv_usec > tv2->tv_usec)
		return 1;
	return 0;
}

int timeval_cmp_margin(const struct timeval *tv1, const struct timeval *tv2,
	unsigned int usec_margin)
{
	unsigned long long usecs_diff;
	int sec_margin, ret;

	if (tv1->tv_sec < tv2->tv_sec) {
		sec_margin = ((int)usec_margin / 1000000) + 1;
		if ((tv2->tv_sec - tv1->tv_sec) > sec_margin)
			return -1;
		usecs_diff = (tv2->tv_sec - tv1->tv_sec) * 1000000ULL +
			(tv2->tv_usec - tv1->tv_usec);
		ret = -1;
	} else if (tv1->tv_sec > tv2->tv_sec) {
		sec_margin = ((int)usec_margin / 1000000) + 1;
		if ((tv1->tv_sec - tv2->tv_sec) > sec_margin)
			return 1;
		usecs_diff = (tv1->tv_sec - tv2->tv_sec) * 1000000ULL +
			(tv1->tv_usec - tv2->tv_usec);
		ret = 1;
	} else if (tv1->tv_usec < tv2->tv_usec) {
		usecs_diff = tv2->tv_usec - tv1->tv_usec;
		ret = -1;
	} else {
		usecs_diff = tv1->tv_usec - tv2->tv_usec;
		ret = 1;
	}
	return usecs_diff > usec_margin ? ret : 0;
}

int timeval_diff_msecs(const struct timeval *tv1, const struct timeval *tv2)
{
	return timeval_diff_usecs(tv1, tv2) / 1000;
}

long long timeval_diff_usecs(const struct timeval *tv1,
			     const struct timeval *tv2)
{
	time_t secs;
	int usecs;

	secs = tv1->tv_sec - tv2->tv_sec;
	usecs = tv1->tv_usec - tv2->tv_usec;
	if (usecs < 0) {
		secs--;
		usecs += 1000000;
	}
	return ((long long)secs * 1000000LL) + usecs;
}

time_t time_to_local_day_start(time_t t)
{
	const struct tm *day_tm;
	struct tm tm;
	time_t new_start_time;

	day_tm = localtime(&t);
	i_zero(&tm);
	tm.tm_year = day_tm->tm_year;
	tm.tm_mon = day_tm->tm_mon;
	tm.tm_mday = day_tm->tm_mday;
	tm.tm_isdst = -1;
	new_start_time = mktime(&tm);
	i_assert(new_start_time != (time_t)-1);
	return new_start_time;
}

static const char *strftime_real(const char *fmt, const struct tm *tm)
{
	size_t bufsize = strlen(fmt) + 32;
	char *buf = t_buffer_get(bufsize);
	size_t ret;

	while ((ret = strftime(buf, bufsize, fmt, tm)) == 0) {
		bufsize *= 2;
		i_assert(bufsize <= STRFTIME_MAX_BUFSIZE);
		buf = t_buffer_get(bufsize);
	}
	t_buffer_alloc(ret + 1);
	return buf;
}

const char *t_strftime(const char *fmt, const struct tm *tm)
{
	return strftime_real(fmt, tm);
}

const char *t_strflocaltime(const char *fmt, time_t t)
{
	return strftime_real(fmt, localtime(&t));
}

const char *t_strfgmtime(const char *fmt, time_t t)
{
	return strftime_real(fmt, gmtime(&t));
}
