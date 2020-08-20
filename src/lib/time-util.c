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

uint64_t i_nanoseconds(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_REALTIME, &ts) < 0)
		i_fatal("clock_gettime() failed: %m");
	return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
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
	long long usecs_diff;
	int sec_margin, ret;

	if (tv1->tv_sec < tv2->tv_sec) {
		sec_margin = ((int)usec_margin / 1000000) + 1;
		if ((tv2->tv_sec - tv1->tv_sec) > sec_margin)
			return -1;
		usecs_diff = (tv2->tv_sec - tv1->tv_sec) * 1000000LL +
			(tv2->tv_usec - tv1->tv_usec);
		ret = -1;
	} else if (tv1->tv_sec > tv2->tv_sec) {
		sec_margin = ((int)usec_margin / 1000000) + 1;
		if ((tv1->tv_sec - tv2->tv_sec) > sec_margin)
			return 1;
		usecs_diff = (tv1->tv_sec - tv2->tv_sec) * 1000000LL +
			(tv1->tv_usec - tv2->tv_usec);
		ret = 1;
	} else if (tv1->tv_usec < tv2->tv_usec) {
		usecs_diff = tv2->tv_usec - tv1->tv_usec;
		ret = -1;
	} else {
		usecs_diff = tv1->tv_usec - tv2->tv_usec;
		ret = 1;
	}
	i_assert(usecs_diff >= 0);
	return (unsigned long long)usecs_diff > usec_margin ? ret : 0;
}

int timeval_diff_msecs(const struct timeval *tv1, const struct timeval *tv2)
{
	long long diff = timeval_diff_usecs(tv1, tv2) / 1000LL;
#ifdef DEBUG
	/* FIXME v2.4: Remove the ifdef */
	i_assert(diff <= INT_MAX);
#endif
	return (int)diff;
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

int str_to_timeval(const char *str, struct timeval *tv_r)
{
	tv_r->tv_usec = 0;

	const char *p = strchr(str, '.');
	if (p == NULL)
		return str_to_time(str, &tv_r->tv_sec);

	int ret;
	T_BEGIN {
		ret = str_to_time(t_strdup_until(str, p++), &tv_r->tv_sec);
	} T_END;
	if (ret < 0 || p[0] == '\0')
		return -1;

	unsigned int len = strlen(p);
	if (len > 6)
		return -1; /* we don't support sub-microseconds */
	char usecs_str[7] = "000000";
	memcpy(usecs_str, p, len);

	unsigned int usec;
	if (str_to_uint(usecs_str, &usec) < 0)
		return -1;
	tv_r->tv_usec = usec;
	return 0;
}
