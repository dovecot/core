/* Copyright (c) 2008-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "time-util.h"

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
	return ((long long)secs * 1000000ULL) + usecs;
}
