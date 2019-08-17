#ifndef TIME_UTIL_H
#define TIME_UTIL_H

#include <sys/time.h> /* for struct timeval */

/* Returns -1 if tv1<tv2, 1 if tv1>tv2, 0 if they're equal. */
int timeval_cmp(const struct timeval *tv1, const struct timeval *tv2);
/* Same as timeval_cmp, but tv->usecs must differ by at least usec_margin */
int timeval_cmp_margin(const struct timeval *tv1, const struct timeval *tv2,
		       unsigned int usec_margin);
/* Returns tv1-tv2 in milliseconds. */
int timeval_diff_msecs(const struct timeval *tv1, const struct timeval *tv2);
/* Returns tv1-tv2 in microseconds. */
long long timeval_diff_usecs(const struct timeval *tv1,
			     const struct timeval *tv2);

static inline void
timeval_add_usecs(struct timeval *tv, long long usecs)
{
	i_assert(usecs >= 0);
	tv->tv_sec += usecs / 1000000;
	tv->tv_usec += (usecs % 1000000);
	if (tv->tv_usec >= 1000000) {
		tv->tv_sec++;
		tv->tv_usec -= 1000000;
	}
}

static inline void
timeval_sub_usecs(struct timeval *tv, long long usecs)
{
	i_assert(usecs >= 0);
	tv->tv_sec -= usecs / 1000000;
	tv->tv_usec -= (usecs % 1000000);
	if (tv->tv_usec < 0) {
		tv->tv_sec--;
		tv->tv_usec += 1000000;
	}
}

static inline void
timeval_add_msecs(struct timeval *tv, unsigned int msecs)
{
	tv->tv_sec += msecs / 1000;
	tv->tv_usec += (msecs % 1000) * 1000;
	if (tv->tv_usec >= 1000000) {
		tv->tv_sec++;
		tv->tv_usec -= 1000000;
	}
}

static inline void
timeval_sub_msecs(struct timeval *tv, unsigned int msecs)
{
	tv->tv_sec -= msecs / 1000;
	tv->tv_usec -= (msecs % 1000) * 1000;
	if (tv->tv_usec < 0) {
		tv->tv_sec--;
		tv->tv_usec += 1000000;
	}
}

/* Convert t to local time and return timestamp on that day at 00:00:00. */
time_t time_to_local_day_start(time_t t);

/* Wrappers to strftime() */
const char *t_strftime(const char *fmt, const struct tm *tm) ATTR_STRFTIME(1);
const char *t_strflocaltime(const char *fmt, time_t t) ATTR_STRFTIME(1);
const char *t_strfgmtime(const char *fmt, time_t t) ATTR_STRFTIME(1);

#endif
