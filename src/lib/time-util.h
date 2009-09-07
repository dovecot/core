#ifndef TIME_UTIL_H
#define TIME_UTIL_H

#include <sys/time.h> /* for struct timeval */

/* Returns -1 if tv1<tv2, 1 if tv1>tv2, 0 if they're equal. */
int timeval_cmp(const struct timeval *tv1, const struct timeval *tv2);
/* Returns tv1-tv2 in milliseconds. */
int timeval_diff_msecs(const struct timeval *tv1, const struct timeval *tv2);
/* Returns tv1-tv2 in microseconds. */
long long timeval_diff_usecs(const struct timeval *tv1,
			     const struct timeval *tv2);

#endif
