#ifndef UTC_MKTIME_H
#define UTC_MKTIME_H

#include <time.h>

/* Like mktime(), but assume that tm is in UTC. Unlike mktime(), values in
   tm fields must be in valid range. */
time_t utc_mktime(const struct tm *tm);

#endif
