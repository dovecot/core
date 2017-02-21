#ifndef UTC_MKTIME_H
#define UTC_MKTIME_H

#include <time.h>

/* Like mktime(), but assume that tm is in UTC. Unlike mktime(), values in
   tm fields must be in valid range. Leap second is accepted any time though
   since utc_mktime is often used before applying the time zone offset. */
time_t utc_mktime(const struct tm *tm);

#endif
