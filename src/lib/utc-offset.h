#ifndef __UTC_OFFSET_H
#define __UTC_OFFSET_H

#include <time.h>

/* Returns given time's offset to UTC in minutes. */
int utc_offset(struct tm *tm, time_t t);

#endif
