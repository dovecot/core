#ifndef __GMTOFF_H
#define __GMTOFF_H

#include <time.h>

/* Returns GMT offset in seconds. */
int gmtoff(struct tm *tm, time_t t);

#endif
