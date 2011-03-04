/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "utc-offset.h"

#include <sys/time.h>

int utc_offset(struct tm *tm, time_t t ATTR_UNUSED)
{
#ifdef HAVE_TM_GMTOFF
	return (int) (tm->tm_gmtoff/60);
#else
	struct tm ltm, gtm;
	int offset;

	/* gmtime() overwrites tm, so we need to copy it elsewhere */
	ltm = *tm;
	tm = gmtime(&t);
	gtm = *tm;

	/* max offset of 24 hours */
	if ((ltm.tm_yday < gtm.tm_yday && ltm.tm_year == gtm.tm_year) ||
	    ltm.tm_year < gtm.tm_year)
		offset = -24 * 60;
	else if ((ltm.tm_yday > gtm.tm_yday && ltm.tm_year == gtm.tm_year) ||
		 ltm.tm_year > gtm.tm_year)
		offset = 24 * 60;
	else
		offset = 0;

	offset += (ltm.tm_hour - gtm.tm_hour) * 60;
	offset += (ltm.tm_min - gtm.tm_min);

	/* restore overwritten tm */
	*tm = ltm;
	return offset;
#endif
}
