/*
    Copyright (c) 2002 Timo Sirainen

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "lib.h"
#include "utc-offset.h"

#include <sys/time.h>

int utc_offset(struct tm *tm, time_t t __attr_unused__)
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
	if (ltm.tm_yday < gtm.tm_yday)
		offset = -24 * 60;
	else if (ltm.tm_yday > gtm.tm_yday)
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
