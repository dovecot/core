/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "ioloop.h"
#include "event-exporter.h"

void event_export_helper_fmt_unix_time(string_t *dest,
				       const struct timeval *time)
{
	str_printfa(dest, "%"PRIdTIME_T".%06u", time->tv_sec,
		    (unsigned int) time->tv_usec);
}

void event_export_helper_fmt_rfc3339_time(string_t *dest,
					  const struct timeval *time)
{
	const struct tm *tm;

	tm = gmtime(&time->tv_sec);

	str_printfa(dest, "%04d-%02d-%02dT%02d:%02d:%02d.%06luZ",
		    tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
		    tm->tm_hour, tm->tm_min, tm->tm_sec,
		    time->tv_usec);
}
