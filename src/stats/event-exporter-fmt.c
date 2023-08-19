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

	str_printfa(dest, "%04d-%02d-%02dT%02d:%02d:%02d.%06uZ",
		    tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
		    tm->tm_hour, tm->tm_min, tm->tm_sec,
		    (unsigned int) time->tv_usec);
}

void event_export_helper_fmt_categories(string_t *dest,
				        const struct event *event,
					void (*append)(string_t *, const char *),
					const char *separator)
{
	struct event_category_iterator *iter;
	const struct event_category *cat;
	bool first = TRUE;

	iter = event_categories_iterate_init(event);
	while (event_categories_iterate(iter, &cat)) {
		if (!first)
			str_append(dest, separator);

		append(dest, cat->name);

		first = FALSE;
	}
	event_categories_iterate_deinit(&iter);
}
