#ifndef __IMAP_DATE_H
#define __IMAP_DATE_H

/* Parses IMAP date/time string. time_t is filled with UTC date.
   timezone_offset is filled with parsed timezone. If no timezone is given,
   local timezone is assumed. */
int imap_parse_date(const char *str, time_t *time);
int imap_parse_datetime(const char *str, time_t *time, int *timezone_offset);

/* Returns given UTC time in local timezone. */
const char *imap_to_datetime(time_t time);

#endif
