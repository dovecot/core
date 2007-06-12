#ifndef __IMAP_DATE_H
#define __IMAP_DATE_H

/* Parses IMAP date/time string. time_t is filled with UTC date.
   timezone_offset is filled with parsed timezone. If no timezone is given,
   local timezone is assumed.

   Returns TRUE if string is valid. If date is outside valid range for time_t
   (usually only with 32bit time_t), the function still return TRUE but
   returned time is (time_t)-1. */
bool imap_parse_date(const char *str, time_t *time);
bool imap_parse_datetime(const char *str, time_t *time, int *timezone_offset);

/* Returns given UTC time in local timezone. */
const char *imap_to_datetime(time_t time);

#endif
