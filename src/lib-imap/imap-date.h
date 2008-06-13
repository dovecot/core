#ifndef IMAP_DATE_H
#define IMAP_DATE_H

/* Parses IMAP date/time string and returns TRUE if the string is valid.
   time_t is filled with UTC date. timezone_offset is filled with parsed
   timezone. If no timezone is given, local timezone is assumed.

   If date is too low or too high to fit to time_t, it's set to lowest/highest
   allowed value. This allows you to use the value directly for comparing
   timestamps. */
bool imap_parse_date(const char *str, time_t *timestamp_r);
bool imap_parse_datetime(const char *str, time_t *timestamp_r,
			 int *timezone_offset_r);

/* Returns given UTC timestamp as IMAP date-time string in local timezone. */
const char *imap_to_datetime(time_t timestamp);
/* Returns given UTC timestamp as IMAP date-time string in given timezone. */
const char *imap_to_datetime_tz(time_t timestamp, int timezone_offset);

#endif
