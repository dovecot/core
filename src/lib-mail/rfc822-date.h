#ifndef __RFC822_DATE
#define __RFC822_DATE

/* Parses RFC822 date/time string. timezone_offset is filled with the
   timezone's difference to UTC in minutes. */
int rfc822_parse_date(const char *str, time_t *time, int *timezone_offset);

/* Create RFC822 date/time string from given time in local timezone. */
const char *rfc822_to_date(time_t time);

#endif
