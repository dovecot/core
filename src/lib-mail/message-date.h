#ifndef __MESSAGE_DATE
#define __MESSAGE_DATE

/* Parses RFC2822 date/time string. timezone_offset is filled with the
   timezone's difference to UTC in minutes. */
int message_date_parse(const unsigned char *data, size_t size,
		       time_t *time, int *timezone_offset);

/* Create RFC2822 date/time string from given time in local timezone. */
const char *message_date_create(time_t time);

#endif
