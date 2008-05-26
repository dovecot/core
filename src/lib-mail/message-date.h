#ifndef MESSAGE_DATE_H
#define MESSAGE_DATE_H

/* Parses RFC2822 date/time string. timezone_offset is filled with the
   timezone's difference to UTC in minutes. */
bool message_date_parse(const unsigned char *data, size_t size,
			time_t *timestamp_r, int *timezone_offset_r);

/* Create RFC2822 date/time string from given time in local timezone. */
const char *message_date_create(time_t timestamp);

#endif
