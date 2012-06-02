#ifndef ISO8601_DATE_H
#define ISO8601_DATE_H

/* Parses ISO8601 (RFC3339) date-time string. timezone_offset is filled with the
   timezone's difference to UTC in minutes. Returned time_t timestamp is
   compensated for time zone. */
bool iso8601_date_parse(const unsigned char *data, size_t size,
			time_t *timestamp_r, int *timezone_offset_r);
/* Equal to iso8601_date_parse, but writes uncompensated timestamp to tm_r. */
bool iso8601_date_parse_tm(const unsigned char *data, size_t size,
			   struct tm *tm_r, int *timezone_offset_r);

/* Create ISO8601 date-time string from given time struct in specified
   timezone. A zone offset of zero will not to 'Z', but '+00:00'. If
   zone_offset == INT_MAX, the time zone will be 'Z'. */
const char *iso8601_date_create_tm(struct tm *tm, int zone_offset);

/* Create ISO8601 date-time string from given time in local timezone. */
const char *iso8601_date_create(time_t timestamp);

#endif
