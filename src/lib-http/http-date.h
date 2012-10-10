#ifndef HTTP_DATE_H
#define HTTP_DATE_H

/* Parses HTTP-date string into time_t timestamp. */
bool http_date_parse(const unsigned char *data, size_t size,
			time_t *timestamp_r);
/* Equal to http_date_parse, but writes uncompensated timestamp to tm_r. */
bool http_date_parse_tm(const unsigned char *data, size_t size,
			   struct tm *tm_r);

/* Create HTTP-date string from given time struct. */
const char *http_date_create_tm(struct tm *tm);

/* Create HTTP-date string from given time. */
const char *http_date_create(time_t timestamp);

#endif
