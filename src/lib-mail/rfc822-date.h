#ifndef __RFC822_DATE
#define __RFC822_DATE

int rfc822_parse_date(const char *str, time_t *time);
const char *rfc822_to_date(time_t time);

#endif
