#ifndef __IMAP_DATE_H
#define __IMAP_DATE_H

int imap_parse_date(const char *str, time_t *time);
int imap_parse_datetime(const char *str, time_t *time);

const char *imap_to_datetime(time_t time);
const char *imap_to_date(time_t time);

#endif
