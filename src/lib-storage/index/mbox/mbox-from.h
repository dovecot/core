#ifndef __MBOX_FROM_H
#define __MBOX_FROM_H

time_t mbox_from_parse_date(const unsigned char *msg, size_t size);
const char *mbox_from_create(const char *sender, time_t time);

#endif
