#ifndef MBOX_FROM_H
#define MBOX_FROM_H

int mbox_from_parse(const unsigned char *msg, size_t size,
		    time_t *time_r, char **sender_r);
const char *mbox_from_create(const char *sender, time_t time);

#endif
