#ifndef MBOX_FROM_H
#define MBOX_FROM_H

/* Parse time and sender from mbox-compatible From_-line. msg points to the
   data after "From ". */
int mbox_from_parse(const unsigned char *msg, size_t size,
		    time_t *time_r, int *tz_offset_r, char **sender_r);
/* Return a mbox-compatible From_-line using given sender and time.
   The returned string begins with "From ". */
const char *mbox_from_create(const char *sender, time_t timestamp);

#endif
