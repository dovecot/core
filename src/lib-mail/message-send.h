#ifndef __MESSAGE_SEND_H
#define __MESSAGE_SEND_H

struct message_size;

/* Send message to client inserting CRs if needed. Only max_virtual_size
   bytes if sent (relative to virtual_skip), if you want it unlimited,
   use (uoff_t)-1. Remember that if input begins with LF, CR is inserted
   before it unless virtual_skip = 1. Returns TRUE if successful. */
int message_send(struct ostream *output, struct istream *input,
		 struct message_size *msg_size,
		 uoff_t virtual_skip, uoff_t max_virtual_size);

#endif
