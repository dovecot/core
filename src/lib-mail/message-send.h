#ifndef __MESSAGE_SEND_H
#define __MESSAGE_SEND_H

#include "message-parser.h"

/* Send message to client inserting CRs if needed. Only max_virtual_size
   bytes if sent (relative to virtual_skip), if you want it unlimited,
   use (uoff_t)-1. Returns TRUE if successful. */
int message_send(IOBuffer *outbuf, IOBuffer *inbuf, MessageSize *msg_size,
		 uoff_t virtual_skip, uoff_t max_virtual_size);

#endif
