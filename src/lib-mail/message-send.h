#ifndef __MESSAGE_SEND_H
#define __MESSAGE_SEND_H

#include "message-parser.h"

/* Send message to client inserting CRs if needed. If max_virtual_size is
   not negative, only that much of the message is sent (relative to
   virtual_skip). Returns TRUE if successful. */
int message_send(IOBuffer *outbuf, IOBuffer *inbuf, MessageSize *msg_size,
		 off_t virtual_skip, off_t max_virtual_size);

#endif
