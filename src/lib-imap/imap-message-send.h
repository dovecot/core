#ifndef __IMAP_MESSAGE_SEND_H
#define __IMAP_MESSAGE_SEND_H

#include "message-parser.h"

/* Send message to client inserting CRs if needed. If max_virtual_size is
   non-zero, only that much of the message is sent. If msg_fd is -1, only
   msg is used. Returns TRUE if successful. */
int imap_message_send(IOBuffer *outbuf, const char *msg, int msg_fd,
		      MessageSize *size, off_t virtual_skip,
		      size_t max_virtual_size);

#endif
