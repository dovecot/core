#ifndef __MESSAGE_SIZE_H
#define __MESSAGE_SIZE_H

#include "message-parser.h"

/* Calculate size of message header. Leave the input point to first
   character in body. */
void message_get_header_size(IStream *input, MessageSize *hdr);
/* Calculate size of message body. Read only max_virtual_size virtual bytes,
   if you want it unlimited, use (uoff_t)-1. If last_cr is not NULL, it's set
   to 1 if last character is CR, 2 if it's virtual CR. */
void message_get_body_size(IStream *input, MessageSize *body,
			   uoff_t max_virtual_size, int *last_cr);

/* Skip number of virtual bytes from putfer. If first character is \n, and
   cr_skipped is FALSE, \r must be sent before it. msg_size is updated if
   it's not NULL. */
void message_skip_virtual(IStream *input, uoff_t virtual_skip,
			  MessageSize *msg_size, int *cr_skipped);

/* Sum contents of src into dest. */
void message_size_add(MessageSize *dest, const MessageSize *src);

#endif
