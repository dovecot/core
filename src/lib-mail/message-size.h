#ifndef __MESSAGE_SIZE_H
#define __MESSAGE_SIZE_H

#include "message-parser.h"

void message_get_header_size(const char *msg, size_t size, MessageSize *hdr);
void message_get_body_size(const char *msg, size_t size, MessageSize *body);
void message_size_add(MessageSize *dest, MessageSize *src);

#endif
