#ifndef __MESSAGE_ADDRESS_H
#define __MESSAGE_ADDRESS_H

struct message_address {
	struct message_address *next;

	const char *name, *route, *mailbox, *domain;
};

struct message_address *
message_address_parse(pool_t pool, const unsigned char *data, size_t size);

#endif
