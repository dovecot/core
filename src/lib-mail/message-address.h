#ifndef __MESSAGE_ADDRESS_H
#define __MESSAGE_ADDRESS_H

/* group: ... ; will be stored like:
   {name = "group", NULL, NULL, NULL}, ..., {NULL, NULL, NULL, NULL}
*/
struct message_address {
	struct message_address *next;

	const char *name, *route, *mailbox, *domain;
};

/* data and size are passed directly to message_tokenize_init(), so (size_t)-1
   can be given if data is \0 terminated. If there's more than max_addresses,
   the rest are skipped. Setting max_addresses to 0 disables this. */
struct message_address *
message_address_parse(pool_t pool, const unsigned char *data, size_t size,
		      unsigned int max_addresses);

void message_address_write(string_t *str, const struct message_address *addr);

#endif
