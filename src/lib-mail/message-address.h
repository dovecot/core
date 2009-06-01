#ifndef MESSAGE_ADDRESS_H
#define MESSAGE_ADDRESS_H

/* group: ... ; will be stored like:
   {name = NULL, NULL, "group", NULL}, ..., {NULL, NULL, NULL, NULL}
*/
struct message_address {
	struct message_address *next;

	/* display-name */
	const char *name;
	/* route string contains the @ prefix */
	const char *route;
	/* local-part */
	const char *mailbox;
	const char *domain;
	/* there were errors when parsing this address */
	bool invalid_syntax;
};

/* Parse message addresses from given data. If fill_missing is TRUE, missing
   mailbox and domain are set to MISSING_MAILBOX and MISSING_DOMAIN strings.
   Otherwise they're set to "".

   Note that giving an empty string will return NULL since there are no
   addresses. */
struct message_address *
message_address_parse(pool_t pool, const unsigned char *data, size_t size,
		      unsigned int max_addresses, bool fill_missing);

void message_address_write(string_t *str, const struct message_address *addr);

#endif
