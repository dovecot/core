#ifndef MESSAGE_ADDRESS_H
#define MESSAGE_ADDRESS_H

struct smtp_address;

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

void message_address_init(struct message_address *addr,
	const char *name, const char *mailbox, const char *domain)
	ATTR_NULL(1);
void message_address_init_from_smtp(struct message_address *addr,
	const char *name, const struct smtp_address *smtp_addr)
	ATTR_NULL(1);

void message_address_write(string_t *str, const struct message_address *addr);

/* Returns TRUE if header is known to be an address */
bool message_header_is_address(const char *hdr_name);

/* Parse address+detail@domain into address@domain and detail
   using given delimiters. Returns used delimiter. */
void message_detail_address_parse(const char *delimiters, const char *address,
				  const char **username_r, char *delim_r,
				  const char **detail_r);

#endif
