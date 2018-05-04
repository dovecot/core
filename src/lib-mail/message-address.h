#ifndef MESSAGE_ADDRESS_H
#define MESSAGE_ADDRESS_H

struct smtp_address;

enum message_address_parse_flags {
	/* If enabled, missing mailbox and domain are set to MISSING_MAILBOX
	   and MISSING_DOMAIN strings. Otherwise they're set to "". */
	MESSAGE_ADDRESS_PARSE_FLAG_FILL_MISSING = BIT(0),
	/* Allow local-part to contain any number of dots anywhere in it.
	   For example ".user", "us..ser" and "user." will be valid. This
	   isn't strictly allowed by RFC5322, but these addresses are commonly
	   used in Japan. */
	MESSAGE_ADDRESS_PARSE_FLAG_NON_STRICT_DOTS = BIT(1),
};

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

/* Parse message addresses from given data. Note that giving an empty string
   will return NULL since there are no addresses. */
struct message_address *
message_address_parse(pool_t pool, const unsigned char *data, size_t size,
		      unsigned int max_addresses,
		      enum message_address_parse_flags flags);

/* Parse RFC 5322 "path" (Return-Path header) from given data. Returns -1 if
   the path is invalid and 0 otherwise.
 */
int message_address_parse_path(pool_t pool, const unsigned char *data,
			       size_t size, struct message_address **addr_r);

void message_address_init(struct message_address *addr,
	const char *name, const char *mailbox, const char *domain)
	ATTR_NULL(1);
void message_address_init_from_smtp(struct message_address *addr,
	const char *name, const struct smtp_address *smtp_addr)
	ATTR_NULL(1);

void message_address_write(string_t *str, const struct message_address *addr);
const char *message_address_to_string(const struct message_address *addr);
const char *message_address_first_to_string(const struct message_address *addr);

/* Returns TRUE if header is known to be an address */
bool message_header_is_address(const char *hdr_name);

#endif
