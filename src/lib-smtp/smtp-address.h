#ifndef SMTP_ADDRESS_H
#define SMTP_ADDRESS_H

#include "array-decl.h"

struct message_address;

enum smtp_address_parse_flags {
	/* Strictly enforce the RFC 5321 syntax */
	SMTP_ADDRESS_PARSE_FLAG_STRICT            = BIT(0),
	/* Allow an empty/NULL address */
	SMTP_ADDRESS_PARSE_FLAG_ALLOW_EMPTY       = BIT(1),
	/* Allow an address without a domain part */
	SMTP_ADDRESS_PARSE_FLAG_ALLOW_LOCALPART   = BIT(2),
	/* Allow omission of the <...> brackets in a path */
	SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL = BIT(3)
};

struct smtp_address {
	const char *localpart;
	const char *domain;
};

ARRAY_DEFINE_TYPE(smtp_address, struct smtp_address *);
ARRAY_DEFINE_TYPE(smtp_address_const, const struct smtp_address *);

/*
 * SMTP address parsing
 */

int smtp_address_parse_mailbox(pool_t pool,
	const char *mailbox, enum smtp_address_parse_flags flags,
	struct smtp_address **address_r, const char **error_r)
	ATTR_NULL(4, 5);
int smtp_address_parse_path_full(pool_t pool, const char *path,
	enum smtp_address_parse_flags flags,
	struct smtp_address **address_r, const char **error_r,
	const char **endp_r) ATTR_NULL(4, 5, 6);
int smtp_address_parse_path(pool_t pool, const char *path,
	enum smtp_address_parse_flags flags,
	struct smtp_address **address_r, const char **error_r)
	ATTR_NULL(4, 5);
int smtp_address_parse_username(pool_t pool, const char *username,
	struct smtp_address **address_r, const char **error_r)
	ATTR_NULL(3, 4);

/* Parse address+detail@domain into address@domain and detail
   using given delimiters. Returns used delimiter. */
void smtp_address_detail_parse(pool_t pool, const char *delimiters,
	struct smtp_address *address, const char **username_r,
	char *delim_r, const char **detail_r);
void smtp_address_detail_parse_temp(const char *delimiters,
	struct smtp_address *address, const char **username_r,
	char *delim_r, const char **detail_r);

/*
 * SMTP address construction
 */

void smtp_address_write(string_t *out,
	const struct smtp_address *address) ATTR_NULL(2);
void smtp_address_write_path(string_t *out,
	const struct smtp_address *address) ATTR_NULL(2);

const char *
smtp_address_encode(const struct smtp_address *address)
	ATTR_NULL(1);
const char *
smtp_address_encode_path(const struct smtp_address *address)
	ATTR_NULL(1);

/*
 * SMTP address manipulation
 */

void smtp_address_init(struct smtp_address *address,
	const char *localpart, const char *domain) ATTR_NULL(2,3);
int smtp_address_init_from_msg(struct smtp_address *address,
			       const struct message_address *msg_addr);

struct smtp_address *
smtp_address_clone(pool_t pool, const struct smtp_address *address)
	ATTR_NULL(2);
struct smtp_address *
smtp_address_create(pool_t pool, const char *localpart, const char *domain)
	ATTR_NULL(2, 3);
int smtp_address_create_from_msg(pool_t pool,
				 const struct message_address *msg_addr,
				 struct smtp_address **address_r);

struct smtp_address *
smtp_address_clone_temp(const struct smtp_address *address)
	ATTR_NULL(1);
struct smtp_address *
smtp_address_create_temp(const char *localpart, const char *domain)
	ATTR_NULL(2, 3);
int smtp_address_create_from_msg_temp(const struct message_address *msg_addr,
				      struct smtp_address **address_r);

struct smtp_address *
smtp_address_add_detail(pool_t pool, const struct smtp_address *address,
	const char *detail, char delim_c);
struct smtp_address *
smtp_address_add_detail_temp(const struct smtp_address *address,
	const char *detail, char delim_c);

int smtp_address_cmp(const struct smtp_address *address1,
	const struct smtp_address *address2)
	ATTR_NULL(1, 2);

static inline bool ATTR_NULL(1, 2)
smtp_address_equals(const struct smtp_address *address1,
	const struct smtp_address *address2)
{
	return (smtp_address_cmp(address1, address2) == 0);
}

static inline bool ATTR_NULL(1) ATTR_PURE
smtp_address_isnull(const struct smtp_address *address)
{
	return (address == NULL || address->localpart == NULL ||
		*address->localpart == '\0');
}

#endif
