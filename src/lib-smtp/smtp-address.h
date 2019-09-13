#ifndef SMTP_ADDRESS_H
#define SMTP_ADDRESS_H

#include "array-decl.h"

struct message_address;

enum smtp_address_parse_flags {
	/* Strictly enforce the RFC 5321 syntax */
	SMTP_ADDRESS_PARSE_FLAG_STRICT              = BIT(0),
	/* Allow an empty/NULL address */
	SMTP_ADDRESS_PARSE_FLAG_ALLOW_EMPTY         = BIT(1),
	/* Allow an address without a domain part */
	SMTP_ADDRESS_PARSE_FLAG_ALLOW_LOCALPART     = BIT(2),
	/* Allow omission of the <...> brackets in a path. This flag is only
	   relevant for smtp_address_parse_path(). */
	SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL   = BIT(3),
	/* Allow localpart to have all kinds of bad unquoted characters by
	   parsing the last '@' in the string directly as the localpart/domain
	   separator. Addresses starting with `<' or `"' are parsed as normal.
	   The address is rejected when the resulting localpart and domain
	   cannot be used to construct a valid RFC 5321 address.
	 */
	SMTP_ADDRESS_PARSE_FLAG_ALLOW_BAD_LOCALPART = BIT(4),
	/* Store an unparsed copy of the address in the `raw' field of struct
	   smtp_address. When combined with SMTP_ADDRESS_PARSE_FLAG_SKIP_BROKEN,
	   the broken address will be stored there. This flag is only relevant
	   for smtp_address_parse_path(). */
	SMTP_ADDRESS_PARSE_FLAG_PRESERVE_RAW        = BIT(5),
	/* Try to skip over a broken address to allow working around syntax
	   errors in e.g. the sender address for the MAIL command. This flag is
	   only relevant for smtp_address_parse_path*(). The parser will return
	   failure, but it will return a broken address which is be equivalent
	   to <>. The raw broken address string is available in the address->raw
	   field. When the broken address contains control characters or is
	   badly delimited, parsing will still fail completely. */
	SMTP_ADDRESS_PARSE_FLAG_IGNORE_BROKEN       = BIT(6),
};

struct smtp_address {
	/* Localpart */
	const char *localpart;
	/* Domain */
	const char *domain;
	/* Raw, unparsed address. If localpart == NULL, the value of this field
	   is syntactically invalid and MUST NOT be used for any purposes that
	   may be visible to external systems. It can be e.g. used for logging.
	   This is always in mailbox format, meaning that there are no
	   surrounding '<' and '>'.
	 */
	const char *raw;
};

ARRAY_DEFINE_TYPE(smtp_address, struct smtp_address *);
ARRAY_DEFINE_TYPE(smtp_address_const, const struct smtp_address *);

/*
 * SMTP address parsing
 */


/* Parse the RFC 5321 address from the provided mailbox string. Returns 0 when
   the address was parsed successfully and -1 upon error. The address is
   returned in address_r. When address_r is NULL, the provided string will be
   verified for validity as a mailbox only. */
int smtp_address_parse_mailbox(pool_t pool, const char *mailbox,
			       enum smtp_address_parse_flags flags,
			       struct smtp_address **address_r,
			       const char **error_r) ATTR_NULL(4, 5);
/* Parse the RFC 5321 address from the provided path string. Returns 0 when
   the address was parsed successfully and -1 upon error. The address is
   returned in address_r. When address_r is NULL, the provided string will be
   verified for validity as a path only. The endp_r parameter is used to
   return a pointer to the end of the path string, so that the caller can
   continue parsing from there. When the SMTP_ADDRESS_PARSE_FLAG_IGNORE_BROKEN
   flag is set, a broken address will be returned, even when the return value
   is -1 (see above). If it is totally broken, *endp_r will be then be NULL.
 */
int smtp_address_parse_path_full(pool_t pool, const char *path,
				 enum smtp_address_parse_flags flags,
				 struct smtp_address **address_r,
				 const char **error_r, const char **endp_r)
				 ATTR_NULL(4, 5, 6);
/* Parse the RFC 5321 address from the provided path string. Returns 0 when
   the address was parsed successfully and -1 upon error. The address is
   returned in address_r. When address_r is NULL, the provided string will be
   verified for validity as a path only. When the
   SMTP_ADDRESS_PARSE_FLAG_IGNORE_BROKEN flag is set, a broken address will be
   returned, even when the return value is -1 (see above). */
int smtp_address_parse_path(pool_t pool, const char *path,
			    enum smtp_address_parse_flags flags,
			    struct smtp_address **address_r,
			    const char **error_r) ATTR_NULL(4, 5);
/* Parse the RFC 5321 address from the provided username string. A username
   string is not strictly parsed as an RFC 5321 mailbox; it allows a more
   lenient syntax. If the address obtained from splitting the string at the last
   `@' can be encoded back into a valid RFC 5321 mailbox string, parsing the
   username will succeeded. Returns 0 when the address was parsed successfully
   and -1 upon error. The address is returned in address_r. When address_r is
   NULL, the provided string will be verified for validity as a username only.
 */
int smtp_address_parse_username(pool_t pool, const char *username,
				struct smtp_address **address_r,
				const char **error_r) ATTR_NULL(3, 4);

/* Parse address+detail@domain into address@domain and detail
   using given delimiters. Returns used delimiter. */
void smtp_address_detail_parse(pool_t pool, const char *delimiters,
			       struct smtp_address *address,
			       const char **username_r, char *delim_r,
			       const char **detail_r);
void smtp_address_detail_parse_temp(const char *delimiters,
				    struct smtp_address *address,
				    const char **username_r, char *delim_r,
				    const char **detail_r);

/* Parse any (possibly broken) address on the input to the best of our ability
   until end of input or unquoted ` '. Things that are truly evil (unending
   quoted string, control characters and a path without a closing '>') will
   still fail and return -1. If the parse was successful, it will return 0.
   The parsed address string is returned in address_r. Any outer < and > are
   omitted in the parsed address. The endp_r parameter is used to return a
   pointer to the end of the path string, so that the caller can continue
   parsing from there.*/
int smtp_address_parse_any(const char *in, const char **address_r,
			   const char **endp_r) ATTR_NULL(2, 3);

/*
 * SMTP address construction
 */

void smtp_address_write(string_t *out, const struct smtp_address *address)
			ATTR_NULL(2);
void smtp_address_write_path(string_t *out, const struct smtp_address *address)
			ATTR_NULL(2);

const char *smtp_address_encode(const struct smtp_address *address)
				ATTR_NULL(1);
const char *smtp_address_encode_path(const struct smtp_address *address)
				     ATTR_NULL(1);

const char *
smtp_address_encode_raw(const struct smtp_address *address) ATTR_NULL(1);
const char *
smtp_address_encode_raw_path(const struct smtp_address *address) ATTR_NULL(1);

/*
 * SMTP address manipulation
 */

void smtp_address_init(struct smtp_address *address,
		       const char *localpart, const char *domain)
		       ATTR_NULL(2,3);
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
smtp_address_clone_temp(const struct smtp_address *address) ATTR_NULL(1);
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
		     const struct smtp_address *address2) ATTR_NULL(1, 2);

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
