/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "message-address.h"
#include "smtp-parser.h"
#include "smtp-address.h"

/* From RFC 5321:

   Reverse-path     = Path / "<>"
   Forward-path     = Path

   Path             = "<" [ A-d-l ":" ] Mailbox ">"
   A-d-l            = At-domain *( "," At-domain )
                    ; Note that this form, the so-called "source
                    ; route", MUST BE accepted, SHOULD NOT be
                    ; generated, and SHOULD be ignored.
   At-domain        = "@" Domain

   Domain           = sub-domain *("." sub-domain)

   sub-domain       = Let-dig [Ldh-str]
   Let-dig          = ALPHA / DIGIT
   Ldh-str          = *( ALPHA / DIGIT / "-" ) Let-dig

   address-literal  = "[" ( IPv4-address-literal /
                      IPv6-address-literal /
                      General-address-literal ) "]"
                    ; See Section 4.1.3

   Mailbox          = Local-part "@" ( Domain / address-literal )

   Local-part       = Dot-string / Quoted-string
                    ; MAY be case-sensitive
   Dot-string       = Atom *("."  Atom)
   Atom             = 1*atext
 */

/*
 * SMTP address parsing
 */

struct smtp_address_parser {
	struct smtp_parser parser;

	struct smtp_address address;

	bool parse:1;
	bool path:1;
};

static int
smtp_parser_parse_dot_string(struct smtp_parser *parser, const char **value_r)
{
	const unsigned char *pbegin = parser->cur;

	/* Dot-string = Atom *("." Atom)
	 */

	/* NOTE: this deviates from Dot-String syntax to allow some Japanese
	   mail addresses with dots at non-standard places to be accepted. */

	if (parser->cur >= parser->end ||
	    (!smtp_char_is_atext(*parser->cur) && *parser->cur != '.'))
		return 0;
	parser->cur++;

	while (parser->cur < parser->end &&
	       (smtp_char_is_atext(*parser->cur) || *parser->cur == '.'))
		parser->cur++;

	if (value_r != NULL)
		*value_r = t_strndup(pbegin, parser->cur - pbegin);
	return 1;
}

static int
smtp_parse_localpart(struct smtp_parser *parser, const char **localpart_r)
{
	int ret;

	if ((ret = smtp_parser_parse_quoted_string(parser, localpart_r)) != 0)
		return ret;

	return smtp_parser_parse_dot_string(parser, localpart_r);
}

static int
smtp_parse_mailbox(struct smtp_address_parser *aparser,
		   enum smtp_address_parse_flags flags)
{
	struct smtp_parser *parser = &aparser->parser;
	const char **value = NULL;
	int ret;

	/* Mailbox = Local-part "@" ( Domain / address-literal )
	 */

	value = (aparser->parse ? &aparser->address.localpart : NULL);
	if ((ret = smtp_parse_localpart(parser, value)) <= 0)
		return ret;

	if ((parser->cur >= parser->end || *parser->cur != '@') &&
	    (flags & SMTP_ADDRESS_PARSE_FLAG_ALLOW_LOCALPART) == 0) {
		if (parser->cur >= parser->end ||
		    (aparser->path && *parser->cur == '>'))
			parser->error = "Missing domain";
		else
			parser->error = "Invalid character in localpart";
		return -1;
	}

	if (parser->cur >= parser->end || *parser->cur != '@')
		return 1;
	parser->cur++;

	value = (aparser->parse ? &aparser->address.domain : NULL);
	if ((ret = smtp_parser_parse_domain(parser, value)) == 0 &&
	    (ret = smtp_parser_parse_address_literal(
		parser, value, NULL)) == 0) {
		if (parser->cur >= parser->end ||
		    (aparser->path && *parser->cur == '>')) {
			parser->error = "Missing domain after '@'";
			return -1;
		} else {
			parser->error = "Invalid domain";
			return -1;
		}
	}
	return ret;
}

static int smtp_parse_source_route(struct smtp_parser *parser)
{
	/* Source-route = [ A-d-l ":" ]
	   A-d-l        = At-domain *( "," At-domain )
	   At-domain    = "@" Domain
	 */

	/* "@" Domain */
	if (parser->cur >= parser->end || *parser->cur != '@')
		return 0;
	parser->cur++;

	for (;;) {
		/* Domain */
		if (smtp_parser_parse_domain(parser, NULL) <= 0) {
			parser->error =
				"Missing domain after '@' in source route";
			return -1;
		}

		/* *( "," At-domain ) */
		if (parser->cur >= parser->end || *parser->cur != ',')
			break;
		parser->cur++;

		/* "@" Domain */
		if (parser->cur >= parser->end || *parser->cur != '@') {
			parser->error = "Missing '@' after ',' in source route";
			return -1;
		}
		parser->cur++;
	}

	/* ":" */
	if (parser->cur >= parser->end || *parser->cur != ':') {
		parser->error = "Missing ':' at end of source route";
		return -1;
	}
	parser->cur++;
	return 1;
}

static int
smtp_parse_path(struct smtp_address_parser *aparser,
		enum smtp_address_parse_flags flags)
{
	struct smtp_parser *parser = &aparser->parser;
	int ret, sret = 0;

	/* Path = "<" [ A-d-l ":" ] Mailbox ">"
	 */

	/* "<" */
	if (parser->cur < parser->end && *parser->cur == '<') {
		aparser->path = TRUE;
		parser->cur++;
	} else if ((flags & SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL) == 0) {
		return 0;
	}

	/* [ A-d-l ":" ] */
	if (aparser->path && (sret = smtp_parse_source_route(parser)) < 0)
		return -1;

	/* Mailbox */
	if ((ret = smtp_parse_mailbox(aparser, flags)) < 0)
		return -1;
	if (ret == 0) {
		if (parser->cur < parser->end && *parser->cur == '>') {
			if (sret > 0) {
				parser->error =
					"Path only consists of source route";
				return -1;
			}
			if ((flags & SMTP_ADDRESS_PARSE_FLAG_ALLOW_EMPTY)
				== 0) {
				parser->error = "Null path not allowed";
				return -1;
			}
		} else {
			parser->error = "Invalid character in localpart";
			return -1;
		}
	}

	/* ">" */
	if (aparser->path) {
		if (parser->cur >= parser->end || *parser->cur != '>') {
			parser->error = "Missing '>' at end of path";
			return -1;
		}
		parser->cur++;
	} else if (parser->cur < parser->end && *parser->cur == '>') {
		parser->error = "Unmatched '>' at end of path";
		return -1;
	}
	return 1;
}

static int smtp_parse_username(struct smtp_address_parser *aparser)
{
	struct smtp_parser *parser = &aparser->parser;
	const char **value = NULL;
	const unsigned char *p, *dp;
	int ret;

	/* Best-effort extraction of SMTP address from a user name.
	 */

	value = (aparser->parse ? &aparser->address.localpart : NULL);
	if (*parser->cur == '\"') {
		/* if the local part is a quoted string, parse it as any other
		   SMTP address */
		if ((ret = smtp_parse_localpart(parser, value)) <= 0)
			return ret;
	} else {
		/* use the right-most '@' as separator */
		dp = parser->end - 1;
		while (dp > parser->cur && *dp != '@')
			dp--;
		if (dp == parser->cur)
			dp = parser->end;
		/* check whether the resulting localpart could be encoded as
		   quoted string */
		for (p = parser->cur; p < dp; p++) {
			if (!smtp_char_is_qtext(*p) || *p == ' ') {
				parser->error =
					"Invalid character in user name";
				return -1;
			}
		}
		if (aparser->parse) {
			aparser->address.localpart =
				p_strdup_until(parser->pool, parser->cur, dp);
		}
		parser->cur = dp;
	}

	if (parser->cur < parser->end && *parser->cur != '@') {
		parser->error = "Invalid character in user name";
		return -1;
	}

	if (parser->cur >= parser->end || *parser->cur != '@')
		return 1;
	parser->cur++;

	value = (aparser->parse ? &aparser->address.domain : NULL);
	if ((ret = smtp_parser_parse_domain(parser, value)) == 0 &&
	    (ret = smtp_parser_parse_address_literal(
		parser, value, NULL)) == 0) {
		if (parser->cur >= parser->end) {
			parser->error = "Missing domain after '@'";
			return -1;
		} else {
			parser->error = "Invalid domain";
			return -1;
		}
	}
	return ret;
}

int smtp_address_parse_mailbox(pool_t pool, const char *mailbox,
			       enum smtp_address_parse_flags flags,
			       struct smtp_address **address_r,
			       const char **error_r)
{
	struct smtp_address_parser aparser;
	int ret;

	if (address_r != NULL)
		*address_r = NULL;
	if (error_r != NULL)
		*error_r = NULL;

	if (error_r != NULL)
		*error_r = NULL;

	if ((mailbox == NULL || *mailbox == '\0')) {
		if ((flags & SMTP_ADDRESS_PARSE_FLAG_ALLOW_EMPTY) == 0) {
			if (error_r != NULL)
				*error_r = "Mailbox is empty string";
			return -1;
		}

		if (address_r != NULL)
			*address_r = p_new(pool, struct smtp_address, 1);
		return 0;
	}

	i_zero(&aparser);
	smtp_parser_init(&aparser.parser, pool_datastack_create(), mailbox);
	aparser.parse = (address_r != NULL);

	if ((ret = smtp_parse_mailbox(&aparser, flags)) <= 0) {
		if (error_r != NULL) {
			*error_r = (ret < 0 ? aparser.parser.error :
				"Invalid character in localpart");
		}
		return -1;
	}
	if (aparser.parser.cur != aparser.parser.end) {
		if (error_r != NULL)
			*error_r = "Invalid character in mailbox";
		return -1;
	}

	if (address_r != NULL)
		*address_r = smtp_address_clone(pool, &aparser.address);
	return 0;
}

int smtp_address_parse_path_full(pool_t pool, const char *path,
				 enum smtp_address_parse_flags flags,
				 struct smtp_address **address_r,
				 const char **error_r, const char **endp_r)
{
	struct smtp_address_parser aparser;
	int ret;

	if (address_r != NULL)
		*address_r = NULL;
	if (error_r != NULL)
		*error_r = NULL;

	if (path == NULL || *path == '\0') {
		if ((flags & SMTP_ADDRESS_PARSE_FLAG_ALLOW_EMPTY) == 0 ||
		    (flags & SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL) == 0) {
			if (error_r != NULL)
				*error_r = "Path is empty string";
			return -1;
		}
		if (address_r != NULL)
			*address_r = p_new(pool, struct smtp_address, 1);
		return 0;
	}

	i_zero(&aparser);
	smtp_parser_init(&aparser.parser, pool_datastack_create(), path);
	aparser.parse = (address_r != NULL);

	if ((ret = smtp_parse_path(&aparser, flags)) <= 0) {
		if (error_r != NULL) {
			*error_r = (ret < 0 ? aparser.parser.error :
				"Missing '<' at beginning of path");
		}
		return -1;
	}
	if (endp_r != NULL)
		*endp_r = (const char *)aparser.parser.cur;
	else if (aparser.parser.cur != aparser.parser.end) {
		if (error_r != NULL)
			*error_r = "Invalid character in path";
		return -1;
	}

	if (address_r != NULL)
		*address_r = smtp_address_clone(pool, &aparser.address);
	return 0;
}

int smtp_address_parse_path(pool_t pool, const char *path,
			    enum smtp_address_parse_flags flags,
			    struct smtp_address **address_r,
			    const char **error_r)
{
	return smtp_address_parse_path_full(pool, path, flags,
					    address_r, error_r, NULL);
}

int smtp_address_parse_username(pool_t pool, const char *username,
				struct smtp_address **address_r,
				const char **error_r)
{
	struct smtp_address_parser aparser;
	int ret;

	if (address_r != NULL)
		*address_r = NULL;
	if (error_r != NULL)
		*error_r = NULL;

	if ((username == NULL || *username == '\0')) {
		if (error_r != NULL)
			*error_r = "Username is empty string";
		return -1;
	}

	i_zero(&aparser);
	smtp_parser_init(&aparser.parser, pool_datastack_create(), username);
	aparser.parse = (address_r != NULL);

	if ((ret = smtp_parse_username(&aparser)) <= 0) {
		if (error_r != NULL) {
			*error_r = (ret < 0 ? aparser.parser.error :
				"Invalid character in user name");
		}
		return -1;
	}
	if (aparser.parser.cur != aparser.parser.end) {
		if (error_r != NULL)
			*error_r = "Invalid character in user name";
		return -1;
	}

	if (address_r != NULL)
		*address_r = smtp_address_clone(pool, &aparser.address);
	return 0;
}

void smtp_address_detail_parse(pool_t pool, const char *delimiters,
			       struct smtp_address *address,
			       const char **username_r, char *delim_r,
			       const char **detail_r)
{
	const char *localpart;
	const char *user, *p;
	size_t idx;

	i_assert(!smtp_address_isnull(address));

	localpart = address->localpart;
	user = localpart;
	*detail_r = "";
	*delim_r = '\0';

	/* first character that matches the recipient_delimiter */
	idx = strcspn(localpart, delimiters);
	p = (localpart[idx] != '\0' ? &localpart[idx] : NULL);

	if (p != NULL) {
		*delim_r = *p;
		/* user+detail */
		user = p_strdup_until(pool, localpart, p);
		*detail_r = p+1;
	}

	if (address->domain == NULL)
		*username_r = user;
	else if (strchr(user, '@') == NULL) {
		/* username is just glued to the domain... no SMTP escaping */
		*username_r = p_strconcat(pool,	user, "@", address->domain,
					  NULL);
	} else {
		struct smtp_address uaddr;

		/* username contains '@'; apply escaping */
		smtp_address_init(&uaddr, user, address->domain);
		if (pool->datastack_pool)
			*username_r = smtp_address_encode(&uaddr);
		else {
			*username_r =
				p_strdup(pool, smtp_address_encode(&uaddr));
		}
	}
}

void smtp_address_detail_parse_temp(const char *delimiters,
				    struct smtp_address *address,
				    const char **username_r, char *delim_r,
				    const char **detail_r)
{
	smtp_address_detail_parse(pool_datastack_create(), delimiters,
				  address, username_r, delim_r, detail_r);
}

/*
 * SMTP address construction
 */

void smtp_address_write(string_t *out, const struct smtp_address *address)
			ATTR_NULL(2)
{
	bool quoted = FALSE;
	const unsigned char *p, *pend, *pblock;
	size_t begin;

	if (smtp_address_isnull(address))
		return;
	begin = str_len(out);

	/* encode localpart */
	p = (const unsigned char *)address->localpart;
	pend = p + strlen(address->localpart);
	pblock = p;
	while (p < pend) {
		while (p < pend && smtp_char_is_atext(*p))
			p++;

		if (!quoted && p < pend && (*p != '.' || p == pblock)) {
			quoted = TRUE;
			str_insert(out, begin, "\"");
		}

		str_append_data(out, pblock, p - pblock);
		if (p >= pend)
			break;

		if (!quoted) {
			str_append_c(out, '.');
		} else {
			i_assert(smtp_char_is_qpair(*p));
			if (!smtp_char_is_qtext(*p))
				str_append_c(out, '\\');
			str_append_c(out, *p);
		}

		p++;
		pblock = p;
	}

	if (p == pblock && !quoted) {
		quoted = TRUE;
		str_insert(out, begin, "\"");
	}

	if (quoted)
		str_append_c(out, '\"');

	if (address->domain == NULL)
		return;

	str_append_c(out, '@');
	str_append(out, address->domain);
}

void smtp_address_write_path(string_t *out, const struct smtp_address *address)
{
	str_append_c(out, '<');
	smtp_address_write(out, address);
	str_append_c(out, '>');
}

const char *smtp_address_encode(const struct smtp_address *address)
{
	string_t *str = t_str_new(256);
	smtp_address_write(str, address);
	return str_c(str);
}

const char *smtp_address_encode_path(const struct smtp_address *address)
{
	string_t *str = t_str_new(256);
	smtp_address_write_path(str, address);
	return str_c(str);
}

/*
 * SMTP address manipulation
 */

void smtp_address_init(struct smtp_address *address,
		       const char *localpart, const char *domain)
{
	i_zero(address);
	address->localpart = localpart;
	address->domain = (localpart == NULL ? NULL : domain);
}

int smtp_address_init_from_msg(struct smtp_address *address,
			       const struct message_address *msg_addr)
{
	const char *p;

	i_zero(address);
	if (msg_addr->mailbox == NULL)
		return 0;

	/* The message_address_parse() function allows UTF-8 codepoints in
	   the localpart. For SMTP addresses that is not an option, so we
	   need to check this upon conversion. */
	for (p = msg_addr->mailbox; *p != '\0'; p++) {
		if (!smtp_char_is_qpair(*p))
			return -1;
	}

	address->localpart = msg_addr->mailbox;
	address->domain = msg_addr->domain;
	return 0;
}

struct smtp_address *
smtp_address_clone(pool_t pool, const struct smtp_address *src)
{
	struct smtp_address *new;
	size_t size, lpsize, dsize = 0;
	char *data, *localpart, *domain = NULL;

	if (smtp_address_isnull(src))
		return NULL;

	/* @UNSAFE */

	size = sizeof(struct smtp_address);
	lpsize = strlen(src->localpart) + 1;
	size = MALLOC_ADD(size, lpsize);
	if (src->domain != NULL) {
		dsize = strlen(src->domain) + 1;
		size = MALLOC_ADD(size, dsize);
	}

	data = p_malloc(pool, size);
	new = (struct smtp_address *)data;
	localpart = PTR_OFFSET(data, sizeof(*new));
	memcpy(localpart, src->localpart, lpsize);
	if (dsize > 0) {
		domain = PTR_OFFSET(data, sizeof(*new) + lpsize);
		memcpy(domain, src->domain, dsize);
	}
	new->localpart = localpart;
	new->domain = domain;

	return new;
}

struct smtp_address *
smtp_address_create(pool_t pool, const char *localpart, const char *domain)
{
	struct smtp_address addr;

	smtp_address_init(&addr, localpart, domain);
	return smtp_address_clone(pool, &addr);
}


int smtp_address_create_from_msg(pool_t pool,
				 const struct message_address *msg_addr,
				 struct smtp_address **address_r)
{
	struct smtp_address addr;

	if (smtp_address_init_from_msg(&addr, msg_addr) < 0) {
		*address_r = NULL;
		return -1;
	}
	*address_r = smtp_address_clone(pool, &addr);
	return 0;
}

struct smtp_address *smtp_address_clone_temp(const struct smtp_address *src)
{
	struct smtp_address *new;

	if (smtp_address_isnull(src))
		return NULL;

	new = t_new(struct smtp_address, 1);
	new->localpart = t_strdup(src->localpart);
	new->domain = t_strdup(src->domain);
	return new;
}

struct smtp_address *
smtp_address_create_temp(const char *localpart, const char *domain)
{
	struct smtp_address addr;

	smtp_address_init(&addr, localpart, domain);
	return smtp_address_clone_temp(&addr);
}

int  smtp_address_create_from_msg_temp(const struct message_address *msg_addr,
				       struct smtp_address **address_r)
{
	struct smtp_address addr;

	if (smtp_address_init_from_msg(&addr, msg_addr) < 0) {
		*address_r = NULL;
		return -1;
	}
	*address_r = smtp_address_clone_temp(&addr);
	return 0;
}

struct smtp_address *
smtp_address_add_detail(pool_t pool, const struct smtp_address *address,
			const char *detail, char delim_c)
{
	struct smtp_address *new_addr;
	const char delim[] = {delim_c, '\0'};

	i_assert(!smtp_address_isnull(address));

	new_addr = p_new(pool, struct smtp_address, 1);
	new_addr->localpart = p_strconcat(pool,	address->localpart, delim,
					  detail, NULL);
	new_addr->domain = p_strdup(pool, address->domain);

	return new_addr;
}

struct smtp_address *
smtp_address_add_detail_temp(const struct smtp_address *address,
			     const char *detail, char delim_c)
{
	struct smtp_address *new_addr;
	const char delim[] = {delim_c, '\0'};

	i_assert(!smtp_address_isnull(address));

	new_addr = t_new(struct smtp_address, 1);
	new_addr->localpart = t_strconcat(address->localpart, delim, detail,
					  NULL);
	new_addr->domain = t_strdup(address->domain);

	return new_addr;
}

int smtp_address_cmp(const struct smtp_address *address1,
		     const struct smtp_address *address2)
{
	bool null1, null2;
	int ret;

	null1 = smtp_address_isnull(address1);
	null2 = smtp_address_isnull(address2);
	if (null1)
		return (null2 ? 0 : -1);
	else if (null2)
		return 1;
	if ((ret = null_strcasecmp(address1->domain, address2->domain)) != 0)
		return ret;
	return null_strcmp(address1->localpart, address2->localpart);
}
