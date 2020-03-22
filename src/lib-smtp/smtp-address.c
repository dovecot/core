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
	const unsigned char *address_end;

	bool parse:1;
	bool path:1;
	bool parsed_any:1;
	bool totally_broken:1;
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
smtp_address_parser_find_end(struct smtp_address_parser *aparser,
			     enum smtp_address_parse_flags flags)
{
	struct smtp_parser *parser = &aparser->parser;
	const char *begin = (const char *)parser->begin, *end;
	const char **address_p = NULL;

	if (aparser->address_end != NULL)
		return 0;

	if (aparser->parse &&
	    HAS_ALL_BITS(flags, SMTP_ADDRESS_PARSE_FLAG_PRESERVE_RAW))
		address_p = &aparser->address.raw;
	if (smtp_address_parse_any(begin, address_p, &end) < 0) {
		parser->error = "Invalid character";
		aparser->totally_broken = TRUE;
		return -1;
	}
	aparser->parsed_any = TRUE;
	aparser->address_end = (const unsigned char *)end;
	if (aparser->path) {
		i_assert(aparser->address_end > parser->begin);
		aparser->address_end--;
	}
	return 0;
}

static int
smtp_parse_mailbox(struct smtp_address_parser *aparser,
		   enum smtp_address_parse_flags flags)
{
	struct smtp_parser *parser = &aparser->parser;
	const char **value = NULL;
	const unsigned char *p, *dp;
	int ret;

	/* Mailbox = Local-part "@" ( Domain / address-literal )
	 */

	value = (aparser->parse ? &aparser->address.localpart : NULL);
	if ((flags & SMTP_ADDRESS_PARSE_FLAG_STRICT) != 0 ||
	    (flags & SMTP_ADDRESS_PARSE_FLAG_ALLOW_BAD_LOCALPART) == 0 ||
	    aparser->path || *parser->cur == '\"') {
		if ((ret = smtp_parse_localpart(parser, value)) <= 0)
			return ret;
	} else {
		/* find the end of the address */
		if (smtp_address_parser_find_end(aparser, flags) < 0)
			return -1;
		/* use the right-most '@' as separator */
		dp = aparser->address_end - 1;
		while (dp > parser->cur && *dp != '@')
			dp--;
		if (dp == parser->cur)
			dp = aparser->address_end;
		/* check whether the resulting localpart could be encoded as
		   quoted string */
		for (p = parser->cur; p < dp; p++) {
			if (!smtp_char_is_qtext(*p) &&
			    !smtp_char_is_qpair(*p)) {
				parser->error =
					"Invalid character in localpart";
				return -1;
			}
		}
		if (aparser->parse) {
			aparser->address.localpart =
				p_strdup_until(parser->pool, parser->cur, dp);
		}
		parser->cur = dp;
	}

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
	aparser.address_end = aparser.parser.end;
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

static int
smtp_address_parse_path_broken(struct smtp_address_parser *aparser,
			       enum smtp_address_parse_flags flags,
			       const char **endp_r) ATTR_NULL(3)
{
	struct smtp_parser *parser = &aparser->parser;
	const char *begin = (const char *)parser->begin, *end;
	const char *raw = aparser->address.raw;
	const char **address_p = NULL;

	i_zero(&aparser->address);
	aparser->address.raw = raw;

	if (aparser->totally_broken ||
	    HAS_NO_BITS(flags, SMTP_ADDRESS_PARSE_FLAG_IGNORE_BROKEN))
		return -1;
	if (*begin != '<' &&
	    HAS_NO_BITS(flags, SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL)) {
		/* brackets missing; totally broken */
		return -1;
	}
	i_assert(aparser->parse);
	if (aparser->parsed_any) {
		if (endp_r != NULL)
			*endp_r = (const char *)aparser->address_end;
		return 0;
	}

	if (HAS_ALL_BITS(flags, SMTP_ADDRESS_PARSE_FLAG_PRESERVE_RAW))
		address_p = &aparser->address.raw;
	if (smtp_address_parse_any(begin, address_p, &end) < 0) {
		/* totally broken */
		return -1;
	}
	if (endp_r != NULL)
		*endp_r = end;
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
	if (endp_r != NULL)
		*endp_r = NULL;

	if (path == NULL || *path == '\0') {
		if ((flags & SMTP_ADDRESS_PARSE_FLAG_ALLOW_EMPTY) == 0 ||
		    (flags & SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL) == 0) {
			if (error_r != NULL)
				*error_r = "Path is empty string";
			return -1;
		}
		if (address_r != NULL)
			*address_r = p_new(pool, struct smtp_address, 1);
		if (endp_r != NULL)
			*endp_r = path;
		return 0;
	}

	i_zero(&aparser);
	smtp_parser_init(&aparser.parser, pool_datastack_create(), path);
	aparser.address_end = (endp_r != NULL ? NULL : aparser.parser.end);
	aparser.parse = (address_r != NULL);

	if ((ret = smtp_parse_path(&aparser, flags)) <= 0) {
		if (error_r != NULL) {
			*error_r = (ret < 0 ? aparser.parser.error :
				"Missing '<' at beginning of path");
		}
		ret = -1;
	} else if (endp_r != NULL) {
		if (aparser.parser.cur == aparser.parser.end ||
		    *aparser.parser.cur == ' ' ||
		    HAS_NO_BITS(flags, SMTP_ADDRESS_PARSE_FLAG_IGNORE_BROKEN)) {
			*endp_r = (const char *)aparser.parser.cur;
			ret = 0;
		} else {
			if (error_r != NULL)
				*error_r = "Invalid character in path";
			ret = -1;
		}
	} else if (aparser.parser.cur == aparser.parser.end) {
		ret = 0;
	} else {
		if (error_r != NULL)
			*error_r = "Invalid character in path";
		ret = -1;
	}

	if (ret < 0) {
		/* normal parsing failed */
		if (smtp_address_parse_path_broken(&aparser, flags,
						   endp_r) < 0) {
			/* failed to parse it as a broken address as well */
			return -1;
		}
		/* broken address */
	} else if (HAS_ALL_BITS(flags, SMTP_ADDRESS_PARSE_FLAG_PRESERVE_RAW) &&
		   aparser.address.localpart != NULL) {
		if (aparser.path &&
		    ((const unsigned char *)(path + 1) < aparser.parser.cur)) {
			aparser.address.raw = t_strdup_until(
				path + 1, aparser.parser.cur - 1);
		} else {
			aparser.address.raw = t_strdup_until(
				path, aparser.parser.cur);
		}
	}

	if (address_r != NULL)
		*address_r = smtp_address_clone(pool, &aparser.address);
	return ret;
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
	enum smtp_address_parse_flags flags =
		SMTP_ADDRESS_PARSE_FLAG_ALLOW_LOCALPART |
		SMTP_ADDRESS_PARSE_FLAG_ALLOW_BAD_LOCALPART;

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
	aparser.address_end = aparser.parser.end;
	aparser.parse = (address_r != NULL);

	if ((ret = smtp_parse_mailbox(&aparser, flags)) <= 0) {
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

	if (address->domain == NULL || *address->domain == '\0')
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

int smtp_address_parse_any(const char *in, const char **address_r,
			   const char **endp_r)
{
	const unsigned char *p, *pend, *poffset;
	bool path = FALSE;
	bool quoted = FALSE;

	if (endp_r != NULL)
		*endp_r = in;

	poffset = p = (const unsigned char *)in;
	pend = p + strlen(in);
	if (*p  == '<') {
		path = TRUE;
		p++;
		poffset = p;
	}
	if (*p == '"') {
		quoted = TRUE;
		p++;
	}

	while (p < pend) {
		if (quoted && *p == '\\') {
			p++;
			if (p == pend || *p < 0x20)
				return -1;
			p++;
			if (p == pend)
				break;
		}
		switch (*p) {
		case '"':
			quoted = FALSE;
			break;
		case ' ':
			if (!quoted) {
				if (path)
					return -1;
				if (address_r != NULL)
					*address_r = t_strdup_until(poffset, p);
				if (endp_r != NULL)
					*endp_r = (const char *)p;
				return 0;
			}
			break;
		case '>':
			if (!quoted) {
				if (address_r != NULL)
					*address_r = t_strdup_until(poffset, p);
				if (endp_r != NULL)
					*endp_r = (const char *)(p + 1);
				return 0;
			}
			break;
		default:
			if (*p < 0x20)
				return -1;
			break;
		}
		p++;
	}
	if (quoted || path)
		return -1;
	if (address_r != NULL)
		*address_r = t_strdup_until(poffset, p);
	if (endp_r != NULL)
		*endp_r = (const char *)p;
	return 0;
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

	if (address->domain == NULL || *address->domain == '\0')
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

const char *smtp_address_encode_raw(const struct smtp_address *address)
{
	if (address != NULL && address->raw != NULL && *address->raw != '\0')
		return address->raw;

	return smtp_address_encode(address);
}

const char *smtp_address_encode_raw_path(const struct smtp_address *address)
{
	if (address != NULL && address->raw != NULL && *address->raw != '\0')
		return t_strconcat("<", address->raw, ">", NULL);

	return smtp_address_encode_path(address);
}

/*
 * SMTP address manipulation
 */

void smtp_address_init(struct smtp_address *address,
		       const char *localpart, const char *domain)
{
	i_zero(address);
	if (localpart == NULL || *localpart == '\0')
		return;

	address->localpart = localpart;
	if (domain != NULL && *domain != '\0')
		address->domain = domain;
}

int smtp_address_init_from_msg(struct smtp_address *address,
			       const struct message_address *msg_addr)
{
	const char *p;

	i_zero(address);
	if (msg_addr->mailbox == NULL || *msg_addr->mailbox == '\0')
		return 0;

	/* The message_address_parse() function allows UTF-8 codepoints in
	   the localpart. For SMTP addresses that is not an option, so we
	   need to check this upon conversion. */
	for (p = msg_addr->mailbox; *p != '\0'; p++) {
		if (!smtp_char_is_qpair(*p))
			return -1;
	}

	address->localpart = msg_addr->mailbox;
	if (msg_addr->domain != NULL && *msg_addr->domain != '\0')
		address->domain = msg_addr->domain;
	return 0;
}

struct smtp_address *
smtp_address_clone(pool_t pool, const struct smtp_address *src)
{
	struct smtp_address *new;
	size_t size, lpsize = 0, dsize = 0, rsize = 0;
	char *data, *localpart = NULL, *domain = NULL, *raw = NULL;

	if (src == NULL)
		return NULL;

	/* @UNSAFE */

	size = sizeof(struct smtp_address);
	if (src->localpart != NULL && *src->localpart != '\0') {
		lpsize = strlen(src->localpart) + 1;
		size = MALLOC_ADD(size, lpsize);
	}
	if (src->domain != NULL && *src->domain != '\0') {
		dsize = strlen(src->domain) + 1;
		size = MALLOC_ADD(size, dsize);
	}
	if (src->raw != NULL && *src->raw != '\0') {
		rsize = strlen(src->raw) + 1;
		size = MALLOC_ADD(size, rsize);
	}

	data = p_malloc(pool, size);
	new = (struct smtp_address *)data;
	if (lpsize > 0) {
		localpart = PTR_OFFSET(data, sizeof(*new));
		memcpy(localpart, src->localpart, lpsize);
	}
	if (dsize > 0) {
		domain = PTR_OFFSET(data, sizeof(*new) + lpsize);
		memcpy(domain, src->domain, dsize);
	}
	if (rsize > 0) {
		raw = PTR_OFFSET(data, sizeof(*new) + lpsize + dsize);
		memcpy(raw, src->raw, rsize);
	}
	new->localpart = localpart;
	new->domain = domain;
	new->raw = raw;

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

	if (src == NULL)
		return NULL;

	new = t_new(struct smtp_address, 1);
	new->localpart = t_strdup_empty(src->localpart);
	new->domain = t_strdup_empty(src->domain);
	new->raw = t_strdup_empty(src->raw);
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
	new_addr->domain = p_strdup_empty(pool, address->domain);

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
	new_addr->domain = t_strdup_empty(address->domain);

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

int smtp_address_cmp_icase(const struct smtp_address *address1,
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
	return null_strcasecmp(address1->localpart, address2->localpart);
}
