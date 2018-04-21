/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "net.h"
#include "uri-util.h"

#include <ctype.h>

/* [URI-GEN] RFC3986 Appendix A:

   URI           = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
   absolute-URI  = scheme ":" hier-part [ "?" query ]
   scheme        = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )

   URI-reference = URI / relative-ref
   relative-ref  = relative-part [ "?" query ] [ "#" fragment ]

   relative-part = "//" authority path-abempty
                 / path-absolute
                 / path-noscheme
                 / path-empty
   hier-part     = "//" authority path-abempty
                 / path-absolute
                 / path-rootless
                 / path-empty

   authority     = [ userinfo "@" ] host [ ":" port ]
   userinfo      = *( unreserved / pct-encoded / sub-delims / ":" )
   host          = IP-literal / IPv4address / reg-name
   port          = *DIGIT

   IP-literal    = "[" ( IPv6address / IPvFuture  ) "]"
   IPvFuture     = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
   IPv6address   =                            6( h16 ":" ) ls32
                 /                       "::" 5( h16 ":" ) ls32
                 / [               h16 ] "::" 4( h16 ":" ) ls32
                 / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
                 / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
                 / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
                 / [ *4( h16 ":" ) h16 ] "::"              ls32
                 / [ *5( h16 ":" ) h16 ] "::"              h16
                 / [ *6( h16 ":" ) h16 ] "::"
   h16           = 1*4HEXDIG
   ls32          = ( h16 ":" h16 ) / IPv4address
   IPv4address   = dec-octet "." dec-octet "." dec-octet "." dec-octet
   dec-octet     = DIGIT                 ; 0-9
                 / %x31-39 DIGIT         ; 10-99
                 / "1" 2DIGIT            ; 100-199
                 / "2" %x30-34 DIGIT     ; 200-249
                 / "25" %x30-35          ; 250-255
   reg-name      = *( unreserved / pct-encoded / sub-delims )

   path          = path-abempty    ; begins with "/" or is empty
                 / path-absolute   ; begins with "/" but not "//"
                 / path-noscheme   ; begins with a non-colon segment
                 / path-rootless   ; begins with a segment
                 / path-empty      ; zero characters
   path-abempty  = *( "/" segment )
   path-absolute = "/" [ segment-nz *( "/" segment ) ]
   path-noscheme = segment-nz-nc *( "/" segment )
   path-rootless = segment-nz *( "/" segment )
   path-empty    = 0<pchar>

   segment       = *pchar
   segment-nz    = 1*pchar
   segment-nz-nc = 1*( unreserved / pct-encoded / sub-delims / "@" )
                 ; non-zero-length segment without any colon ":"
   pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"

   query         = *( pchar / "/" / "?" )
   fragment      = *( pchar / "/" / "?" )

   pct-encoded   = "%" HEXDIG HEXDIG
   unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
   reserved      = gen-delims / sub-delims
   gen-delims    = ":" / "/" / "?" / "#" / "[" / "]" / "@"
   sub-delims    = "!" / "$" / "&" / "'" / "(" / ")"
                 / "*" / "+" / "," / ";" / "="
 */

#define URI_MAX_SCHEME_NAME_LEN 64

/* Character lookup table
 *
 * unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"     [bit0]
 * sub-delims    = "!" / "$" / "&" / "'" / "(" / ")"
 *               / "*" / "+" / "," / ";" / "="               [bit1]
 * gen-delims    = ":" / "/" / "?" / "#" / "[" / "]" / "@"   [bit2]
 * pchar         = unreserved / sub-delims / ":" / "@"       [bit0|bit1|bit3]
 * 'pfchar'      = unreserved / sub-delims / ":" / "@" / "/" 
 *                                                      [bit0|bit1|bit3|bit5]
 * 'uchar'       = unreserved / sub-delims / ":"             [bit0|bit1|bit4]
 * 'qchar'       = pchar / "/" / "?"               [bit0|bit1|bit3|bit5|bit6]
 *
 */

#define CHAR_MASK_UNRESERVED (1<<0)
#define CHAR_MASK_SUB_DELIMS (1<<1)
#define CHAR_MASK_PCHAR ((1<<0)|(1<<1)|(1<<3))
#define CHAR_MASK_PFCHAR ((1<<0)|(1<<1)|(1<<3)|(1<<5))
#define CHAR_MASK_UCHAR ((1<<0)|(1<<1)|(1<<4))
#define CHAR_MASK_QCHAR ((1<<0)|(1<<1)|(1<<3)|(1<<5)|(1<<6))

static unsigned const char _uri_char_lookup[256] = {
	 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  // 00
	 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  // 10
	 0,  2,  0,  4,  2,  0,  2,  2,  2,  2,  2,  2,  2,  1,  1, 36,  // 20
	 1,  1,  1,  1,  1,  1,  1,  1,  1,  1, 28,  2,  0,  2,  0, 68,  // 30
	12,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  // 40
	 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  4,  0,  4,  0,  1,  // 50
	 0,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  // 60
	 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  0,  0,  0,  1,  0,  // 70
};

static inline int _decode_hex_digit(const unsigned char digit)
{
	switch (digit) {
	case '0': case '1': case '2': case '3': case '4':
	case '5': case '6': case '7': case '8': case '9':
		return digit - '0';

	case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
		return digit - 'a' + 0x0a;

	case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
		return digit - 'A' + 0x0A;
	}
	return -1;
}

static int
uri_parse_pct_encoded_data(struct uri_parser *parser,
		      const unsigned char **p, const unsigned char *pend,
		      unsigned char *ch_r) ATTR_NULL(3)
{
	int value;

	if (**p != '%' || (pend != NULL && *p >= pend))
		return 0;
	*p += 1;

	if (**p == 0 || *(*p+1) == 0 || (pend != NULL && *p+1 >= pend)) {
		parser->error = "Unexpected URI boundary after '%'";
		return -1;
	}

	if ((value = _decode_hex_digit(**p)) < 0) {
		parser->error = p_strdup_printf(parser->pool,
			"Expecting hex digit after '%%', but found '%c'", **p);
		return -1;
	}
	
	*ch_r = (value & 0x0f) << 4;
	*p += 1;
	
	if ((value = _decode_hex_digit(**p)) < 0) {
		parser->error = p_strdup_printf(parser->pool,
			"Expecting hex digit after '%%%c', but found '%c'",	*((*p)-1), **p);
		return -1;
	}

	*ch_r |= (value & 0x0f);
	*p += 1;

	if (!parser->allow_pct_nul && *ch_r == '\0') {
		parser->error =
			"Percent encoding is not allowed to encode NUL character";
		return -1;
	}
	return 1;	
}

int uri_parse_pct_encoded(struct uri_parser *parser,
		      unsigned char *ch_r)
{
	return uri_parse_pct_encoded_data
		(parser, &parser->cur, parser->end, ch_r);
}

static int
uri_parse_unreserved_char(struct uri_parser *parser, unsigned char *ch_r)
{
	if ((*parser->cur & 0x80) != 0)
		return 0;

	if ((_uri_char_lookup[*parser->cur] & CHAR_MASK_UNRESERVED) != 0) {
		*ch_r = *parser->cur;
		parser->cur++;
		return 1;
	}			
	return 0;
}

int uri_parse_unreserved(struct uri_parser *parser, string_t *part)
{
	int len = 0;

	while (parser->cur < parser->end) {
		int ret;
		unsigned char ch = 0;

		if ((ret = uri_parse_unreserved_char(parser, &ch)) < 0)
			return -1;
		if (ret == 0)
			break;

		if (part != NULL)
			str_append_c(part, ch);
		len++;
	}

	return len > 0 ? 1 : 0;
}

int uri_parse_unreserved_pct(struct uri_parser *parser, string_t *part)
{
	int len = 0;

	while (parser->cur < parser->end) {
		int ret;
		unsigned char ch = 0;

		if ((ret=uri_parse_pct_encoded(parser, &ch)) < 0)
			return -1;
		else if (ret == 0 &&
			(ret=uri_parse_unreserved_char(parser, &ch)) < 0)
			return -1;
		if (ret == 0)
			break;

		if (part != NULL)
			str_append_c(part, ch);
		len++;
	}

	return len > 0 ? 1 : 0;
}

bool uri_data_decode(struct uri_parser *parser, const char *data,
		     const char *until, const char **decoded_r)
{
	const unsigned char *p = (const unsigned char *)data;
	const unsigned char *pend = (const unsigned char *)until;
	string_t *decoded;
	int ret;

	if (pend == NULL) {
		/* NULL means unlimited; solely rely on '\0' */
		pend = (const unsigned char *)(size_t)-1;
	}
	
	if (p >= pend || *p == '\0') {
		if (decoded_r != NULL)
			*decoded_r = "";
		return TRUE;
	}
	
	decoded = uri_parser_get_tmpbuf(parser, 256);
	while (p < pend && *p != '\0') {
		unsigned char ch;

		if ((ret=uri_parse_pct_encoded_data
			(parser, &p, NULL, &ch)) != 0) {
			if (ret < 0)
				return FALSE;
			str_append_c(decoded, ch);
		} else {
			str_append_c(decoded, *p);
			p++;
		}
	}

	if (decoded_r != NULL)
		*decoded_r = p_strdup(parser->pool, str_c(decoded));
	return TRUE;
}

int uri_parse_scheme(struct uri_parser *parser, const char **scheme_r)
{
	const unsigned char *first = parser->cur;
	size_t len = 1;
	
	/* RFC 3968:
	 *   scheme  = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
	 */
	
	if (parser->cur >= parser->end || !i_isalpha(*parser->cur))
		return 0;
	parser->cur++;
		
	while (len < URI_MAX_SCHEME_NAME_LEN &&
		parser->cur < parser->end) {
		if (!i_isalnum(*parser->cur) &&
			*parser->cur != '+' && *parser->cur != '-' &&
			*parser->cur != '.')
			break;
		parser->cur++;
		len++;
	}
	
	if (parser->cur >= parser->end || *parser->cur != ':') {
		parser->error = "Invalid URI scheme";
		return -1;
	}
	if (scheme_r != NULL)
		*scheme_r = t_strndup(first, parser->cur - first);
	parser->cur++;
	return 1;
}

int uri_cut_scheme(const char **uri_p, const char **scheme_r)
{
	struct uri_parser parser;

	uri_parser_init(&parser, NULL, *uri_p);
	if (uri_parse_scheme(&parser, scheme_r) <= 0)
		return -1;
	*uri_p = (const char *)parser.cur;
	return 0;
}

static int
uri_parse_dec_octet(struct uri_parser *parser, string_t *literal,
		    uint8_t *octet_r) ATTR_NULL(2)
{
	unsigned int octet = 0;
	int count = 0;

	/* RFC 3986:
	 *
	 * dec-octet     = DIGIT                 ; 0-9
	 *               / %x31-39 DIGIT         ; 10-99
	 *               / "1" 2DIGIT            ; 100-199
	 *               / "2" %x30-34 DIGIT     ; 200-249
	 *               / "25" %x30-35          ; 250-255
	 */

	while (parser->cur < parser->end && i_isdigit(*parser->cur)) {
		octet = octet * 10 + (parser->cur[0] - '0');
		if (octet > 255)
			return -1;

		if (literal != NULL)
			str_append_c(literal, *parser->cur);

		parser->cur++;
		count++;
	}

	if (count > 0) {
		*octet_r = octet;
		return 1;
	}
	return 0;
}

static int
uri_parse_ipv4address(struct uri_parser *parser, string_t *literal,
		      struct in_addr *ip4_r) ATTR_NULL(2,3)
{
	uint8_t octet;
	uint32_t ip = 0;
	int ret;
	int i;

	/* RFC 3986:
	 *
	 * IPv4address   = dec-octet "." dec-octet "." dec-octet "." dec-octet
	 */

	if ((ret = uri_parse_dec_octet(parser, literal, &octet)) <= 0)
		return ret;
	ip = octet;
	
	for (i = 0; i < 3 && parser->cur < parser->end; i++) {
		if (*parser->cur != '.')
			return -1;

		if (literal != NULL)
			str_append_c(literal, '.');
		parser->cur++;

		if ((ret = uri_parse_dec_octet(parser, literal, &octet)) <= 0)
			return -1;
		ip = (ip << 8) + octet;
	}
	
	if (ip4_r != NULL)
		ip4_r->s_addr = htonl(ip);
	return 1;
}

static int
uri_do_parse_reg_name(struct uri_parser *parser,
	string_t *reg_name) ATTR_NULL(2)
{
	/* RFC 3986:
	 *
	 * reg-name      = *( unreserved / pct-encoded / sub-delims )
	*/

	while (parser->cur < parser->end) {
		int ret;
		unsigned char c;

		/* unreserved / pct-encoded */
		if ((ret=uri_parse_pct_encoded(parser, &c)) < 0)
			return -1;
		else if (ret == 0 &&
			(ret=uri_parse_unreserved_char(parser, &c)) < 0)
			return -1;

		if (ret > 0) {
			if (reg_name != NULL)
				str_append_c(reg_name, c);
			continue;
		}

		/* sub-delims */
		c = *parser->cur;
		if ((c & 0x80) == 0 && (_uri_char_lookup[c] & CHAR_MASK_SUB_DELIMS) != 0) {
			if (reg_name != NULL)
				str_append_c(reg_name, *parser->cur);
			parser->cur++;
			continue;
		}
		break;
	}
	return 0;
}

int uri_parse_reg_name(struct uri_parser *parser,
	const char **reg_name_r)
{
	string_t *reg_name = NULL;
	int ret;

	if (reg_name_r != NULL)
		reg_name = uri_parser_get_tmpbuf(parser, 256);

	if ((ret=uri_do_parse_reg_name(parser, reg_name)) <= 0)
		return ret;

	if (reg_name_r != NULL)
		*reg_name_r = str_c(reg_name);
	return 1;
}

static int uri_do_parse_host_name(struct uri_parser *parser,
	string_t *host_name) ATTR_NULL(2)
{
	const unsigned char *first, *part;
	int ret;

	/* RFC 3986, Section 3.2.2:

	   A registered name intended for lookup in the DNS uses the syntax
	   defined in Section 3.5 of [RFC1034] and Section 2.1 of [RFC1123].
	   Such a name consists of a sequence of domain labels separated by ".",
	   each domain label starting and ending with an alphanumeric character
	   and possibly also containing "-" characters.  The rightmost domain
	   label of a fully qualified domain name in DNS may be followed by a
	   single "." and should be if it is necessary to distinguish between
	   the complete domain name and some local domain.

	   RFC 2396, Section 3.2.2 (old URI specification):

	   hostname      = *( domainlabel "." ) toplabel [ "." ]
	   domainlabel   = alphanum | alphanum *( alphanum | "-" ) alphanum
	   toplabel      = alpha | alpha *( alphanum | "-" ) alphanum

	   The description in RFC 3986 is more liberal, so:

	   hostname      = *( domainlabel "." ) domainlabel [ "." ]
	   domainlabel   = alphanum | alphanum *( alphanum | "-" ) alphanum

	   We also support percent encoding in spirit of the generic reg-name,
	   even though this should explicitly not be used according to the RFC.
	   It is, however, not strictly forbidden (unlike older RFC), so we
	   support it.
	 */

	first = part = parser->cur;
	for (;;) {
		const unsigned char *offset;
		unsigned char ch, pch;

		/* alphanum */
		offset = parser->cur;
		ch = pch = *parser->cur;
		if (parser->cur >= parser->end)
			break;
		if ((ret=uri_parse_pct_encoded(parser, &ch)) < 0) {
			return -1;
		} else if (ret > 0) {
			if (!i_isalnum(ch))
				return -1;
			if (host_name != NULL)
				str_append_c(host_name, ch);
			part = parser->cur;
		} else {
			if (!i_isalnum(*parser->cur))
				break;
			parser->cur++;
		}

		if (parser->cur < parser->end) {
			/* *( alphanum | "-" ) alphanum */
			do {
				offset = parser->cur;

				if ((ret=uri_parse_pct_encoded(parser, &ch)) < 0) {
					return -1;
				} else if (ret > 0) {
					if (!i_isalnum(ch) && ch != '-')
						break;
					if (host_name != NULL) {
						if (offset > part)
							str_append_data(host_name, part, offset - part);
						str_append_c(host_name, ch);
					}
					part = parser->cur;
				} else {
					ch = *parser->cur;
					if (!i_isalnum(ch) && ch != '-')
						break;
					parser->cur++;
				}
				pch = ch;
			} while (parser->cur < parser->end);

			if (!i_isalnum(pch)) {
				parser->error = "Invalid domain label in hostname";
				return -1;
			}
		}

		if (host_name != NULL && parser->cur > part)
			str_append_data(host_name, part, parser->cur - part);

		/* "." */
		if (parser->cur >= parser->end || ch != '.')
			break;
		if (host_name != NULL)
			str_append_c(host_name, '.');
		if (parser->cur == offset)
			parser->cur++;
		part = parser->cur;
	}

	if (parser->cur == first)
		return 0;

	/* remove trailing '.' */
	if (host_name != NULL) {
		const char *name = str_c(host_name);

		i_assert(str_len(host_name) > 0);
		if (name[str_len(host_name)-1] == '.')
			str_truncate(host_name, str_len(host_name)-1);
	}
	return 1;
}

int uri_parse_host_name(struct uri_parser *parser,
	const char **host_name_r)
{
	string_t *host_name = NULL;
	int ret;

	if (host_name_r != NULL)
		host_name = uri_parser_get_tmpbuf(parser, 256);

	if ((ret=uri_do_parse_host_name(parser, host_name)) <= 0)
		return ret;

	if (host_name_r != NULL)
		*host_name_r = str_c(host_name);
	return 1;
}

static int
uri_parse_ip_literal(struct uri_parser *parser, string_t *literal,
		     struct in6_addr *ip6_r) ATTR_NULL(2,3)
{
	const unsigned char *p;
	const char *address;
	struct in6_addr ip6;
	int ret;

	/* IP-literal    = "[" ( IPv6address / IPvFuture  ) "]"
	 * IPvFuture     = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
	 * IPv6address   = ; Syntax not relevant: parsed using inet_pton()
	 */

	/* "[" already verified */

	/* Scan for end of address */
	for (p = parser->cur+1; p < parser->end; p++) {
		if (*p == ']')
			break;
	}

	if (p >= parser->end || *p != ']') {
		parser->error = "Expecting ']' at end of IP-literal";
		return -1;
	}

	if (literal != NULL)
		str_append_data(literal, parser->cur, p-parser->cur+1);
	address = t_strdup_until(parser->cur+1, p);
	parser->cur = p + 1;	

	if (*address == '\0') {
		parser->error = "Empty IPv6 host address";
		return -1;
	}
	if (*address == 'v') {
		parser->error = p_strdup_printf(parser->pool,
			"Future IP host address '%s' not supported", address);
		return -1;
	}
	if ((ret = inet_pton(AF_INET6, address, &ip6)) <= 0) {
		parser->error = p_strdup_printf(parser->pool,
			"Invalid IPv6 host address '%s'", address);
		return -1;
	}
	if (ip6_r != NULL)
		*ip6_r = ip6;
	return 1;
}

static int
uri_do_parse_host(struct uri_parser *parser,
	struct uri_host *host, bool host_name)
	ATTR_NULL(2)
{
	const unsigned char *preserve;
	struct in_addr ip4;
	struct in6_addr ip6;
	string_t *literal = NULL;
	int ret;

	/* RFC 3986:
	 *
	 * host          = IP-literal / IPv4address / reg-name
	 */

	if (host != NULL)
		i_zero(host);

	literal = uri_parser_get_tmpbuf(parser, 256);

	/* IP-literal / */
	if (parser->cur < parser->end && *parser->cur == '[') {
		if ((ret=uri_parse_ip_literal(parser, literal, &ip6)) <= 0)
			return -1;

		if (host != NULL) {
			host->name = p_strdup(parser->pool, str_c(literal));;
			host->ip.family = AF_INET6;
			host->ip.u.ip6 = ip6;
		}
		return 1;
	}

	/* IPv4address /
	 *
	 * If it fails to parse, we try to parse it as a reg-name
	 */
	preserve = parser->cur;
	if ((ret = uri_parse_ipv4address(parser, literal, &ip4)) > 0) {
		if (host != NULL) {
			host->name = p_strdup(parser->pool, str_c(literal));
			host->ip.family = AF_INET;
			host->ip.u.ip4 = ip4;
		}
		return ret;
	}
	parser->cur = preserve;
	str_truncate(literal, 0);

	/* reg-name */
	if (host_name) {
		if (uri_do_parse_host_name(parser, literal) < 0)
			return -1;
	} else 	if (uri_do_parse_reg_name(parser, literal) < 0)
		return -1;
	if (host != NULL)
		host->name = p_strdup(parser->pool, str_c(literal));
	return 0;
}

int uri_parse_host(struct uri_parser *parser,
	struct uri_host *host)
{
	return uri_do_parse_host(parser, host, TRUE);
}

static int
uri_parse_port(struct uri_parser *parser,
	struct uri_authority *auth) ATTR_NULL(2)
{
	const unsigned char *first;
	in_port_t port;

	/* RFC 3986:
	 *
	 * port        = *DIGIT
	 */

	first = parser->cur;
	while (parser->cur < parser->end && i_isdigit(*parser->cur))
		parser->cur++;

	if (parser->cur == first)
		return 0;
	if (net_str2port(t_strdup_until(first, parser->cur), &port) < 0) {
		parser->error = "Invalid port number";
		return -1;
	}

	if (auth != NULL)
		auth->port = port;
	return 1;
}

static int
uri_do_parse_authority(struct uri_parser *parser,
	struct uri_authority *auth, bool host_name) ATTR_NULL(2)
{
	const unsigned char *p;
	int ret;
	
	/*
	 * authority     = [ userinfo "@" ] host [ ":" port ]
	 */

	if (auth != NULL)
		i_zero(auth);

	/* Scan ahead to check whether there is a [userinfo "@"] uri component */
	for (p = parser->cur; p < parser->end; p++){
		/* refuse 8bit characters */
		if ((*p & 0x80) != 0)
			break;

		/* break at first delimiter */
		if (*p != '%' && (_uri_char_lookup[*p] & CHAR_MASK_UCHAR) == 0)
			break;
	}

	/* Extract userinfo */	
	if (p < parser->end && *p == '@') {
		if (auth != NULL)
			auth->enc_userinfo = p_strdup_until(parser->pool, parser->cur, p);
		parser->cur = p+1;
	}

	/* host */
	if (uri_do_parse_host(parser,
		(auth == NULL ? NULL : &auth->host), host_name) < 0)
		return -1;
	if (parser->cur == parser->end)
		return 1;
	switch (*parser->cur) {
	case ':': case '/': case '?': case '#':
		break;
	default:
		parser->error = "Invalid host identifier";
		return -1;
	}

	/* [":" port] */
	if (*parser->cur == ':') {
		parser->cur++;
	
		if ((ret = uri_parse_port(parser, auth)) < 0)
			return ret;
		if (parser->cur == parser->end)
			return 1;
		switch (*parser->cur) {
		case '/': case '?': case '#':
			break;
		default:
			parser->error = "Invalid host port";
			return -1;
		}
	}

	return 1;
}

static int
uri_do_parse_slashslash_authority(struct uri_parser *parser,
	struct uri_authority *auth, bool host_name)
	ATTR_NULL(2)
{
	/* "//" authority */

	if ((parser->end - parser->cur) <= 2 || parser->cur[0] != '/' ||
	    parser->cur[1] != '/')
		return 0;

	parser->cur += 2;
	return uri_do_parse_authority(parser, auth, host_name);
}

int uri_parse_authority(struct uri_parser *parser,
	struct uri_authority *auth)
{
	return uri_do_parse_authority(parser, auth, FALSE);
}

int uri_parse_slashslash_authority(struct uri_parser *parser,
	struct uri_authority *auth)
{
	return uri_do_parse_slashslash_authority(parser, auth, FALSE);
}

int uri_parse_host_authority(struct uri_parser *parser,
	struct uri_authority *auth)
{
	return uri_do_parse_authority(parser, auth, TRUE);
}

int uri_parse_slashslash_host_authority(struct uri_parser *parser,
	struct uri_authority *auth)
{
	return uri_do_parse_slashslash_authority(parser, auth, TRUE);
}

int uri_parse_path_segment(struct uri_parser *parser, const char **segment_r)
{
	const unsigned char *first = parser->cur;
	int ret;

	while (parser->cur < parser->end) {
		if (*parser->cur == '%') {
			unsigned char ch = 0;
			if ((ret=uri_parse_pct_encoded(parser, &ch)) < 0)
				return -1;
			if (ret > 0)
				continue;
		}

		if ((*parser->cur & 0x80) != 0 ||
			(_uri_char_lookup[*parser->cur] & CHAR_MASK_PCHAR) == 0)
			break;

		parser->cur++;
	}

	if (parser->cur < parser->end &&
		*parser->cur != '/' && *parser->cur != '?' && *parser->cur != '#' ) {
		parser->error =
			"Path component contains invalid character";
		return -1;
	}

	if (first == parser->cur)
		return 0;

	if (segment_r != NULL)
		*segment_r = p_strdup_until(parser->pool, first, parser->cur);
	return 1;
}

int uri_parse_path(struct uri_parser *parser,
		   int *relative_r, const char *const **path_r)
{
	const unsigned char *pbegin = parser->cur;
	ARRAY_TYPE(const_string) segments;
	const char *segment = NULL;
	unsigned int count;
	int relative = 1;
	int ret;

	count = 0;
	if (path_r != NULL)
		p_array_init(&segments, parser->pool, 16);
	else
		i_zero(&segments);

	/* check for a leading '/' and indicate absolute path
	   when it is present
	 */
	if (parser->cur < parser->end && *parser->cur == '/') {
		parser->cur++;
		relative = 0;
	}
	
	/* parse first segment */
	if ((ret = uri_parse_path_segment(parser, &segment)) < 0)
		return -1;
	
	for (;;) {
		if (ret > 0) {
			/* strip dot segments */
			if (segment[0] == '.') {
				if (segment[1] == '.') {
					if (segment[2] == '\0') {
						/* '..' -> skip and... */
						segment = NULL;

						/* ... pop last segment (if any) */
						if (count > 0) {
							if (path_r != NULL) {
								i_assert(count == array_count(&segments));
								array_delete(&segments, count-1, 1);
							}
							count--;
						} else if ( relative > 0 ) {
							relative++;
						}
					}
				} else if (segment[1] == '\0') {
					/* '.' -> skip */
					segment = NULL;
				}
			}
		} else {
			segment = "";
		}

		if (segment != NULL) {
			if (path_r != NULL)
				array_append(&segments, &segment, 1);
			count++;
		}

		if (parser->cur >= parser->end || *parser->cur != '/')
			break;
		parser->cur++;

		/* parse next path segment */
		if ((ret = uri_parse_path_segment(parser, &segment)) < 0)
			return -1;
	}

	if (relative_r != NULL)
		*relative_r = relative;
	if (path_r != NULL)
		*path_r = NULL;

	if (parser->cur == pbegin) {
		/* path part of URI is empty */
		return 0;
	}

	if (path_r != NULL) {
		/* special treatment for a trailing '..' or '.' */
		if (segment == NULL) {
			segment = "";
			array_append(&segments, &segment, 1);
		}
		array_append_zero(&segments);
		*path_r = array_get(&segments, &count);
	}
	if (parser->cur < parser->end &&
		*parser->cur != '?' && *parser->cur != '#') {
		parser->error = "Path component contains invalid character";
		return -1;
	}
	return 1;
}

int uri_parse_query(struct uri_parser *parser, const char **query_r)
{
	const unsigned char *first = parser->cur;
	int ret;

	/* RFC 3986:
	 *
	 * URI           = { ... } [ "?" query ] { ... }
	 * query         = *( pchar / "/" / "?" )
	 * pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
	 */
	if (parser->cur >= parser->end || *parser->cur != '?')
		return 0;
	parser->cur++;

	while (parser->cur < parser->end) {
		if (*parser->cur == '%') {
			unsigned char ch = 0;
			if ((ret=uri_parse_pct_encoded(parser, &ch)) < 0)
				return -1;
			if (ret > 0)
				continue;
		}

		if ((*parser->cur & 0x80) != 0 ||
			(_uri_char_lookup[*parser->cur] & CHAR_MASK_QCHAR) == 0)
			break;
		parser->cur++;
	}

	if (parser->cur < parser->end && *parser->cur != '#') {
		parser->error = "Query component contains invalid character";
		return -1;
	}

	if (query_r != NULL)
		*query_r = p_strdup_until(parser->pool, first+1, parser->cur);
	return 1;
}

int uri_parse_fragment(struct uri_parser *parser, const char **fragment_r)
{
	const unsigned char *first = parser->cur;
	int ret;

	/* RFC 3986:
	 *
	 * URI           = { ... } [ "#" fragment ]
	 * fragment      = *( pchar / "/" / "?" )
	 * pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
	 */

	if (parser->cur >= parser->end || *parser->cur != '#')
		return 0;
	parser->cur++;

	while (parser->cur < parser->end) {
		if (*parser->cur == '%') {
			unsigned char ch = 0;
			if ((ret=uri_parse_pct_encoded(parser, &ch)) < 0)
				return -1;
			if (ret > 0)
				continue;
		}

		if ((*parser->cur & 0x80) != 0 ||
			(_uri_char_lookup[*parser->cur] & CHAR_MASK_QCHAR) == 0)
			break;
		parser->cur++;
	}

	if (parser->cur < parser->end) {
		parser->error = "Fragment component contains invalid character";
		return -1;
	}

	if (fragment_r != NULL)
		*fragment_r = p_strdup_until(parser->pool, first+1, parser->cur);
	return 1;
}

void uri_parser_init_data(struct uri_parser *parser,
	pool_t pool, const unsigned char *data, size_t size)
{
	i_zero(parser);
	parser->pool = pool;
	parser->begin = parser->cur = data;
	parser->end = data + size;
}

void uri_parser_init(struct uri_parser *parser,
	pool_t pool, const char *uri)
{
	uri_parser_init_data
		(parser, pool, (const unsigned char *)uri, strlen(uri));
}

string_t *uri_parser_get_tmpbuf(struct uri_parser *parser, size_t size)
{
	if (parser->tmpbuf == NULL)
		parser->tmpbuf = str_new(parser->pool, size);
	else
		str_truncate(parser->tmpbuf, 0);
	return parser->tmpbuf;
}

int uri_parse_absolute_generic(struct uri_parser *parser,
	enum uri_parse_flags flags)
{
	int relative, aret, ret = 0;

	/*
	   URI           = scheme ":" hier-part [ "?" query ] [ "#" fragment ]

	   hier-part     = "//" authority path-abempty
		               / path-absolute
		               / path-rootless
		               / path-empty
	   path-abempty  = *( "/" segment )
	   path-absolute = "/" [ segment-nz *( "/" segment ) ]
	   path-rootless = segment-nz *( "/" segment )
	   path-empty    = 0<pchar>

	   segment       = *pchar
	   segment-nz    = 1*pchar
	 */

	/* scheme ":" */
	if ((flags & URI_PARSE_SCHEME_EXTERNAL) == 0 &&
		(ret=uri_parse_scheme(parser, NULL)) <= 0) {
		if (ret == 0)
			parser->error = "Missing scheme";
		return -1;
	}

	/* "//" authority */
	if ((aret=uri_parse_slashslash_authority
		(parser, NULL)) < 0)
		return -1;

	/* path-absolute / path-rootless / path-empty */
	if (aret == 0) {
		ret = uri_parse_path(parser, &relative, NULL);
	/* path-abempty */
	} else if (parser->cur < parser->end && *parser->cur == '/') {
		ret = uri_parse_path(parser,	&relative, NULL);
		i_assert(ret <= 0 || relative == 0);
	}
	if (ret < 0)
		return -1;

	/* [ "?" query ] */
	if (uri_parse_query(parser, NULL) < 0)
		return -1;

	/* [ "#" fragment ] */
	if ((ret=uri_parse_fragment(parser, NULL)) < 0)
		return ret;
	if (ret > 0 && (flags & URI_PARSE_ALLOW_FRAGMENT_PART) == 0) {
		parser->error = "Fragment part not allowed";
		return -1;
	}

	i_assert(parser->cur == parser->end);
	return 0;
}

/*
 * Generic URI manipulation
 */

void uri_host_copy(pool_t pool, struct uri_host *dest,
	const struct uri_host *src)
{
	const char *host_name = src->name;

	/* create host name literal if caller is lazy */
	if (host_name == NULL && src->ip.family != 0) {
		host_name = net_ip2addr(&src->ip);
		i_assert(*host_name != '\0');
	}

	*dest = *src;
	dest->name = p_strdup(pool, host_name);
}

/*
 * Check generic URI
 */

int uri_check_data(const unsigned char *data, size_t size,
	enum uri_parse_flags flags, const char **error_r)
{
	struct uri_parser parser;
	int ret;

	i_zero(&parser);
	parser.pool = pool_datastack_create();
	parser.begin = parser.cur = data;
	parser.end = data + size;

	ret = uri_parse_absolute_generic(&parser, flags);
	*error_r = parser.error;
	return ret;
}

int uri_check(const char *uri, enum uri_parse_flags flags,
	const char **error_r)
{
	return uri_check_data
		((unsigned char *)uri, strlen(uri), flags, error_r);
}

/*
 * Generic URI construction
 */

void uri_data_encode(string_t *out,
	const unsigned char esc_table[256],
	unsigned char esc_mask, const char *esc_extra,
	const char *data)
{
	const unsigned char *pbegin, *p;

	pbegin = p = (const unsigned char *)data;
	while (*p != '\0') {
		if ((*p & 0x80) != 0 || (esc_table[*p] & esc_mask) == 0 ||
			(esc_extra != NULL && strchr(esc_extra, (char)*p) != NULL)) {
			if ((p - pbegin) > 0)
				str_append_data(out, pbegin, p - pbegin);
			str_printfa(out, "%%%02x", *p);
			p++;
			pbegin = p;
		} else {
			p++;
		}
	}
	if ((p - pbegin) > 0)
		str_append_data(out, pbegin, p - pbegin);
}

void uri_append_scheme(string_t *out, const char *scheme)
{
	str_append(out, scheme);
	str_append_c(out, ':');
}

void uri_append_user_data(string_t *out, const char *esc,
	const char *data)
{
	uri_data_encode(out, _uri_char_lookup, CHAR_MASK_UCHAR, esc, data);
}

void uri_append_userinfo(string_t *out, const char *userinfo)
{
	uri_append_user_data(out, NULL, userinfo);
	str_append_c(out, '@');
}

void uri_append_host_name(string_t *out, const char *name)
{
	uri_data_encode(out, _uri_char_lookup,
			CHAR_MASK_UNRESERVED | CHAR_MASK_SUB_DELIMS, NULL, name);
}

void uri_append_host_ip(string_t *out, const struct ip_addr *host_ip)
{
	const char *addr = net_ip2addr(host_ip);

	i_assert(host_ip->family != 0);

	if (host_ip->family == AF_INET) {
		str_append(out, addr);
		return;
	}

	i_assert(host_ip->family == AF_INET6);
	str_append_c(out, '[');
	str_append(out, addr);
	str_append_c(out, ']');
}

void uri_append_host(string_t *out, const struct uri_host *host)
{
	if (host->name != NULL) {
		/* assume IPv6 literal if starts with '['; avoid encoding */
		if (*host->name == '[')
			str_append(out, host->name);
		else
			uri_append_host_name(out, host->name);
	} else
		uri_append_host_ip(out, &host->ip);
}

void uri_append_port(string_t *out, in_port_t port)
{
	if (port != 0)
		str_printfa(out, ":%u", port);
}

void uri_append_path_segment_data(string_t *out, const char *esc,
				  const char *data)
{
	uri_data_encode(out, _uri_char_lookup, CHAR_MASK_PCHAR, esc, data);
}

void uri_append_path_segment(string_t *out, const char *segment)
{
	str_append_c(out, '/');
	if (*segment != '\0')
		uri_append_path_data(out, NULL, segment);
}

void uri_append_path_data(string_t *out, const char *esc,
			  const char *data)
{
	uri_data_encode(out, _uri_char_lookup, CHAR_MASK_PFCHAR, esc, data);
}

void uri_append_path(string_t *out, const char *path)
{
	str_append_c(out, '/');
	if (*path != '\0')
		uri_append_path_data(out, NULL, path);
}

void uri_append_query_data(string_t *out, const char *esc,
			   const char *data)
{
	uri_data_encode(out, _uri_char_lookup, CHAR_MASK_QCHAR, esc, data);
}

void uri_append_query(string_t *out, const char *query)
{
	str_append_c(out, '?');
	if (*query != '\0')
		uri_append_query_data(out, NULL, query);
}

void uri_append_fragment_data(string_t *out, const char *esc,
			      const char *data)
{
	uri_data_encode(out, _uri_char_lookup, CHAR_MASK_QCHAR, esc, data);
}

void uri_append_fragment(string_t *out, const char *fragment)
{
	str_append_c(out, '#');
	if (*fragment != '\0')
		uri_append_fragment_data(out, NULL, fragment);
}
