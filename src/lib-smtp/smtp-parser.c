/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "str.h"
#include "strescape.h"

#include "smtp-parser.h"

#include <ctype.h>

/* Character definitions from RFC 5321/5322:

   textstring  = 1*(%d09 / %d32-126) ; HT, SP, Printable US-ASCII
               = 1*(%x09 / %x20-7e)
   ehlo-param  = 1*(%d33-126)
               = 1*(%x21-7e)
   ehlo-greet  = 1*(%d0-9 / %d11-12 / %d14-127)
               = 1*(%x00-09 / %x0b-0c / %x0e-7f)
   qtext       = %d32-33 / %d35-91 / %d93-126
               = %x20-21 / %x23-5B / %x5d-7e
   quoted-pair = %d92 %d32-126
               = %x5c %x20-7e
   atext       = ALPHA / DIGIT /    ; Printable US-ASCII
                 "!" / "#" /        ;  characters not including
                 "$" / "%" /        ;  specials.  Used for atoms.
                 "&" / "'" /
                 "*" / "+" /
                 "-" / "/" /
                 "=" / "?" /
                 "^" / "_" /
                 "`" / "{" /
                 "|" / "}" /
                 "~"
               = %x21 / %x23-27 / %x2a-2b / %x2d / %x2f-39 / %x3d /
                 %d3f / %x41-5a / %x5e-7e /
   esmtp-value = 1*(%d33-60 / %d62-126)
               = 1*(%x21-3c / %x3e-7e)
   dcontent    = %d33-90 / ; Printable US-ASCII
                 %d94-126  ; excl. "[", "\", "]"
               = %x21-5a / %x5e-7e
   xchar       = any ASCII CHAR between "!" (33) and "~" (126) inclusive,
                 except for "+" and "=". [RFC 3461]
               = %x21-2a / %2c-3c / %x3e-7e

   Bit mappings (FIXME: rearrange):

   (1<<0) => %x21-2a / %2c-3c / %x3e-7e  (xtext)
   (1<<1) => %x21 / %x23-27 / %x2a-2b / %x2d / %x2f-39 / %x3d /
               %d3f / %x41-5a / %x5e-7e /
   (1<<2) => %x28-29 / %x2c / %x2e / %x3a-3c / %x3e / %x40
   (1<<8) => %x00-09 / %x0b-0c / %x0e-20 / %x7f
   (1<<5) => %x09 / %5b-5d
   (1<<4) => %x5b / %x5d
   (1<<3) => %x20
   (1<<9) => %x22
   (1<<6) => %x2b
   (1<<7) => %x3d
 */

/* xtext */
const uint16_t smtp_xtext_char_mask = (1<<0);
/* atext */
const uint16_t smtp_atext_char_mask = (1<<1);
/* dcontent */
const uint16_t smtp_dcontent_char_mask = (1<<1)|(1<<2)|(1<<9);
/* qtext */
const uint16_t smtp_qtext_char_mask = (1<<1)|(1<<2)|(1<<3)|(1<<4);
/* textstring */
const uint16_t smtp_textstr_char_mask = (1<<1)|(1<<2)|(1<<9)|(1<<3)|(1<<5);
/* esmtp-value */
const uint16_t smtp_esmtp_value_char_mask = (1<<0)|(1<<6);
/* ehlo-param */
const uint16_t smtp_ehlo_param_char_mask = (1<<0)|(1<<6)|(1<<7);
/* ehlo-greet */
const uint16_t smtp_ehlo_greet_char_mask = (1<<0)|(1<<6)|(1<<7)|(1<<8);
/* quoted-pair */
const uint16_t smtp_qpair_char_mask = (1<<0)|(1<<3)|(1<<6)|(1<<7);

const uint16_t smtp_char_lookup[256] = {
	0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, // 00
	0x100, 0x120, 0x000, 0x100, 0x100, 0x000, 0x100, 0x100, // 08
	0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, // 10
	0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, // 18
	0x108, 0x003, 0x201, 0x003, 0x003, 0x003, 0x003, 0x003, // 20
	0x005, 0x005, 0x003, 0x042, 0x005, 0x003, 0x005, 0x003, // 28
	0x003, 0x003, 0x003, 0x003, 0x003, 0x003, 0x003, 0x003, // 30
	0x003, 0x003, 0x005, 0x005, 0x005, 0x082, 0x005, 0x003, // 38
	0x005, 0x003, 0x003, 0x003, 0x003, 0x003, 0x003, 0x003, // 40
	0x003, 0x003, 0x003, 0x003, 0x003, 0x003, 0x003, 0x003, // 48
	0x003, 0x003, 0x003, 0x003, 0x003, 0x003, 0x003, 0x003, // 50
	0x003, 0x003, 0x003, 0x031, 0x021, 0x031, 0x003, 0x003, // 58
	0x003, 0x003, 0x003, 0x003, 0x003, 0x003, 0x003, 0x003, // 60
	0x003, 0x003, 0x003, 0x003, 0x003, 0x003, 0x003, 0x003, // 68
	0x003, 0x003, 0x003, 0x003, 0x003, 0x003, 0x003, 0x003, // 70
	0x003, 0x003, 0x003, 0x003, 0x003, 0x003, 0x003, 0x100, // 78

	0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, // 80
	0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, // 88
	0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, // 90
	0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, // 98
	0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, // a0
	0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, // a8
	0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, // b0
	0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, // b8
	0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, // c0
	0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, // c8
	0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, // d0
	0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, // d8
	0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, // e0
	0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, // e8
	0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, // f0
	0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, // f8
};

/*
 * Parser
 */

void smtp_parser_init(struct smtp_parser *parser,
	pool_t pool, const char *data)
{
	parser->pool = pool;
	parser->begin = parser->cur = (unsigned char *)data;
	parser->end = (unsigned char *)data + strlen(data);
	parser->error = NULL;
}

/*
 * Common syntax
 */

static int
smtp_parser_parse_ldh_str(struct smtp_parser *parser,
	string_t *out)
{
	const unsigned char *pbegin = parser->cur, *palnum;

	/* Ldh-str = *( ALPHA / DIGIT / "-" ) Let-dig
	   Let-dig = ALPHA / DIGIT
	 */

	/* Ldh-str */
	palnum = NULL;
	while (parser->cur < parser->end) {
		if (i_isalnum(*parser->cur))
			palnum = parser->cur;
		else if (*parser->cur != '-')
			break;
		parser->cur++;
	}
	if (parser->cur == pbegin || palnum == NULL) {
		parser->cur = pbegin;
		return 0;
	}

	parser->cur = palnum+1;
	if (out != NULL)
		str_append_data(out, pbegin, parser->cur - pbegin);
	return 1;
}

int smtp_parser_parse_domain(struct smtp_parser *parser,
	const char **value_r)
{
	string_t *value = NULL;

	/* Domain     = sub-domain *("." sub-domain)
	   sub-domain = Let-dig [Ldh-str]
	   Let-dig    = ALPHA / DIGIT
	   Ldh-str    = *( ALPHA / DIGIT / "-" ) Let-dig
	  
	   NOTE: A more generic syntax is accepted to be lenient towards
	         systems that don't adhere to the standards. It allows
	         '-' and '_' to occur anywhere in a sub-domain.
	 */

	/* Let-dig (first) (nope) */
	if (parser->cur >= parser->end ||
		(!i_isalnum(*parser->cur) && *parser->cur != '-' &&
			*parser->cur != '_'))
		return 0;

	if (value_r != NULL)
		value = t_str_new(256);

	for (;;) {
		/* Let-dig (nope) */
		if (parser->cur >= parser->end || *parser->cur == '.') {
			parser->error = "Empty sub-domain";
			return -1;
		}
		if (!i_isalnum(*parser->cur) && *parser->cur != '-' &&
			*parser->cur != '_') {
			parser->error = "Invalid character in domain";
			return -1;
		}
		if (value_r != NULL)
			str_append_c(value, *parser->cur);
		parser->cur++;

		/* Ldh-str (nope) */
		while (parser->cur < parser->end) {
			if (!i_isalnum(*parser->cur) && *parser->cur != '-' &&
				*parser->cur != '_')
				break;

			if (value_r != NULL)
				str_append_c(value, *parser->cur);
			parser->cur++;
		}

		/* *("." sub-domain) */
		if (parser->cur >= parser->end || *parser->cur != '.')
			break;

		if (value_r != NULL)
			str_append_c(value, '.');
		parser->cur++;
	}

	if (value_r != NULL)
		*value_r = str_c(value);
	return 1;
}

static int
smtp_parser_parse_snum(struct smtp_parser *parser, string_t *literal,
		       uint8_t *octet_r)
{
	const unsigned char *pbegin = parser->cur;
	uint8_t octet = 0;

	/* Snum                    = 1*3DIGIT
	                           ; representing a decimal integer
	                           ; value in the range 0 through 255
	 */

	if (*parser->cur < '0' || *parser->cur > '9')
		return 0;
	do {
		if (octet >= ((uint8_t)-1 / 10)) {
			if (octet > (uint8_t)-1 / 10)
				return -1;
			if ((uint8_t)(*parser->cur - '0') > ((uint8_t)-1 % 10))
				return -1;
		}
		octet = octet * 10 + (*parser->cur - '0');
		parser->cur++;
	} while (*parser->cur >= '0' && *parser->cur <= '9');

	if (literal != NULL)
		str_append_data(literal, pbegin, parser->cur - pbegin);
	*octet_r = octet;
	return 1;
}

static int
smtp_parser_parse_ipv4_address(struct smtp_parser *parser,
			       string_t *literal, struct in_addr *ip4_r)
{
	uint8_t octet;
	uint32_t ip = 0;
	int ret;
	int i;

	/* IPv4-address-literal    = Snum 3("."  Snum) */
	if ((ret = smtp_parser_parse_snum(parser, literal, &octet)) <= 0)
		return ret;
	ip = octet;

	for (i = 0; i < 3 && parser->cur < parser->end; i++) {
		if (*parser->cur != '.')
			return -1;

		if (literal != NULL)
			str_append_c(literal, '.');
		parser->cur++;

		if ((ret = smtp_parser_parse_snum(parser,
			literal, &octet)) <= 0)
			return -1;
		ip = (ip << 8) + octet;
	}

	if (ip4_r != NULL)
		ip4_r->s_addr = htonl(ip);
	return 1;
}

int smtp_parser_parse_address_literal(struct smtp_parser *parser,
	const char **value_r, struct ip_addr *ip_r)
{
	const unsigned char *pblock;
	struct in_addr ip4;
	struct in6_addr ip6;
	bool ipv6 = FALSE;
	string_t *value = NULL, *tagbuf;
	int ret;

	/* address-literal         = "[" ( IPv4-address-literal /
	                            IPv6-address-literal /
	                            General-address-literal ) "]"
	                           ; See Section 4.1.3

	   IPv6-address-literal    = "IPv6:" IPv6-addr
	   General-address-literal = Standardized-tag ":" 1*dcontent
	   Standardized-tag        = Ldh-str
	                           ; Standardized-tag MUST be specified in a
	                           ; Standards-Track RFC and registered with
	                           ; IANA
	   dcontent                = %d33-90 / ; Printable US-ASCII
	                             %d94-126 ; excl. "[", "\", "]"
	 */

	/* "[" */
	if (parser->cur >= parser->end || *parser->cur != '[')
		return 0;
	parser->cur++;

	if (value_r != NULL) {
		value = t_str_new(128);
		str_append_c(value, '[');
	}
	if (ip_r != NULL)
		i_zero(ip_r);

	/* IPv4-address-literal / ... */
	i_zero(&ip4);
	if ((ret=smtp_parser_parse_ipv4_address(parser, value, &ip4)) != 0) {
		if (ret < 0) {
			parser->error = "Invalid IPv4 address literal";
			return -1;
		}
		if (ip_r != NULL) {
			ip_r->family = AF_INET;
			ip_r->u.ip4 = ip4;
		}

	/* ... / IPv6-address-literal / General-address-literal */
	} else {
		/* IPv6-address-literal    = "IPv6:" IPv6-addr
		   General-address-literal = Standardized-tag ":" 1*dcontent
		   Standardized-tag        = Ldh-str
		 */
		if (value_r != NULL) {
			tagbuf = value;
		} else {
			tagbuf = t_str_new(16);
			str_append_c(tagbuf, '[');
		}
		if ((ret=smtp_parser_parse_ldh_str(parser, tagbuf)) <= 0 ||
			parser->cur >= parser->end || *parser->cur != ':') {
			parser->error = "Invalid address literal";
			return -1;
		}
		if (strcasecmp(str_c(tagbuf)+1, "IPv6") == 0)
			ipv6 = TRUE;
		else if (value_r == NULL) {
			parser->error = t_strdup_printf(
				"Unsupported %s address literal",
				str_c(tagbuf)+1);
			return -1;
		}
		parser->cur++;
		if (value_r != NULL)
			str_append_c(value, ':');

		/* 1*dcontent */
		pblock = parser->cur;
		while (parser->cur < parser->end &&
			smtp_char_is_dcontent(*parser->cur))
			parser->cur++;

		if (parser->cur == pblock) {
			parser->error = "Empty address literal";
			return -1;
		}
		if (value_r != NULL)
			str_append_data(value, pblock, parser->cur - pblock);

		if (ipv6) {
			i_zero(&ip6);
			if ((ret = inet_pton(AF_INET6, t_strndup(pblock,
				parser->cur - pblock), &ip6)) <= 0) {
				parser->error = "Invalid IPv6 address literal";
				return -1;
			}
			if (ip_r != NULL) {
				ip_r->family = AF_INET6;
				ip_r->u.ip6 = ip6;
			}
		}
	}

	/* ']' */
	if (parser->cur >= parser->end) {
		parser->error = "Missing ']' at end of address literal";
		return -1;
	} else if (*parser->cur != ']') {
		parser->error = "Invalid character in address literal";
		return -1;
	}

	parser->cur++;
	if (value_r != NULL) {
		str_append_c(value, ']');
		*value_r = str_c(value);
	}
	return 1;
}

int smtp_parser_parse_quoted_string(struct smtp_parser *parser,
	const char **value_r)
{
	string_t *value = NULL;
	const unsigned char *pbegin;

	/* Quoted-string    = DQUOTE *QcontentSMTP DQUOTE
	   QcontentSMTP     = qtextSMTP / quoted-pairSMTP
	   quoted-pairSMTP  = %d92 %d32-126
	                    ; i.e., backslash followed by any ASCII
	                    ; graphic (including itself) or SPace
	   qtextSMTP        = %d32-33 / %d35-91 / %d93-126
	                    ; i.e., within a quoted string, any
	                    ; ASCII graphic or space is permitted
	                    ; without blackslash-quoting except
	                    ; double-quote and the backslash itself.
	 */

	/* DQUOTE */
	if (parser->cur >= parser->end || *parser->cur != '"')
		return 0;
	parser->cur++;

	if (value_r != NULL)
		value = t_str_new(256);

	/* *QcontentSMTP */
	while (parser->cur < parser->end) {
		pbegin = parser->cur;
		while (parser->cur < parser->end &&
			smtp_char_is_qtext(*parser->cur)) {
			/* qtextSMTP */
			parser->cur++;
		}

		if (value_r != NULL)
			str_append_data(value, pbegin, parser->cur - pbegin);

		if (parser->cur >= parser->end || *parser->cur != '\\')
			break;
		parser->cur++;

		/* quoted-pairSMTP */
		if (parser->cur >= parser->end ||
			!smtp_char_is_qpair(*parser->cur)) {
			parser->error =
				"Invalid character after '\\' in quoted string";
			return -1;
		}

		if (value_r != NULL)
			str_append_c(value, *parser->cur);
		parser->cur++;
	}

	/* DQUOTE */
	if (parser->cur >= parser->end)  {
		parser->error = "Premature end of quoted string";
		return -1;
	}
	if (*parser->cur != '"') {
		parser->error = "Invalid character in quoted string";
		return -1;
	}
	parser->cur++;
	if (value_r != NULL)
		*value_r = str_c(value);
	return 1;
}

static int
smtp_parser_skip_atom(struct smtp_parser *parser)
{
	/* Atom = 1*atext */

	if (parser->cur >= parser->end || !smtp_char_is_atext(*parser->cur))
		return 0;
	parser->cur++;

	while (parser->cur < parser->end && smtp_char_is_atext(*parser->cur))
		parser->cur++;
	return 1;
}

int smtp_parser_parse_atom(struct smtp_parser *parser,
	const char **value_r)
{
	const unsigned char *pbegin = parser->cur;
	int ret;

	if ((ret=smtp_parser_skip_atom(parser)) <= 0)
		return ret;

	if (value_r != NULL)
		*value_r = t_strndup(pbegin, parser->cur - pbegin);
	return 1;
}

int smtp_parser_parse_string(struct smtp_parser *parser,
	const char **value_r)
{
	int ret;

	/* String = Atom / Quoted-string */

	if ((ret=smtp_parser_parse_quoted_string(parser, value_r)) != 0)
		return ret;
	return smtp_parser_parse_atom(parser, value_r);
}

static bool
smtp_parse_xtext_hexdigit(const unsigned char digit,
	unsigned char *hexvalue)
{
	switch (digit) {
	case '0': case '1': case '2': case '3': case '4':
	case '5': case '6': case '7': case '8': case '9':
		*hexvalue = (*hexvalue) << 4;
		*hexvalue += digit - '0';
		break;
	case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
		*hexvalue = (*hexvalue) << 4;
		*hexvalue += digit - 'A' + 10;
		break;
	default:
		return FALSE;
	}
	return TRUE;
}

int smtp_parser_parse_xtext(struct smtp_parser *parser,
	string_t *out)
{
	unsigned char hexchar;

	/* xtext   = *( xchar / hexchar )
	   xchar   = any ASCII CHAR between "!" (33) and "~" (126) inclusive,
	              except for "+" and "=".
	   hexchar = ASCII "+" immediately followed by two upper case
	             hexadecimal digits
	 */
	if (parser->cur >= parser->end ||
		(!smtp_char_is_xtext(*parser->cur) && *parser->cur != '+'))
		return 0;

	while (parser->cur < parser->end) {
		const unsigned char *pbegin = parser->cur;

		while (parser->cur < parser->end &&
			smtp_char_is_xtext(*parser->cur))
			parser->cur++;

		if (out != NULL)
			str_append_data(out, pbegin, parser->cur - pbegin);

		if (parser->cur >= parser->end || *parser->cur != '+')
			break;
		parser->cur++;

		hexchar = 0;
		if (smtp_parse_xtext_hexdigit(*parser->cur, &hexchar)) {
			parser->cur++;
			if (smtp_parse_xtext_hexdigit(*parser->cur, &hexchar)) {
				parser->cur++;
				if (out != NULL)
					str_append_c(out, hexchar);
				continue;
			}
		}

		parser->error = "Invalid hexchar after '+' in xtext";
		return -1;
	}

	return 1;
}
