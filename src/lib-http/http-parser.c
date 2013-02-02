/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "str.h"
#include "strescape.h"
#include "http-url.h"

#include "http-parser.h"

/*
 Character definitions:

 tchar          = "!" / "#" / "$" / "%" / "&" / "'" / "*"
                / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
                / DIGIT / ALPHA
                ; any VCHAR, except special
 special        = "(" / ")" / "<" / ">" / "@" / ","
                / ";" / ":" / "\" / DQUOTE / "/" / "["
                / "]" / "?" / "=" / "{" / "}"
 qdtext         = OWS / %x21 / %x23-5B / %x5D-7E / obs-text
 qdtext-nf      = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text
 ctext          = OWS / %x21-27 / %x2A-5B / %x5D-7E / obs-text 
 obs-text       = %x80-FF
 OWS            = *( SP / HTAB )

 Mapping
 (1<<0) => tchar
 (1<<1) => special
 (1<<2) => %x21 / %x2A-5B / %x5D-7E
 (1<<3) => %x23-29
 (1<<4) => %x22-27
 (1<<5) => HTAB / SP / obs-text
 */

const unsigned char _http_token_char_mask  = (1<<0);
const unsigned char _http_value_char_mask  = (1<<0)|(1<<1);
const unsigned char _http_text_char_mask   = (1<<0)|(1<<1)|(1<<5);
const unsigned char _http_qdtext_char_mask = (1<<2)|(1<<3)|(1<<5);
const unsigned char _http_ctext_char_mask  = (1<<2)|(1<<4)|(1<<5);

const unsigned char _http_char_lookup[256] = {
	 0,  0,  0,  0,  0,  0,  0,  0,  0, 32,  0,  0,  0,  0,  0,  0, // 00
	 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, // 10
	32, 21, 18, 25, 25, 25, 25, 25, 10, 10,  5,  5,  6,  5,  5,  6, // 20
	 5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  6,  6,  6,  6,  6,  6, // 30
	 6,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5, // 40
	 5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  6,  2,  6,  5,  5, // 50
	 5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5, // 60
	 5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  6,  5,  6,  5,  0, // 70

	32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 80
	32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 90
	32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // A0
	32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // B0
	32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // C0
	32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // D0
	32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // E0
	32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // F0
};

/*
 * HTTP value parsing
 */

void http_parser_init(struct http_parser *parser,
			const unsigned char *data, size_t size)
{
	memset(parser, 0, sizeof(*parser));
	parser->begin = data;
	parser->cur = data;
	parser->end = data + size;
}

void http_parse_ows(struct http_parser *parser)
{
	/* OWS            = *( SP / HTAB ) */
	if (parser->cur >= parser->end)
		return;
	while (parser->cur < parser->end &&
		(parser->cur[0] == ' ' || parser->cur[0] == '\t')) {
		parser->cur++;
	}
}

int http_parse_token(struct http_parser *parser, const char **token_r)
{
	const unsigned char *first;

	/* token          = 1*tchar */

	if (parser->cur >= parser->end || !http_char_is_token(*parser->cur))
		return 0;

	first = parser->cur++;
	while (parser->cur < parser->end && http_char_is_token(*parser->cur))
		parser->cur++;

	*token_r = t_strndup(first, parser->cur - first);
	return 1;
}

int http_parse_token_list_next(struct http_parser *parser,
	const char **token_r)
{
	/* http://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging-21;
	     Appendix B:

	   For compatibility with legacy list rules, recipients SHOULD accept
	   empty list elements.  In other words, consumers would follow the list
	   productions:

	   #element => [ ( "," / element ) *( OWS "," [ OWS element ] ) ]
	   1#element => *( "," OWS ) element *( OWS "," [ OWS element ] )
	*/

	for (;;) {	
		if (http_parse_token(parser, token_r) > 0)
			break;
		http_parse_ows(parser);
		if (parser->cur >= parser->end || parser->cur[0] != ',')
			return 0;
		parser->cur++;
		http_parse_ows(parser);
	}

	return 1;
}




