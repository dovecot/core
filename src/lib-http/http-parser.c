/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

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
 VCHAR          =  %x21-7E
 't68char'      = ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/"

 'text'         = ( HTAB / SP / VCHAR / obs-text )
 
 Character bit mappings:

 (1<<0) => ALPHA / DIGIT / "-" / "." / "_" / "~" / "+"
 (1<<1) => "!" / "#" / "$" / "%" / "&" / "'" / "*" / "^" / "`" / "|"
 (1<<2) => special
 (1<<3) => %x21 / %x2A-5B / %x5D-7E
 (1<<4) => %x23-29
 (1<<5) => %x22-27
 (1<<6) => HTAB / SP / obs-text
 (1<<7) => "/"
 */

const unsigned char _http_token_char_mask   = (1<<0)|(1<<1);
const unsigned char _http_value_char_mask   = (1<<0)|(1<<1)|(1<<2);
const unsigned char _http_text_char_mask    = (1<<0)|(1<<1)|(1<<2)|(1<<6);
const unsigned char _http_qdtext_char_mask  = (1<<3)|(1<<4)|(1<<6);
const unsigned char _http_ctext_char_mask   = (1<<3)|(1<<5)|(1<<6);
const unsigned char _http_token68_char_mask = (1<<0)|(1<<7);

const unsigned char _http_char_lookup[256] = {
	 0,  0,  0,  0,  0,  0,  0,  0,  0, 64,  0,  0,  0,  0,  0,   0, // 00
	 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,   0, // 10
	64, 10, 36, 50, 50, 50, 50, 50, 20, 20, 10,  9, 12,  9,  9, 140, // 20
	 9,  9,  9,  9,  9,  9,  9,  9,  9,  9, 12, 12, 12, 12, 12,  12, // 30
	12,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,   9, // 40
	 9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9, 12,  4, 12, 10,   9, // 50
	10,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,   9, // 60
	 9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9, 12, 10, 12,  9,   0, // 70

	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,  64, // 80
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,  64, // 90
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,  64, // A0
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,  64, // B0
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,  64, // C0
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,  64, // D0
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,  64, // E0
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,  64, // F0
};

/*
 * HTTP value parsing
 */

void http_parser_init(struct http_parser *parser,
			const unsigned char *data, size_t size)
{
	i_zero(parser);
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

int http_parser_skip_token(struct http_parser *parser)
{
	/* token          = 1*tchar */

	if (parser->cur >= parser->end || !http_char_is_token(*parser->cur))
		return 0;
	parser->cur++;

	while (parser->cur < parser->end && http_char_is_token(*parser->cur))
		parser->cur++;
	return 1;
}

int http_parse_token(struct http_parser *parser, const char **token_r)
{
	const unsigned char *first = parser->cur;
	int ret;

	if ((ret=http_parser_skip_token(parser)) <= 0)
		return ret;
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

int http_parse_quoted_string(struct http_parser *parser, const char **str_r)
{
	string_t *str;

	/* quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE
	   qdtext        = HTAB / SP / "!" / %x23-5B ; '#'-'['
	                   / %x5D-7E ; ']'-'~'
	                   / obs-text
	   quoted-pair   = "\" ( HTAB / SP / VCHAR / obs-text )
	   obs-text      = %x80-FF
	 */

	/* DQUOTE */
	if (parser->cur >= parser->end || parser->cur[0] != '"')
		return 0;
	parser->cur++;

	/* *( qdtext / quoted-pair ) */
	str = t_str_new(256);
	for (;;) {
		const unsigned char *first;

		/* *qdtext */
		first = parser->cur;
		while (parser->cur < parser->end && http_char_is_qdtext(*parser->cur))
			parser->cur++;

		if (parser->cur >= parser->end)
			return -1;

		str_append_data(str, first, parser->cur - first);

		/* DQUOTE */
		if (*parser->cur == '"') {
			parser->cur++;
			break;

		/* "\" */
		} else if (*parser->cur == '\\') {
			parser->cur++;
			
			if (parser->cur >= parser->end || !http_char_is_text(*parser->cur))
				return -1;
			str_append_c(str, *parser->cur);
			parser->cur++;

		/* ERROR */
		} else {
			return -1;
		}
	}
	*str_r = str_c(str);
	return 1;
}

int http_parse_token_or_qstring(struct http_parser *parser,
	const char **word_r)
{
	if (parser->cur >= parser->end)
		return 0;
	if (parser->cur[0] == '"')
		return http_parse_quoted_string(parser, word_r);
	return http_parse_token(parser, word_r);
}
