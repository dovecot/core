/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "istream.h"
#include "str.h"
#include "str-sanitize.h"
#include "http-parser.h"

#include "http-header-parser.h"

enum http_header_parse_state {
	HTTP_HEADER_PARSE_STATE_INIT = 0,
	HTTP_HEADER_PARSE_STATE_NAME,
	HTTP_HEADER_PARSE_STATE_COLON,
	HTTP_HEADER_PARSE_STATE_OWS,
	HTTP_HEADER_PARSE_STATE_CONTENT,
	HTTP_HEADER_PARSE_STATE_CR,
	HTTP_HEADER_PARSE_STATE_LF,
	HTTP_HEADER_PARSE_STATE_NEW_LINE,
	HTTP_HEADER_PARSE_STATE_LAST_LINE,
	HTTP_HEADER_PARSE_STATE_EOH
};

struct http_header_parser {
	struct istream *input;

	const unsigned char *begin, *cur, *end;
	const char *error;

	string_t *name;
	buffer_t *value_buf;

	enum http_header_parse_state state;
};

// FIXME(Stephan): Add support for limiting maximum header size.

struct http_header_parser *http_header_parser_init(struct istream *input)
{
	struct http_header_parser *parser;

	parser = i_new(struct http_header_parser, 1);
	parser->input = input;
	parser->name = str_new(default_pool, 128);
	parser->value_buf = buffer_create_dynamic(default_pool, 4096);

	return parser;
}

void http_header_parser_deinit(struct http_header_parser **_parser)
{
	struct http_header_parser *parser = *_parser;

	//i_stream_skip(ctx->input, ctx->skip);
	buffer_free(&parser->value_buf);
	str_free(&parser->name);
	i_free(parser);
	*_parser = NULL;
}

void http_header_parser_reset(struct http_header_parser *parser)
{
	parser->state = HTTP_HEADER_PARSE_STATE_INIT;
}

static int http_header_parse_name(struct http_header_parser *parser)
{
	const unsigned char *first = parser->cur;

	/* field-name     = token
	   token          = 1*tchar
	 */
	while (parser->cur < parser->end && http_char_is_token(*parser->cur))
		parser->cur++;

	str_append_n(parser->name, first, parser->cur-first);

	if (parser->cur == parser->end)
		return 0;
	if (str_len(parser->name) == 0) {
		parser->error = "Empty header field name";
		return -1;
	}
	return 1;
}

static int http_header_parse_ows(struct http_header_parser *parser)
{
	/* OWS            = *( SP / HTAB )
	                  ; "optional" whitespace
	 */
	while (parser->cur < parser->end &&
		(*parser->cur == ' ' || *parser->cur == '\t'))
		parser->cur++;
	return (parser->cur == parser->end ? 0 : 1);
}

static int http_header_parse_content(struct http_header_parser *parser)
{
	const unsigned char *first = parser->cur;

	/* field-content  = *( HTAB / SP / VCHAR / obs-text )
	 */
	while (parser->cur < parser->end && http_char_is_text(*parser->cur))
		parser->cur++;

	buffer_append(parser->value_buf, first, parser->cur-first);

	if (parser->cur == parser->end)
		return 0;
	return 1;
}

static inline const char *_chr_sanitize(unsigned char c)
{
	if (c >= 0x20 && c < 0x7F)
		return t_strdup_printf("'%c'", c);
	return t_strdup_printf("0x%02x", c);
}

static int http_header_parse(struct http_header_parser *parser)
{
	int ret;

	/* 'header'       = *( header-field CRLF ) CRLF
	   header-field   = field-name ":" OWS field-value OWS
	   field-name     = token
	   field-value    = *( field-content / obs-fold )
	   field-content  = *( HTAB / SP / VCHAR / obs-text )
	   obs-fold       = CRLF ( SP / HTAB )
	                  ; obsolete line folding
	                  ; see Section 3.2.2
	 */

	for (;;) {
		switch (parser->state) {
		case HTTP_HEADER_PARSE_STATE_INIT:
			buffer_set_used_size(parser->value_buf, 0);
			str_truncate(parser->name, 0);
			parser->state = HTTP_HEADER_PARSE_STATE_NAME;
			/* fall through */
		case HTTP_HEADER_PARSE_STATE_NAME:
			if (http_char_is_token(*parser->cur)) {
				if ((ret=http_header_parse_name(parser)) <= 0)
					return ret;
			} else if (str_len(parser->name) == 0) {
				parser->state = HTTP_HEADER_PARSE_STATE_LAST_LINE;
				break;
			}
			parser->state = HTTP_HEADER_PARSE_STATE_COLON;
			/* fall through */
		case HTTP_HEADER_PARSE_STATE_COLON:
			if (*parser->cur != ':') {
				parser->error = t_strdup_printf
					("Expected ':' after header field name '%s', but found %s",
						str_sanitize(str_c(parser->name),64),
						_chr_sanitize(*parser->cur));
				return -1;
			}
			parser->cur++;
			if (str_len(parser->name) == 0) {
				parser->error = "Empty header field name";
				return -1;
			}
			parser->state = HTTP_HEADER_PARSE_STATE_OWS;
			/* fall through */
		case HTTP_HEADER_PARSE_STATE_OWS:
			if ((ret=http_header_parse_ows(parser)) <= 0)
				return ret;
			parser->state = HTTP_HEADER_PARSE_STATE_CONTENT;
			/* fall through */
		case HTTP_HEADER_PARSE_STATE_CONTENT:
			if ((ret=http_header_parse_content(parser)) <= 0)
				return ret;
			parser->state = HTTP_HEADER_PARSE_STATE_CR;
			/* fall through */
		case HTTP_HEADER_PARSE_STATE_CR:
			if (*parser->cur == '\r') {
				parser->cur++;
			}
			parser->state = HTTP_HEADER_PARSE_STATE_LF;
			if (parser->cur == parser->end)
				return 0;
			/* fall through */
		case HTTP_HEADER_PARSE_STATE_LF:
			if (*parser->cur != '\n') {
				parser->error = t_strdup_printf
					("Expected line end after header field '%s', but found %s",
						str_sanitize(str_c(parser->name),64),
						_chr_sanitize(*parser->cur));
				return -1;
			}
			parser->cur++;
			parser->state = HTTP_HEADER_PARSE_STATE_NEW_LINE;
			if (parser->cur == parser->end)
				return 0;
			/* fall through */
		case HTTP_HEADER_PARSE_STATE_NEW_LINE:
			if (*parser->cur == ' ' || *parser->cur == '\t') {
				/* obs-fold */
				buffer_append_c(parser->value_buf, ' ');
				parser->state = HTTP_HEADER_PARSE_STATE_OWS;
				break;
			}
			parser->state = HTTP_HEADER_PARSE_STATE_NAME;
			return 1;
		case HTTP_HEADER_PARSE_STATE_LAST_LINE:
			if (*parser->cur == '\r') {
				/* last CRLF */
				parser->cur++;
				parser->state = HTTP_HEADER_PARSE_STATE_EOH;
				if (parser->cur == parser->end)
					return 0;
				break;
			} else if (*parser->cur == '\n') {
				/* header fully parsed */
				parser->cur++;
				parser->state = HTTP_HEADER_PARSE_STATE_EOH;
				return 1;
			}
			parser->error = t_strdup_printf
				("Expected CRLF or header field name, but found %s",
					_chr_sanitize(*parser->cur));
			return -1;
		case HTTP_HEADER_PARSE_STATE_EOH:
			if (*parser->cur != '\n') {
				parser->error = t_strdup_printf
					("Expected LF after CR at end of header, but found %s",
						_chr_sanitize(*parser->cur));
				return -1;
			}
			/* header fully parsed */
			parser->cur++;
			return 1;

		default:
			i_unreached();
		}
	}

	i_unreached();
	return -1;
}

int http_header_parse_next_field(struct http_header_parser *parser,
	const char **name_r, const unsigned char **data_r, size_t *size_r,
	const char **error_r)
{
	const unsigned char *data;
	size_t size;
	int ret;

	while ((ret=i_stream_read_data
		(parser->input, &parser->begin, &size, 0)) > 0) {
		parser->cur = parser->begin;
		parser->end = parser->cur + size;

		if ((ret=http_header_parse(parser)) < 0) {
			*error_r = parser->error;
			return -1;
		}

		i_stream_skip(parser->input, parser->cur - parser->begin);

		if (ret == 1) {
			if (parser->state != HTTP_HEADER_PARSE_STATE_EOH) {
				data = buffer_get_data(parser->value_buf, &size);
			
				/* trim trailing OWS */
				while (size > 0 &&
					(data[size-1] == ' ' || data[size-1] == '\t'))
					size--;

				*name_r = str_c(parser->name);
				*data_r = data;
				*size_r = size;
				parser->state = HTTP_HEADER_PARSE_STATE_INIT;
			} else {
				*name_r = NULL;
				*data_r = NULL;
			}
			return 1;
		}
	}

	i_assert(ret != -2);
	if (ret < 0)
		*error_r = "Stream error";
	return ret;
}
