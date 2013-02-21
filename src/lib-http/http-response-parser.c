/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "strfuncs.h"
#include "istream.h"
#include "http-parser.h"
#include "http-date.h"
#include "http-header-parser.h"
#include "http-transfer.h"

#include "http-response-parser.h"

#include <ctype.h>

enum http_response_parser_state {
	HTTP_RESPONSE_PARSE_STATE_INIT = 0,
	HTTP_RESPONSE_PARSE_STATE_VERSION,
	HTTP_RESPONSE_PARSE_STATE_SP1,
	HTTP_RESPONSE_PARSE_STATE_STATUS,
	HTTP_RESPONSE_PARSE_STATE_SP2,
	HTTP_RESPONSE_PARSE_STATE_REASON,
	HTTP_RESPONSE_PARSE_STATE_CR,
	HTTP_RESPONSE_PARSE_STATE_LF,
	HTTP_RESPONSE_PARSE_STATE_HEADER
};

struct http_response_parser {
	struct istream *input;

	const unsigned char *begin, *cur, *end;
	const char *error;

	string_t *strbuf;

	enum http_response_parser_state state;
	struct http_header_parser *header_parser;

	uoff_t content_length;
	const char *transfer_encoding;
	struct istream *payload;

	struct http_response *response;
	pool_t response_pool;
};

struct http_response_parser *http_response_parser_init(struct istream *input)
{
	struct http_response_parser *parser;

	parser = i_new(struct http_response_parser, 1);
	parser->input = input;
	parser->strbuf = str_new(default_pool, 128);
	return parser;
}

void http_response_parser_deinit(struct http_response_parser **_parser)
{
	struct http_response_parser *parser = *_parser;

	str_free(&parser->strbuf);
	if (parser->header_parser != NULL)
		http_header_parser_deinit(&parser->header_parser);
	if (parser->response_pool != NULL)
		pool_unref(&parser->response_pool);
	if (parser->payload != NULL)
		i_stream_unref(&parser->payload);
	i_free(parser);
}

static void
http_response_parser_restart(struct http_response_parser *parser)
{
	i_assert(parser->payload == NULL);
	parser->content_length = 0;
	parser->transfer_encoding = NULL;
	str_truncate(parser->strbuf, 0);
	if (parser->response_pool != NULL)
		pool_unref(&parser->response_pool);
	parser->response_pool = pool_alloconly_create("http_response", 4096);
	parser->response = p_new(parser->response_pool, struct http_response, 1);
	parser->response->date = (time_t)-1;
	p_array_init(&parser->response->headers, parser->response_pool, 32);
}

static int http_response_parse_version(struct http_response_parser *parser)
{
	const unsigned char *first = parser->cur;
	const char *p;

	/* HTTP-version  = HTTP-name "/" DIGIT "." DIGIT
	   HTTP-name     = %x48.54.54.50 ; "HTTP", case-sensitive
	 */
	while (parser->cur < parser->end && http_char_is_value(*parser->cur))
		parser->cur++;

	if (str_len(parser->strbuf) + (parser->cur-first) > 8)
		return -1;

	if ((parser->cur - first) > 0)
		str_append_n(parser->strbuf, first, parser->cur-first);
	if (parser->cur == parser->end)
		return 0;

	if (str_len(parser->strbuf) != 8)
		return -1;
	if (strncmp(str_c(parser->strbuf), "HTTP/",5) != 0)
		return -1;
	p = str_c(parser->strbuf) + 5;
	if (!i_isdigit(*p))
		return -1;
	parser->response->version_major = *p - '0';
	p++;
	if (*(p++) != '.')
		return -1;
	if (!i_isdigit(*p))
		return -1;
	parser->response->version_minor = *p - '0';
	str_truncate(parser->strbuf, 0);
	return 1;
}

static int http_response_parse_status(struct http_response_parser *parser)
{
	const unsigned char *first = parser->cur;
	const unsigned char *p;

	/* status-code   = 3DIGIT
	 */
	while (parser->cur < parser->end && i_isdigit(*parser->cur)) {
		parser->cur++;
		if ((parser->cur - first) > 3)
			return -1;
	}

	if (str_len(parser->strbuf) + (parser->cur - first) > 3)
		return -1;
	if ((parser->cur - first) > 0)
		str_append_n(parser->strbuf, first, parser->cur-first);
	if (parser->cur == parser->end)
		return 0;
	if (str_len(parser->strbuf) != 3)
		return -1;
	p = str_data(parser->strbuf);
	parser->response->status =
		(p[0] - '0')*100 + (p[1] - '0')*10 + (p[2] - '0');
	str_truncate(parser->strbuf, 0);
	return 1;
}

static int http_response_parse_reason(struct http_response_parser *parser)
{
	const unsigned char *first = parser->cur;

	/* reason-phrase = *( HTAB / SP / VCHAR / obs-text )
	 */
	while (parser->cur < parser->end && http_char_is_text(*parser->cur))
		parser->cur++;

	if ((parser->cur - first) > 0)
		str_append_n(parser->strbuf, first, parser->cur-first);
	if (parser->cur == parser->end)
		return 0;
	parser->response->reason =
		p_strdup(parser->response_pool, str_c(parser->strbuf));
	str_truncate(parser->strbuf, 0);
	return 1;
}

static inline const char *_chr_sanitize(unsigned char c)
{
	if (c >= 0x20 && c < 0x7F)
		return t_strdup_printf("'%c'", c);
	return t_strdup_printf("0x%02x", c);
}

static int http_response_parse(struct http_response_parser *parser)
{
	int ret;

	/* status-line   = HTTP-version SP status-code SP reason-phrase CRLF
	   status-code   = 3DIGIT
	   reason-phrase = *( HTAB / SP / VCHAR / obs-text )
	 */

	for (;;) {
		switch (parser->state) {
		case HTTP_RESPONSE_PARSE_STATE_INIT:
			http_response_parser_restart(parser);
			parser->state = HTTP_RESPONSE_PARSE_STATE_VERSION;
			/* fall through */
		case HTTP_RESPONSE_PARSE_STATE_VERSION:
			if ((ret=http_response_parse_version(parser)) <= 0) {
				if (ret < 0)
					parser->error = "Invalid HTTP version in response";
				return ret;
			}
			parser->state = HTTP_RESPONSE_PARSE_STATE_SP1;
			if (parser->cur == parser->end)
				return 0;
			/* fall through */
		case HTTP_RESPONSE_PARSE_STATE_SP1:
			if (*parser->cur != ' ') {
				parser->error = t_strdup_printf
					("Expected ' ' after response version, but found %s",
						_chr_sanitize(*parser->cur));
				return -1;
			}
			parser->cur++;
			parser->state = HTTP_RESPONSE_PARSE_STATE_STATUS;
			if (parser->cur >= parser->end)
				return 0;
			/* fall through */
		case HTTP_RESPONSE_PARSE_STATE_STATUS:
			if ((ret=http_response_parse_status(parser)) <= 0) {
				if (ret < 0)
					parser->error = "Invalid HTTP status code in response";
				return ret;
			}
			parser->state = HTTP_RESPONSE_PARSE_STATE_SP2;
			if (parser->cur == parser->end)
				return 0;
			/* fall through */
		case HTTP_RESPONSE_PARSE_STATE_SP2:
			if (*parser->cur != ' ') {
				parser->error = t_strdup_printf
					("Expected ' ' after response status code, but found %s",
						_chr_sanitize(*parser->cur));
				return -1;
			}
			parser->cur++;
			parser->state = HTTP_RESPONSE_PARSE_STATE_REASON;
			if (parser->cur >= parser->end)
				return 0;
			/* fall through */
		case HTTP_RESPONSE_PARSE_STATE_REASON:
			if ((ret=http_response_parse_reason(parser)) <= 0)
				return ret;
			parser->state = HTTP_RESPONSE_PARSE_STATE_CR;
			if (parser->cur == parser->end)
				return 0;
			/* fall through */
		case HTTP_RESPONSE_PARSE_STATE_CR:
			if (*parser->cur == '\r')
				parser->cur++;
			parser->state = HTTP_RESPONSE_PARSE_STATE_LF;
			if (parser->cur == parser->end)
				return 0;
			/* fall through */
		case HTTP_RESPONSE_PARSE_STATE_LF:
			if (*parser->cur != '\n') {
				parser->error = t_strdup_printf
					("Expected line end after response, but found %s",
						_chr_sanitize(*parser->cur));
				return -1;
			}
			parser->cur++;
			parser->state = HTTP_RESPONSE_PARSE_STATE_HEADER;
			return 1;
		case HTTP_RESPONSE_PARSE_STATE_HEADER:
		default:
			i_unreached();
		}
	}

	i_unreached();
	return -1;
}

static int http_response_parse_status_line(struct http_response_parser *parser)
{
	size_t size;
	int ret;

	while ((ret = i_stream_read_data(parser->input,
					 &parser->begin, &size, 0)) > 0) {
		parser->cur = parser->begin;
		parser->end = parser->cur + size;

		if ((ret = http_response_parse(parser)) < 0)
			return -1;

		i_stream_skip(parser->input, parser->cur - parser->begin);
		if (ret > 0)
			return 1;
	}

	i_assert(ret != -2);
	if (ret < 0) {
		if (parser->input->eof && parser->state == HTTP_RESPONSE_PARSE_STATE_INIT)
			return 0;
		parser->error = "Stream error";
		return -1;
	}
	return 0;
}

static int
http_response_parse_header(struct http_response_parser *parser,
			   const char *name, const unsigned char *data, size_t size)
{
	struct http_response_header *hdr;
	struct http_parser hparser;

	hdr = array_append_space(&parser->response->headers);
	hdr->key = p_strdup(parser->response_pool, name);
	hdr->value = p_strndup(parser->response_pool, data, size);
	hdr->size = size;

	switch (name[0]) {
	case 'C': case 'c':
		if (strcasecmp(name, "Connection") == 0) {
			const char *option;

			/* Connection        = 1#connection-option
				 connection-option = token
			*/
			http_parser_init(&hparser, data, size);
			for (;;) {
				if (http_parse_token_list_next(&hparser, &option) <= 0)
					break;
				if (strcasecmp(option, "close") == 0) {
					parser->response->connection_close = TRUE;
					break; // not interested in any other options
				}
			}
			return 1;
		}
		if (strcasecmp(name, "Content-Length") == 0) {
			/* Content-Length = 1*DIGIT */
			if (str_to_uoff(hdr->value, &parser->content_length) < 0) {
				parser->error = "Invalid Content-Length header";
				return -1;
			}
			return 1;
		}
		break;
	case 'D': case 'd':
		if (strcasecmp(name, "Date") == 0) {
			/* Date = HTTP-date */
			(void)http_date_parse(data, size, &parser->response->date);
			return 1;
		}
		break;
	case 'L': case 'l':
		if (strcasecmp(name, "Location") == 0) {
			/* Location = URI-reference (not parsed here) */
			parser->response->location =
				p_strndup(parser->response_pool, data, size);
			return 1;
		}
		break;
	case 'T': case 't':
		if (strcasecmp(name, "Transfer-Encoding") == 0) {
			/* Transfer-Encoding = 1#transfer-coding */
			parser->transfer_encoding = hdr->value;
			return 1;
		}
		break;
	default:
		break;
	}
	return 1;
}

int http_response_parse_next(struct http_response_parser *parser,
			     bool no_payload, struct http_response **response_r,
			     const char **error_r)
{
	struct http_parser hparser;
	const char *field_name, *error;
	const unsigned char *field_data;
	size_t field_size;
	int ret;

	/* make sure we finished streaming payload from previous response
	   before we continue. */
	if (parser->payload != NULL) {
		struct istream *payload = parser->payload;

		i_assert(parser->state == HTTP_RESPONSE_PARSE_STATE_INIT);

		if (i_stream_have_bytes_left(payload)) {
			do {
				i_stream_skip(payload, i_stream_get_data_size(payload));
			} while ((ret=i_stream_read(payload)) > 0);
			if (ret == 0)
				return 0;
			if (ret < 0 && !payload->eof) {
				*error_r = "Stream error while skipping payload";
				return -1;
			}
		}

		if (payload->eof)	{
			i_stream_unref(&parser->payload);
			parser->payload = NULL;
		}
	}

	/* HTTP-message   = start-line
	                   *( header-field CRLF )
	                    CRLF
	                    [ message-body ]
	 */

	/* start-line */
	if (parser->state != HTTP_RESPONSE_PARSE_STATE_HEADER) {
		if ((ret=http_response_parse_status_line(parser)) <= 0) {
			*error_r = parser->error;
			return ret;
		}
	} 

	/* *( header-field CRLF ) CRLF */
	if (parser->header_parser == NULL)
		parser->header_parser = http_header_parser_init(parser->input);
	else
		http_header_parser_reset(parser->header_parser);

	while ((ret=http_header_parse_next_field
		(parser->header_parser, &field_name, &field_data, &field_size, &error)) > 0) {
		if (field_name == NULL) break;
		if ((ret=http_response_parse_header
		     (parser, field_name, field_data, field_size)) < 0) {
			*error_r = parser->error;
			return -1;
		}
	}

	if (ret <= 0) {
		if (ret < 0)
			*error_r = t_strdup_printf("Failed to parse response header: %s", error);
		return ret;
	}

	/* http://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging-21
	     Section 3.3.2:

	   A server MUST NOT send a Content-Length header field in any response
	   with a status code of 1xx (Informational) or 204 (No Content). [...]
	 */
	if ((parser->response->status / 100 == 1 ||
		parser->response->status == 204) && parser->content_length > 0) {
		*error_r = t_strdup_printf(
			"Unexpected Content-Length header field for %u response "
			"(length=%"PRIuUOFF_T")", parser->response->status,
			parser->content_length);
		return -1;
	}

	/* http://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging-21
	     Section 3.3.3:

	   Any response to a HEAD request and any response with a 1xx
	   (Informational), 204 (No Content), or 304 (Not Modified) status
	   code is always terminated by the first empty line after the
	   header fields, regardless of the header fields present in the
	   message, and thus cannot contain a message body.
	 */
	if (parser->response->status / 100 == 1 || parser->response->status == 204
		|| parser->response->status == 304) { // HEAD is handled in caller
		no_payload = TRUE;
	}

	if (!no_payload) {
		/* [ message-body ] */
		if (parser->content_length > 0) {
			/* Got explicit message size from Content-Length: header */
			parser->payload = parser->response->payload =
				i_stream_create_limit(parser->input, parser->content_length);
		} else if (parser->transfer_encoding != NULL) {
			const char *tenc;

			/* Transfer-Encoding = 1#transfer-coding
			   transfer-coding    = "chunked" / "compress" / "deflate" / "gzip"
			                      / transfer-extension       ;  [FIXME]
			   transfer-extension = token *( OWS ";" OWS transfer-parameter )
			*/
			http_parser_init(&hparser,
				(const unsigned char *)parser->transfer_encoding,
				strlen(parser->transfer_encoding));
			for (;;) {
				if (http_parse_token_list_next(&hparser, &tenc) <= 0)
					break;
				if (strcasecmp(tenc, "chunked") == 0) {
					parser->payload =  parser->response->payload =
						http_transfer_chunked_istream_create(parser->input);
					break; // FIXME
				} else {
					*error_r = t_strdup_printf(
						"Unkown Transfer-Encoding `%s' for %u response",
						tenc, parser->response->status);
					return -1;
				}
			}
		}
	}

	parser->state = HTTP_RESPONSE_PARSE_STATE_INIT;
	*response_r = parser->response;
	return 1;
}
