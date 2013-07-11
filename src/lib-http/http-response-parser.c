/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "http-parser.h"
#include "http-message-parser.h"
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
	struct http_message_parser parser;
	enum http_response_parser_state state;

	struct http_response response;
};

struct http_response_parser *http_response_parser_init(struct istream *input)
{
	struct http_response_parser *parser;

	parser = i_new(struct http_response_parser, 1);
	http_message_parser_init(&parser->parser, input);
	return parser;
}

void http_response_parser_deinit(struct http_response_parser **_parser)
{
	struct http_response_parser *parser = *_parser;

	http_message_parser_deinit(&parser->parser);
	i_free(parser);
}

static void
http_response_parser_restart(struct http_response_parser *parser)
{
	http_message_parser_restart(&parser->parser);
	memset(&parser->response, 0, sizeof(parser->response));
}

static int http_response_parse_status(struct http_response_parser *parser)
{
	const unsigned char *p = parser->parser.cur;
	const size_t size = parser->parser.end - parser->parser.cur;

	/* status-code   = 3DIGIT
	 */
	if (size < 3)
		return 0;
	if (!i_isdigit(p[0]) || !i_isdigit(p[1]) || !i_isdigit(p[2]))
		return -1;
	parser->response.status =
		(p[0] - '0')*100 + (p[1] - '0')*10 + (p[2] - '0');
	parser->parser.cur += 3;
	return 1;
}

static int http_response_parse_reason(struct http_response_parser *parser)
{
	const unsigned char *p = parser->parser.cur;

	/* reason-phrase = *( HTAB / SP / VCHAR / obs-text )
	 */
	while (p < parser->parser.end && http_char_is_text(*p))
		p++;

	if (p == parser->parser.end)
		return 0;
	parser->response.reason =
		p_strdup_until(parser->parser.msg_pool, parser->parser.cur, p);
	parser->parser.cur = p;
	return 1;
}

static inline const char *_chr_sanitize(unsigned char c)
{
	if (c >= 0x20 && c < 0x7F)
		return t_strdup_printf("'%c'", c);
	return t_strdup_printf("0x%02x", c);
}

static int http_response_parse(struct http_response_parser *parser,
			       const char **error_r)
{
	struct http_message_parser *_parser = &parser->parser;
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
			if ((ret=http_message_parse_version(_parser)) <= 0) {
				if (ret < 0)
					*error_r = "Invalid HTTP version in response";
				return ret;
			}
			parser->state = HTTP_RESPONSE_PARSE_STATE_SP1;
			if (_parser->cur == _parser->end)
				return 0;
			/* fall through */
		case HTTP_RESPONSE_PARSE_STATE_SP1:
			if (*_parser->cur != ' ') {
				*error_r = t_strdup_printf
					("Expected ' ' after response version, but found %s",
						_chr_sanitize(*_parser->cur));
				return -1;
			}
			_parser->cur++;
			parser->state = HTTP_RESPONSE_PARSE_STATE_STATUS;
			if (_parser->cur >= _parser->end)
				return 0;
			/* fall through */
		case HTTP_RESPONSE_PARSE_STATE_STATUS:
			if ((ret=http_response_parse_status(parser)) <= 0) {
				if (ret < 0)
					*error_r = "Invalid HTTP status code in response";
				return ret;
			}
			parser->state = HTTP_RESPONSE_PARSE_STATE_SP2;
			if (_parser->cur == _parser->end)
				return 0;
			/* fall through */
		case HTTP_RESPONSE_PARSE_STATE_SP2:
			if (*_parser->cur != ' ') {
				*error_r = t_strdup_printf
					("Expected ' ' after response status code, but found %s",
						_chr_sanitize(*_parser->cur));
				return -1;
			}
			_parser->cur++;
			parser->state = HTTP_RESPONSE_PARSE_STATE_REASON;
			if (_parser->cur >= _parser->end)
				return 0;
			/* fall through */
		case HTTP_RESPONSE_PARSE_STATE_REASON:
			if ((ret=http_response_parse_reason(parser)) <= 0) {
				i_assert(ret == 0);
				return 0;
			}
			parser->state = HTTP_RESPONSE_PARSE_STATE_CR;
			if (_parser->cur == _parser->end)
				return 0;
			/* fall through */
		case HTTP_RESPONSE_PARSE_STATE_CR:
			if (*_parser->cur == '\r')
				_parser->cur++;
			parser->state = HTTP_RESPONSE_PARSE_STATE_LF;
			if (_parser->cur == _parser->end)
				return 0;
			/* fall through */
		case HTTP_RESPONSE_PARSE_STATE_LF:
			if (*_parser->cur != '\n') {
				*error_r = t_strdup_printf
					("Expected line end after response, but found %s",
						_chr_sanitize(*_parser->cur));
				return -1;
			}
			_parser->cur++;
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

static int http_response_parse_status_line(struct http_response_parser *parser,
					   const char **error_r)
{
	struct http_message_parser *_parser = &parser->parser;
	const unsigned char *begin;
	size_t size, old_bytes = 0;
	int ret;

	while ((ret = i_stream_read_data(_parser->input, &begin, &size,
					 old_bytes)) > 0) {
		_parser->cur = begin;
		_parser->end = _parser->cur + size;

		if ((ret = http_response_parse(parser, error_r)) < 0)
			return -1;

		i_stream_skip(_parser->input, _parser->cur - begin);
		if (ret > 0)
			return 1;
		old_bytes = i_stream_get_data_size(_parser->input);
	}

	i_assert(ret != -2);
	if (ret < 0) {
		if (_parser->input->eof &&
		    parser->state == HTTP_RESPONSE_PARSE_STATE_INIT)
			return 0;
		*error_r = "Stream error";
		return -1;
	}
	return 0;
}

int http_response_parse_next(struct http_response_parser *parser,
			     bool no_payload, struct http_response **response_r,
			     const char **error_r)
{
	int ret;

	/* make sure we finished streaming payload from previous response
	   before we continue. */
	if ((ret = http_message_parse_finish_payload(&parser->parser, error_r)) <= 0)
		return ret;

	/* HTTP-message   = start-line
	                   *( header-field CRLF )
	                    CRLF
	                    [ message-body ]
	 */
	if (parser->state != HTTP_RESPONSE_PARSE_STATE_HEADER) {
		if ((ret = http_response_parse_status_line(parser, error_r)) <= 0)
			return ret;
	} 
	if ((ret = http_message_parse_headers(&parser->parser, error_r)) <= 0)
		return ret;

	/* http://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging-21
	     Section 3.3.2:

	   A server MUST NOT send a Content-Length header field in any response
	   with a status code of 1xx (Informational) or 204 (No Content). [...]
	 */
	if ((parser->response.status / 100 == 1 || parser->response.status == 204) &&
	    parser->parser.msg.content_length > 0) {
		*error_r = t_strdup_printf(
			"Unexpected Content-Length header field for %u response "
			"(length=%"PRIuUOFF_T")", parser->response.status,
			parser->parser.msg.content_length);
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
	if (parser->response.status / 100 == 1 || parser->response.status == 204
		|| parser->response.status == 304) { // HEAD is handled in caller
		no_payload = TRUE;
	}

	if (!no_payload) {
		/* [ message-body ] */
		if (http_message_parse_body(&parser->parser, error_r) < 0)
			return -1;
	}
	parser->state = HTTP_RESPONSE_PARSE_STATE_INIT;

	parser->response.version_major = parser->parser.msg.version_major;
	parser->response.version_minor = parser->parser.msg.version_minor;
	parser->response.location = parser->parser.msg.location;
	parser->response.date = parser->parser.msg.date;
	parser->response.payload = parser->parser.payload;
	parser->response.headers = parser->parser.msg.headers;
	parser->response.connection_close = parser->parser.msg.connection_close;

	*response_r = &parser->response;
	return 1;
}
