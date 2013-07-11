/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "http-parser.h"
#include "http-message-parser.h"
#include "http-request-parser.h"

enum http_request_parser_state {
	HTTP_REQUEST_PARSE_STATE_INIT = 0,
	HTTP_REQUEST_PARSE_STATE_METHOD,
	HTTP_REQUEST_PARSE_STATE_SP1,
	HTTP_REQUEST_PARSE_STATE_TARGET,
	HTTP_REQUEST_PARSE_STATE_SP2,
	HTTP_REQUEST_PARSE_STATE_VERSION,
	HTTP_REQUEST_PARSE_STATE_CR,
	HTTP_REQUEST_PARSE_STATE_LF,
	HTTP_REQUEST_PARSE_STATE_HEADER
};

struct http_request_parser {
	struct http_message_parser parser;
	enum http_request_parser_state state;

	struct http_request request;
};

struct http_request_parser *http_request_parser_init(struct istream *input)
{
	struct http_request_parser *parser;

	parser = i_new(struct http_request_parser, 1);
	http_message_parser_init(&parser->parser, input);
	return parser;
}

void http_request_parser_deinit(struct http_request_parser **_parser)
{
	struct http_request_parser *parser = *_parser;

	http_message_parser_deinit(&parser->parser);
	i_free(parser);
}

static void
http_request_parser_restart(struct http_request_parser *parser)
{
	http_message_parser_restart(&parser->parser);
	memset(&parser->request, 0, sizeof(parser->request));
}

static int http_request_parse_method(struct http_request_parser *parser)
{
	const unsigned char *p = parser->parser.cur;

	/* method         = token
	 */
	while (p < parser->parser.end && http_char_is_token(*p))
		p++;

	if (p == parser->parser.end)
		return 0;
	parser->request.method =
		p_strdup_until(parser->parser.msg_pool, parser->parser.cur, p);
	parser->parser.cur = p;
	return 1;
}

static int http_request_parse_target(struct http_request_parser *parser)
{
	const unsigned char *p = parser->parser.cur;

	/* We'll just parse anything up to the first SP or a control char.
	   We could also implement workarounds for buggy HTTP clients and
	   parse anything up to the HTTP-version and return 301 with the
	   target properly encoded. */
	while (p < parser->parser.end && *p > ' ')
		p++;

	if (p == parser->parser.end)
		return 0;
	parser->request.target =
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

static int http_request_parse(struct http_request_parser *parser,
			      const char **error_r)
{
	struct http_message_parser *_parser = &parser->parser;
	int ret;

	/* request-line = method SP request-target SP HTTP-version CRLF
	 */

	for (;;) {
		switch (parser->state) {
		case HTTP_REQUEST_PARSE_STATE_INIT:
			http_request_parser_restart(parser);
			parser->state = HTTP_REQUEST_PARSE_STATE_VERSION;
			if (_parser->cur == _parser->end)
				return 0;
			if (*_parser->cur == '\r' || *_parser->cur == '\n') {
				/* HTTP/1.0 client sent a CRLF after body.
				   ignore it. */
				parser->state = HTTP_REQUEST_PARSE_STATE_CR;
				return http_request_parse(parser, error_r);
			}
			/* fall through */
		case HTTP_REQUEST_PARSE_STATE_METHOD:
			if ((ret=http_request_parse_method(parser)) <= 0) {
				if (ret < 0)
					*error_r = "Invalid HTTP method in request";
				return ret;
			}
			parser->state = HTTP_REQUEST_PARSE_STATE_SP1;
			if (_parser->cur == _parser->end)
				return 0;
			/* fall through */
		case HTTP_REQUEST_PARSE_STATE_SP1:
			if (*_parser->cur != ' ') {
				*error_r = t_strdup_printf
					("Expected ' ' after request method, but found %s",
						_chr_sanitize(*_parser->cur));
				return -1;
			}
			_parser->cur++;
			parser->state = HTTP_REQUEST_PARSE_STATE_TARGET;
			if (_parser->cur >= _parser->end)
				return 0;
			/* fall through */
		case HTTP_REQUEST_PARSE_STATE_TARGET:
			if ((ret=http_request_parse_target(parser)) <= 0) {
				if (ret < 0)
					*error_r = "Invalid HTTP target in request";
				return ret;
			}
			parser->state = HTTP_REQUEST_PARSE_STATE_SP2;
			if (_parser->cur == _parser->end)
				return 0;
			/* fall through */
		case HTTP_REQUEST_PARSE_STATE_SP2:
			if (*_parser->cur != ' ') {
				*error_r = t_strdup_printf
					("Expected ' ' after request target, but found %s",
						_chr_sanitize(*_parser->cur));
				return -1;
			}
			_parser->cur++;
			parser->state = HTTP_REQUEST_PARSE_STATE_VERSION;
			if (_parser->cur >= _parser->end)
				return 0;
			/* fall through */
		case HTTP_REQUEST_PARSE_STATE_VERSION:
			if ((ret=http_message_parse_version(&parser->parser)) <= 0) {
				if (ret < 0)
					*error_r = "Invalid HTTP version in request";
				return ret;
			}
			parser->state = HTTP_REQUEST_PARSE_STATE_CR;
			if (_parser->cur == _parser->end)
				return 0;
			/* fall through */
		case HTTP_REQUEST_PARSE_STATE_CR:
			if (*_parser->cur == '\r')
				_parser->cur++;
			parser->state = HTTP_REQUEST_PARSE_STATE_LF;
			if (_parser->cur == _parser->end)
				return 0;
			/* fall through */
		case HTTP_REQUEST_PARSE_STATE_LF:
			if (*_parser->cur != '\n') {
				*error_r = t_strdup_printf
					("Expected line end after request, but found %s",
						_chr_sanitize(*_parser->cur));
				return -1;
			}
			_parser->cur++;
			parser->state = HTTP_REQUEST_PARSE_STATE_HEADER;
			return 1;
		case HTTP_REQUEST_PARSE_STATE_HEADER:
		default:
			i_unreached();
		}
	}

	i_unreached();
	return -1;
}

static int http_request_parse_request_line(struct http_request_parser *parser,
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

		if ((ret = http_request_parse(parser, error_r)) < 0)
			return -1;

		i_stream_skip(_parser->input, _parser->cur - begin);
		if (ret > 0)
			return 1;
		old_bytes = i_stream_get_data_size(_parser->input);
	}

	i_assert(ret != -2);
	if (ret < 0) {
		if (_parser->input->eof &&
		    parser->state == HTTP_REQUEST_PARSE_STATE_INIT)
			return 0;
		*error_r = "Stream error";
		return -1;
	}
	return 0;
}

int http_request_parse_next(struct http_request_parser *parser,
			    struct http_request **request_r,
			    const char **error_r)
{
	int ret;

	/* make sure we finished streaming payload from previous request
	   before we continue. */
	if ((ret = http_message_parse_finish_payload(&parser->parser, error_r)) <= 0)
		return ret;

	/* HTTP-message   = start-line
	                   *( header-field CRLF )
	                    CRLF
	                    [ message-body ]
	 */
	if (parser->state != HTTP_REQUEST_PARSE_STATE_HEADER) {
		if ((ret = http_request_parse_request_line(parser, error_r)) <= 0)
			return ret;
	} 
	if ((ret = http_message_parse_headers(&parser->parser, error_r)) <= 0)
		return ret;
	if (http_message_parse_body(&parser->parser, error_r) < 0)
		return -1;
	parser->state = HTTP_REQUEST_PARSE_STATE_INIT;

	parser->request.version_major = parser->parser.msg.version_major;
	parser->request.version_minor = parser->parser.msg.version_minor;
	parser->request.date = parser->parser.msg.date;
	parser->request.payload = parser->parser.payload;
	parser->request.headers = parser->parser.msg.headers;
	parser->request.connection_close = parser->parser.msg.connection_close;

	*request_r = &parser->request;
	return 1;
}
