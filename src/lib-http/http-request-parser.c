/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "http-url.h"
#include "http-parser.h"
#include "http-message-parser.h"
#include "http-request-parser.h"

enum http_request_parser_state {
	HTTP_REQUEST_PARSE_STATE_INIT = 0,
	HTTP_REQUEST_PARSE_STATE_SKIP_LINE,
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

	enum http_request_parse_error error_code;

	const char *request_method;
	const char *request_target;

	unsigned int skipping_line:1;
};

struct http_request_parser *
http_request_parser_init(struct istream *input,
	const struct http_header_limits *hdr_limits)
{
	struct http_request_parser *parser;

	parser = i_new(struct http_request_parser, 1);
	http_message_parser_init(&parser->parser, input, hdr_limits);
	return parser;
}

void http_request_parser_deinit(struct http_request_parser **_parser)
{
	struct http_request_parser *parser = *_parser;

	http_message_parser_deinit(&parser->parser);
	i_free(parser);
}

static void
http_request_parser_restart(struct http_request_parser *parser,
	pool_t pool)
{
	http_message_parser_restart(&parser->parser, pool);
	parser->request_method = NULL;
	parser->request_target = NULL;
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
	parser->request_method =
		p_strdup_until(parser->parser.msg.pool, parser->parser.cur, p);
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
	parser->request_target =
		p_strdup_until(parser->parser.msg.pool, parser->parser.cur, p);
	parser->parser.cur = p;
	return 1;
}

static inline const char *_chr_sanitize(unsigned char c)
{
	if (c >= 0x20 && c < 0x7F)
		return t_strdup_printf("`%c'", c);
	if (c == 0x0a)
		return "<LF>";
	if (c == 0x0d)
		return "<CR>";
	return t_strdup_printf("<0x%02x>", c);
}

static int http_request_parse(struct http_request_parser *parser,
			      pool_t pool)
{
	struct http_message_parser *_parser = &parser->parser;
	int ret;

	/* request-line = method SP request-target SP HTTP-version CRLF
	 */

	for (;;) {
		switch (parser->state) {
		case HTTP_REQUEST_PARSE_STATE_INIT:
			http_request_parser_restart(parser, pool);
			parser->state = HTTP_REQUEST_PARSE_STATE_SKIP_LINE;
			if (_parser->cur == _parser->end)
				return 0;
		case HTTP_REQUEST_PARSE_STATE_SKIP_LINE:
			if (*_parser->cur == '\r' || *_parser->cur == '\n') {
				if (parser->skipping_line) {
					/* second extra CRLF; not allowed */
					parser->error_code = HTTP_REQUEST_PARSE_ERROR_BROKEN_REQUEST;
					_parser->error = "Empty request line";
					return -1;
				}
				/* HTTP/1.0 client sent one extra CRLF after body.
				   ignore it. */
				parser->skipping_line = TRUE;
				parser->state = HTTP_REQUEST_PARSE_STATE_CR;
				break;
			}
			parser->state = HTTP_REQUEST_PARSE_STATE_METHOD;
			parser->skipping_line = FALSE;
			/* fall through */
		case HTTP_REQUEST_PARSE_STATE_METHOD:
			if ((ret=http_request_parse_method(parser)) <= 0)
				return ret;
			parser->state = HTTP_REQUEST_PARSE_STATE_SP1;
			if (_parser->cur == _parser->end)
				return 0;
			/* fall through */
		case HTTP_REQUEST_PARSE_STATE_SP1:
			if (*_parser->cur != ' ') {
				parser->error_code = HTTP_REQUEST_PARSE_ERROR_BROKEN_REQUEST;
				_parser->error = t_strdup_printf
					("Unexpected character %s in request method",
						_chr_sanitize(*_parser->cur));
				return -1;
			}
			_parser->cur++;
			parser->state = HTTP_REQUEST_PARSE_STATE_TARGET;
			if (_parser->cur >= _parser->end)
				return 0;
			/* fall through */
		case HTTP_REQUEST_PARSE_STATE_TARGET:
			if ((ret=http_request_parse_target(parser)) <= 0)
				return ret;
			parser->state = HTTP_REQUEST_PARSE_STATE_SP2;
			if (_parser->cur == _parser->end)
				return 0;
			/* fall through */
		case HTTP_REQUEST_PARSE_STATE_SP2:
			if (*_parser->cur != ' ') {
				parser->error_code = HTTP_REQUEST_PARSE_ERROR_BROKEN_REQUEST;
				_parser->error = t_strdup_printf
					("Unexpected character %s in request target",
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
				if (ret < 0) {
					parser->error_code = HTTP_REQUEST_PARSE_ERROR_BROKEN_REQUEST;
					_parser->error = "Invalid HTTP version in request";
				}
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
				parser->error_code = HTTP_REQUEST_PARSE_ERROR_BROKEN_REQUEST;
				_parser->error = t_strdup_printf
					("Unexpected character %s at end of request line",
						_chr_sanitize(*_parser->cur));
				return -1;
			}
			_parser->cur++;
			if (!parser->skipping_line) {
				parser->state = HTTP_REQUEST_PARSE_STATE_HEADER;
				return 1;
			}
			parser->state = HTTP_REQUEST_PARSE_STATE_INIT;
			break;
 		case HTTP_REQUEST_PARSE_STATE_HEADER:
 		default:
 			i_unreached();
		}
	}

	i_unreached();
	return -1;
}

static int http_request_parse_request_line(struct http_request_parser *parser,
					   pool_t pool)
{
	struct http_message_parser *_parser = &parser->parser;
	const unsigned char *begin;
	size_t size, old_bytes = 0;
	int ret;

	while ((ret = i_stream_read_data(_parser->input, &begin, &size,
					 old_bytes)) > 0) {
		_parser->cur = begin;
		_parser->end = _parser->cur + size;

		if ((ret = http_request_parse(parser, pool)) < 0)
			return -1;

		i_stream_skip(_parser->input, _parser->cur - begin);
		if (ret > 0)
			return 1;
		old_bytes = i_stream_get_data_size(_parser->input);
	}

	if (ret == -2) {
		parser->error_code = HTTP_REQUEST_PARSE_ERROR_BROKEN_REQUEST;
		_parser->error = "HTTP request line is too long";
		return -1;
	}
	if (ret < 0) {
		if (_parser->input->eof &&
	    parser->state == HTTP_REQUEST_PARSE_STATE_INIT)
			return 0;
		parser->error_code = HTTP_REQUEST_PARSE_ERROR_BROKEN_STREAM;
		_parser->error = "Broken stream";
		return -1;
	}
	return 0;
}

static inline enum http_request_parse_error
http_request_parser_message_error(struct http_request_parser *parser)
{
	switch (parser->parser.error_code) {
	case HTTP_MESSAGE_PARSE_ERROR_BROKEN_STREAM:
		return HTTP_REQUEST_PARSE_ERROR_BROKEN_STREAM;
	case HTTP_MESSAGE_PARSE_ERROR_BAD_MESSAGE:
		return HTTP_REQUEST_PARSE_ERROR_BAD_REQUEST;
	case HTTP_MESSAGE_PARSE_ERROR_NOT_IMPLEMENTED:
		return HTTP_REQUEST_PARSE_ERROR_NOT_IMPLEMENTED;
	case HTTP_MESSAGE_PARSE_ERROR_BROKEN_MESSAGE:
		return HTTP_REQUEST_PARSE_ERROR_BROKEN_REQUEST;
	default:
		break;
	}
	i_unreached();
	return HTTP_REQUEST_PARSE_ERROR_BROKEN_REQUEST;
}

int http_request_parse_next(struct http_request_parser *parser,
			    pool_t pool, struct http_request *request,
			    enum http_request_parse_error *error_code_r, const char **error_r)
{
	const struct http_header_field *hdr;
	const char *error;
	int ret;

	*error_code_r = parser->error_code = HTTP_REQUEST_PARSE_ERROR_NONE;
	*error_r = parser->parser.error = NULL;

	/* make sure we finished streaming payload from previous request
	   before we continue. */
	if ((ret = http_message_parse_finish_payload(&parser->parser)) <= 0) {
		if (ret < 0) {
			*error_code_r = http_request_parser_message_error(parser);
			*error_r = parser->parser.error;
		}
		return ret;
	}

	/* HTTP-message   = start-line
	                   *( header-field CRLF )
	                    CRLF
	                    [ message-body ]
	 */
	if (parser->state != HTTP_REQUEST_PARSE_STATE_HEADER) {
		ret = http_request_parse_request_line(parser, pool);

		/* assign early for error reporting */
		request->method = parser->request_method;
		request->target_raw = parser->request_target; 
		request->version_major = parser->parser.msg.version_major;
		request->version_minor = parser->parser.msg.version_minor;

		if (ret <= 0) {
			if (ret < 0) {
				*error_code_r = parser->error_code;
				*error_r = parser->parser.error;
			}
			return ret;
		}
	}

	if ((ret = http_message_parse_headers(&parser->parser)) <= 0) {
		if (ret < 0) {
			*error_code_r = http_request_parser_message_error(parser);
			*error_r = parser->parser.error;
		}
		return ret;
	}

	if (http_message_parse_body(&parser->parser, TRUE) < 0) {
		*error_code_r = http_request_parser_message_error(parser);
		*error_r = parser->parser.error;
		return -1;
	}
	parser->state = HTTP_REQUEST_PARSE_STATE_INIT;

	/* https://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging-23
	     Section 5.4:

	   A server MUST respond with a 400 (Bad Request) status code to any
	   HTTP/1.1 request message that lacks a Host header field and to any
	   request message that contains more than one Host header field or a
	   Host header field with an invalid field-value.
	 */
	if ((ret=http_header_field_find_unique
		(parser->parser.msg.header, "Host", &hdr)) <= 0) {
		*error_code_r = HTTP_REQUEST_PARSE_ERROR_BAD_REQUEST;
		if (ret == 0)
			*error_r = "Missing Host header";
		else
			*error_r = "Duplicate Host header";
		return -1;
	}

	memset(request, 0, sizeof(*request));

	if (http_url_request_target_parse(parser->request_target, hdr->value,
		parser->parser.msg.pool, &request->target, &error) < 0) {
		*error_code_r = HTTP_REQUEST_PARSE_ERROR_BAD_REQUEST;
		*error_r = t_strdup_printf("Bad request target `%s': %s",
			parser->request_target, error);
		return -1;
	}

	request->method = parser->request_method;
	request->target_raw = parser->request_target;
	request->version_major = parser->parser.msg.version_major;
	request->version_minor = parser->parser.msg.version_minor;
	request->date = parser->parser.msg.date;
	request->payload = parser->parser.payload;
	request->header = parser->parser.msg.header;
	request->connection_options = parser->parser.msg.connection_options;
	request->connection_close = parser->parser.msg.connection_close;
	return 1;
}
