/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "http-url.h"
#include "http-parser.h"
#include "http-message-parser.h"
#include "http-request-parser.h"

#define HTTP_REQUEST_PARSER_MAX_METHOD_LENGTH 32

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
	pool_t pool;
	
	enum http_request_parser_state state;

	struct http_url *default_base_url;

	uoff_t max_target_length;

	enum http_request_parse_error error_code;

	const char *request_method;
	const char *request_target;

	bool skipping_line:1;
};

struct http_request_parser *
http_request_parser_init(struct istream *input,
			 const struct http_url *default_base_url,
			 const struct http_request_limits *limits,
			 enum http_request_parse_flags flags)
{
	struct http_request_parser *parser;
	pool_t pool;
	struct http_header_limits hdr_limits;
	uoff_t max_payload_size;
	enum http_message_parse_flags msg_flags = 0;

	pool = pool_alloconly_create("http request parser", 512);
	parser = p_new(pool, struct http_request_parser, 1);
	parser->pool = pool;

	if (default_base_url != NULL) {
		parser->default_base_url =
			http_url_clone_authority(pool, default_base_url);
	}

	if (limits != NULL) {
		hdr_limits = limits->header;
		max_payload_size = limits->max_payload_size;
	} else {
		i_zero(&hdr_limits);
		max_payload_size = 0;
	}

	/* substitute default limits */
	if (parser->max_target_length == 0)
		parser->max_target_length =	HTTP_REQUEST_DEFAULT_MAX_TARGET_LENGTH;
	if (hdr_limits.max_size == 0)
		hdr_limits.max_size =	HTTP_REQUEST_DEFAULT_MAX_HEADER_SIZE;
	if (hdr_limits.max_field_size == 0)
		hdr_limits.max_field_size =	HTTP_REQUEST_DEFAULT_MAX_HEADER_FIELD_SIZE;
	if (hdr_limits.max_fields == 0)
		hdr_limits.max_fields =	HTTP_REQUEST_DEFAULT_MAX_HEADER_FIELDS;
	if (max_payload_size == 0)
		max_payload_size = HTTP_REQUEST_DEFAULT_MAX_PAYLOAD_SIZE;

	if ((flags & HTTP_REQUEST_PARSE_FLAG_STRICT) != 0)
		msg_flags |= HTTP_MESSAGE_PARSE_FLAG_STRICT;
	http_message_parser_init(&parser->parser, input,
		&hdr_limits, max_payload_size, msg_flags);
	return parser;
}

void http_request_parser_deinit(struct http_request_parser **_parser)
{
	struct http_request_parser *parser = *_parser;

	*_parser = NULL;

	http_message_parser_deinit(&parser->parser);
	pool_unref(&parser->pool);
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
	pool_t pool;

	/* method         = token
	 */
	while (p < parser->parser.end && http_char_is_token(*p))
		p++;

	if ((p - parser->parser.cur) > HTTP_REQUEST_PARSER_MAX_METHOD_LENGTH) {
		parser->error_code = HTTP_REQUEST_PARSE_ERROR_METHOD_TOO_LONG;
		parser->parser.error = "HTTP request method is too long";
		return -1;
	}
	if (p == parser->parser.end)
		return 0;
	pool = http_message_parser_get_pool(&parser->parser);
	parser->request_method =
		p_strdup_until(pool, parser->parser.cur, p);
	parser->parser.cur = p;
	return 1;
}

static int http_request_parse_target(struct http_request_parser *parser)
{
	struct http_message_parser *_parser = &parser->parser;
	const unsigned char *p = parser->parser.cur;
	pool_t pool;

	/* We'll just parse anything up to the first SP or a control char.
	   We could also implement workarounds for buggy HTTP clients and
	   parse anything up to the HTTP-version and return 301 with the
	   target properly encoded (FIXME). */
	while (p < _parser->end && *p > ' ')
		p++;

	/* target is too long when explicit limit is exceeded or when input buffer
	   runs out of space */
	/* FIXME: put limit on full request line rather than target and method
	   separately */
	/* FIXME: is it wise to keep target in stream buffer? It can become very
	   large for some applications, increasing the stream buffer size */
	if ((uoff_t)(p - _parser->cur) > parser->max_target_length ||
		(p == _parser->end && ((uoff_t)(p - _parser->cur) >=
			i_stream_get_max_buffer_size(_parser->input)))) {
		parser->error_code = HTTP_REQUEST_PARSE_ERROR_TARGET_TOO_LONG;
		parser->parser.error = "HTTP request target is too long";
		return -1;
	}
	if (p == _parser->end)
		return 0;
	pool = http_message_parser_get_pool(_parser);
	parser->request_target = p_strdup_until(pool, _parser->cur, p);
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

	/* RFC 7230, Section 3.1.1: Request Line

	   request-line  = method SP request-target SP HTTP-version CRLF
	   method        = token
	 */
	for (;;) {
		switch (parser->state) {
		case HTTP_REQUEST_PARSE_STATE_INIT:
			http_request_parser_restart(parser, pool);
			parser->state = HTTP_REQUEST_PARSE_STATE_SKIP_LINE;
			if (_parser->cur == _parser->end)
				return 0;
			/* fall through */
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

	while ((ret = i_stream_read_bytes(_parser->input, &begin, &size,
					  old_bytes + 1)) > 0) {
		_parser->begin = _parser->cur = begin;
		_parser->end = _parser->begin + size;

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
	case HTTP_MESSAGE_PARSE_ERROR_PAYLOAD_TOO_LARGE:
		return HTTP_REQUEST_PARSE_ERROR_PAYLOAD_TOO_LARGE;
	case HTTP_MESSAGE_PARSE_ERROR_BROKEN_MESSAGE:
		return HTTP_REQUEST_PARSE_ERROR_BROKEN_REQUEST;
	default:
		break;
	}
	i_unreached();
	return HTTP_REQUEST_PARSE_ERROR_BROKEN_REQUEST;
}

bool http_request_parser_pending_payload(
	struct http_request_parser *parser)
{
	if (parser->parser.payload == NULL)
		return FALSE;
	return i_stream_have_bytes_left(parser->parser.payload);
}

static int
http_request_parse_expect_header(struct http_request_parser *parser,
	struct http_request *request, const struct http_header_field *hdr)
{
	struct http_message_parser *_parser = &parser->parser;
	struct http_parser hparser;
	bool parse_error = FALSE;
	unsigned int num_expectations = 0;

	/* RFC 7231, Section 5.1.1:

	   Expect  = "100-continue"
	 */
	// FIXME: simplify; RFC 7231 discarded Expect extension mechanism
	http_parser_init(&hparser, (const unsigned char *)hdr->value, hdr->size);
	while (!parse_error) {
		const char *expect_name, *expect_value;

		/* expect-name */
		if (http_parse_token(&hparser, &expect_name) > 0) {
			num_expectations++;
			if (strcasecmp(expect_name, "100-continue") == 0) {
				request->expect_100_continue = TRUE;
			} else {
				if (parser->error_code == HTTP_REQUEST_PARSE_ERROR_NONE) {
					parser->error_code = HTTP_REQUEST_PARSE_ERROR_EXPECTATION_FAILED;
					_parser->error = t_strdup_printf
						("Unknown Expectation `%s'", expect_name);
				}
			}

			/* BWS "=" BWS */
			http_parse_ows(&hparser);
			if (hparser.cur >= hparser.end)
				break;
			
			if (*hparser.cur == '=') {
				hparser.cur++;
				http_parse_ows(&hparser);

				/* value */
				if (http_parse_token_or_qstring(&hparser, &expect_value) <= 0) {
					parse_error = TRUE;
					break;
				}
		
				if (parser->error_code == HTTP_REQUEST_PARSE_ERROR_NONE) {
					parser->error_code = HTTP_REQUEST_PARSE_ERROR_EXPECTATION_FAILED;
					_parser->error = t_strdup_printf
						("Expectation `%s' has unexpected value", expect_name);
				}
			}

			/* *( OWS ";" [ OWS expect-param ] ) */
			while (!parse_error) {
				const char *attribute, *value;

				/* OWS ";" */
				http_parse_ows(&hparser);
				if (hparser.cur >= hparser.end || *hparser.cur != ';')
					break;
				hparser.cur++;
				http_parse_ows(&hparser);

				/* expect-param */
				if (http_parse_token(&hparser, &attribute) <= 0) {
					parse_error = TRUE;
					break;
				}

				/* BWS "=" BWS */
				http_parse_ows(&hparser);
				if (hparser.cur >= hparser.end || *hparser.cur != '=') {
					parse_error = TRUE;
					break;
				}
				hparser.cur++;
				http_parse_ows(&hparser);

				/* value */
				if (http_parse_token_or_qstring(&hparser, &value) <= 0) {
					parse_error = TRUE;
					break;
				}

				if (parser->error_code == HTTP_REQUEST_PARSE_ERROR_NONE) {
					parser->error_code = HTTP_REQUEST_PARSE_ERROR_EXPECTATION_FAILED;
					_parser->error = t_strdup_printf
						("Expectation `%s' has unknown parameter `'%s'",
							expect_name, attribute);
				}
			}
			if (parse_error)
				break;		
		}
		http_parse_ows(&hparser);
		if (hparser.cur >= hparser.end || *hparser.cur != ',')
			break;
		hparser.cur++;
		http_parse_ows(&hparser);
	}

	if (parse_error || hparser.cur < hparser.end) {
		parser->error_code = HTTP_REQUEST_PARSE_ERROR_BAD_REQUEST;
		_parser->error = "Invalid Expect header";
		return -1;
	}

	if (parser->error_code != HTTP_REQUEST_PARSE_ERROR_NONE)
		return -1;

	if (num_expectations == 0) {
		parser->error_code = HTTP_REQUEST_PARSE_ERROR_BAD_REQUEST;
		_parser->error = "Empty Expect header";
		return -1;
	}
	return 0;
}

static int
http_request_parse_headers(struct http_request_parser *parser,
	struct http_request *request)
{
	const ARRAY_TYPE(http_header_field) *hdrs;
	const struct http_header_field *hdr;
	
	hdrs = http_header_get_fields(parser->parser.msg.header);
	array_foreach(hdrs, hdr) {
		int ret = 0;

		/* Expect: */
		if (http_header_field_is(hdr, "Expect"))
			ret = http_request_parse_expect_header(parser, request, hdr);

		if (ret < 0)
			return -1;
	}
	return 0;
}

int http_request_parse_finish_payload(
	struct http_request_parser *parser,
	enum http_request_parse_error *error_code_r,
	const char **error_r)
{
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
	}
	return ret;
}

int http_request_parse_next(struct http_request_parser *parser,
			    pool_t pool, struct http_request *request,
			    enum http_request_parse_error *error_code_r, const char **error_r)
{
	const struct http_header_field *hdr;
	const char *host_hdr, *error;
	int ret;

	/* initialize and get rid of any payload of previous request */
	if ((ret=http_request_parse_finish_payload
		(parser, error_code_r, error_r)) <= 0)
		return ret;

	/* RFC 7230, Section 3:
		
	   HTTP-message   = start-line
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

	/* RFC 7230, Section 5.4: Host

	   A server MUST respond with a 400 (Bad Request) status code to any
	   HTTP/1.1 request message that lacks a Host header field and to any
	   request message that contains more than one Host header field or a
	   Host header field with an invalid field-value.
	 */
	host_hdr = NULL;
	if (parser->parser.msg.version_major == 1 &&
	    parser->parser.msg.version_minor > 0) {
		if ((ret=http_header_field_find_unique(
			parser->parser.msg.header, "Host", &hdr)) <= 0) {
			*error_code_r = HTTP_REQUEST_PARSE_ERROR_BAD_REQUEST;
			if (ret == 0)
				*error_r = "Missing Host header";
			else
				*error_r = "Duplicate Host header";
			return -1;
		}

		host_hdr = hdr->value;
	}

	i_zero(request);

	pool = http_message_parser_get_pool(&parser->parser);
	if (http_url_request_target_parse(parser->request_target, host_hdr,
		parser->default_base_url, pool, &request->target, &error) < 0) {
		*error_code_r = HTTP_REQUEST_PARSE_ERROR_BAD_REQUEST;
		*error_r = t_strdup_printf("Bad request target `%s': %s",
			parser->request_target, error);
		return -1;
	}

	/* parse request-specific headers */
	if (http_request_parse_headers(parser, request) < 0) {
		*error_code_r = parser->error_code;
		*error_r = parser->parser.error;
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

	/* reset this state early */
	parser->request_method = NULL;
	parser->request_target = NULL;
	return 1;
}
