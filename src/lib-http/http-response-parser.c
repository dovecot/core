/* Copyright (c) 2013-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "http-parser.h"
#include "http-date.h"
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

	unsigned int response_status;
	const char *response_reason;
};

struct http_response_parser *
http_response_parser_init(struct istream *input,
	const struct http_header_limits *hdr_limits)
{
	struct http_response_parser *parser;

	/* FIXME: implement status line limit */
	parser = i_new(struct http_response_parser, 1);
	http_message_parser_init(&parser->parser, input, hdr_limits, 0, TRUE);
	return parser;
}

void http_response_parser_deinit(struct http_response_parser **_parser)
{
	struct http_response_parser *parser = *_parser;

	*_parser = NULL;

	http_message_parser_deinit(&parser->parser);
	i_free(parser);
}

static void
http_response_parser_restart(struct http_response_parser *parser)
{
	http_message_parser_restart(&parser->parser, NULL);
	parser->response_status = 0;
	parser->response_reason = NULL;
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
	parser->response_status =
		(p[0] - '0')*100 + (p[1] - '0')*10 + (p[2] - '0');
	if (parser->response_status < 100 ||
		parser->response_status >= 600)
		return -1;
	parser->parser.cur += 3;
	return 1;
}

static int http_response_parse_reason(struct http_response_parser *parser)
{
	const unsigned char *p = parser->parser.cur;

	/* reason-phrase = *( HTAB / SP / VCHAR / obs-text )
	 */
	// FIXME: limit length
	while (p < parser->parser.end && http_char_is_text(*p))
		p++;

	if (p == parser->parser.end)
		return 0;
	parser->response_reason =
		p_strdup_until(parser->parser.msg.pool, parser->parser.cur, p);
	parser->parser.cur = p;
	return 1;
}

static const char *_reply_sanitize(struct http_message_parser *parser)
{
	string_t *str = t_str_new(32);
	const unsigned char *p;
	unsigned int i;
	bool quote_open = FALSE;

	i_assert(parser->cur < parser->end);
	for (p = parser->cur, i = 0; p < parser->end && i < 20; p++, i++) {
		if (*p >= 0x20 && *p < 0x7F) {
			if (!quote_open) {
				str_append_c(str, '`');
				quote_open = TRUE;
			}
			str_append_c(str, *p);
		} else {
			if (quote_open) {
				str_append_c(str, '\'');
				quote_open = FALSE;
			}
			if (*p == 0x0a)
				str_append(str, "<LF>");
			else if (*p == 0x0d)
				str_append(str, "<CR>");
			else
				str_printfa(str, "<0x%02x>", *p);
		}
	}
	if (quote_open)
		str_append_c(str, '\'');
	return str_c(str);
}

static int http_response_parse(struct http_response_parser *parser)
{
	struct http_message_parser *_parser = &parser->parser;
	int ret;

	/* RFC 7230, Section 3.1.2: Status Line

	   status-line   = HTTP-version SP status-code SP reason-phrase CRLF
	   status-code   = 3DIGIT
	   reason-phrase = *( HTAB / SP / VCHAR / obs-text )
	 */
	switch (parser->state) {
	case HTTP_RESPONSE_PARSE_STATE_INIT:
		http_response_parser_restart(parser);
		parser->state = HTTP_RESPONSE_PARSE_STATE_VERSION;
		/* fall through */
	case HTTP_RESPONSE_PARSE_STATE_VERSION:
		if ((ret=http_message_parse_version(_parser)) <= 0) {
			if (ret < 0)
				_parser->error = t_strdup_printf(
					"Invalid HTTP version in response: %s",
					_reply_sanitize(_parser));
			return ret;
		}
		parser->state = HTTP_RESPONSE_PARSE_STATE_SP1;
		if (_parser->cur == _parser->end)
			return 0;
		/* fall through */
	case HTTP_RESPONSE_PARSE_STATE_SP1:
		if (*_parser->cur != ' ') {
			_parser->error = t_strdup_printf
				("Expected ' ' after response version, but found %s",
					_reply_sanitize(_parser));
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
				_parser->error = "Invalid HTTP status code in response";
			return ret;
		}
		parser->state = HTTP_RESPONSE_PARSE_STATE_SP2;
		if (_parser->cur == _parser->end)
			return 0;
		/* fall through */
	case HTTP_RESPONSE_PARSE_STATE_SP2:
		if (*_parser->cur != ' ') {
			_parser->error = t_strdup_printf
				("Expected ' ' after response status code, but found %s",
					_reply_sanitize(_parser));
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
			_parser->error = t_strdup_printf
				("Expected line end after response, but found %s",
					_reply_sanitize(_parser));
			return -1;
		}
		_parser->cur++;
		parser->state = HTTP_RESPONSE_PARSE_STATE_HEADER;
		return 1;
	case HTTP_RESPONSE_PARSE_STATE_HEADER:
	default:
		break;
	}

	i_unreached();
	return -1;
}

static int
http_response_parse_status_line(struct http_response_parser *parser)
{
	struct http_message_parser *_parser = &parser->parser;
	const unsigned char *begin;
	size_t size, old_bytes = 0;
	int ret;

	while ((ret = i_stream_read_bytes(_parser->input, &begin, &size,
					  old_bytes + 1)) > 0) {
		_parser->cur = begin;
		_parser->end = _parser->cur + size;

		if ((ret = http_response_parse(parser)) < 0)
			return -1;

		i_stream_skip(_parser->input, _parser->cur - begin);
		if (ret > 0)
			return 1;
		old_bytes = i_stream_get_data_size(_parser->input);
	}

	if (ret == -2) {
		_parser->error = "HTTP status line is too long";
		return -1;
	}
	if (ret < 0) {
		if (_parser->input->eof &&
		    parser->state == HTTP_RESPONSE_PARSE_STATE_INIT)
			return 0;
		_parser->error = "Stream error";
		return -1;
	}
	return 0;
}

static int
http_response_parse_retry_after(const char *hdrval, time_t resp_time,
	time_t *retry_after_r)
{
	time_t delta;

	/* RFC 7231, Section 7.1.3: Retry-After

	   The value of this field can be either an HTTP-date or a number of
	   seconds to delay after the response is received.

	     Retry-After = HTTP-date / delta-seconds

	   A delay-seconds value is a non-negative decimal integer, representing
	   time in seconds.

       delta-seconds  = 1*DIGIT
	 */
	if (str_to_time(hdrval, &delta) >= 0) {
		if (resp_time == (time_t)-1) {
			return -1;
		}
		*retry_after_r = resp_time + delta;
		return 0;
	}

	return (http_date_parse
		((unsigned char *)hdrval, strlen(hdrval), retry_after_r) ? 0 : -1);
}

int http_response_parse_next(struct http_response_parser *parser,
			     enum http_response_payload_type payload_type,
			     struct http_response *response, const char **error_r)
{
	const char *hdrval;
	time_t retry_after = (time_t)-1;
	int ret;

	/* make sure we finished streaming payload from previous response
	   before we continue. */
	if ((ret = http_message_parse_finish_payload(&parser->parser)) <= 0) {
		*error_r = parser->parser.error;
		return ret;
	}

	/* RFC 7230, Section 3:
		
	   HTTP-message   = start-line
	                   *( header-field CRLF )
	                    CRLF
	                    [ message-body ]
	 */
	if (parser->state != HTTP_RESPONSE_PARSE_STATE_HEADER) {
		if ((ret = http_response_parse_status_line(parser)) <= 0) {
			*error_r = parser->parser.error;
			return ret;
		}
	} 
	if ((ret = http_message_parse_headers(&parser->parser)) <= 0) {
		*error_r = parser->parser.error;
		return ret;
	}

	/* RFC 7230, Section 3.3.2: Content-Length

	   A server MUST NOT send a Content-Length header field in any response
	   with a status code of 1xx (Informational) or 204 (No Content).
	 */
	if ((parser->response_status / 100 == 1 || parser->response_status == 204) &&
	    parser->parser.msg.content_length > 0) {
		*error_r = t_strdup_printf(
			"Unexpected Content-Length header field for %u response "
			"(length=%"PRIuUOFF_T")", parser->response_status,
			parser->parser.msg.content_length);
		return -1;
	}

	/* RFC 7230, Section 3.3.3: Message Body Length

	   1.  Any response to a HEAD request and any response with a 1xx
	       (Informational), 204 (No Content), or 304 (Not Modified) status
	       code is always terminated by the first empty line after the
	       header fields, regardless of the header fields present in the
	       message, and thus cannot contain a message body.
	 */
	if (parser->response_status / 100 == 1 || parser->response_status == 204
		|| parser->response_status == 304) { // HEAD is handled in caller
		payload_type = HTTP_RESPONSE_PAYLOAD_TYPE_NOT_PRESENT;
	}

	if ((payload_type == HTTP_RESPONSE_PAYLOAD_TYPE_ALLOWED) ||
		(payload_type == HTTP_RESPONSE_PAYLOAD_TYPE_ONLY_UNSUCCESSFUL &&
			parser->response_status / 100 != 2)) {
		/* [ message-body ] */
		if (http_message_parse_body(&parser->parser, FALSE) < 0) {
			*error_r = parser->parser.error;
 			return -1;
		}
	}

	/* RFC 7231, Section 7.1.3: Retry-After
	
	   Servers send the "Retry-After" header field to indicate how long the
	   user agent ought to wait before making a follow-up request.  When
	   sent with a 503 (Service Unavailable) response, Retry-After indicates
	   how long the service is expected to be unavailable to the client.
	   When sent with any 3xx (Redirection) response, Retry-After indicates
	   the minimum time that the user agent is asked to wait before issuing
	   the redirected request.
	 */
	if (parser->response_status == 503 || (parser->response_status / 100) == 3) {		
		hdrval = http_header_field_get(parser->parser.msg.header, "Retry-After");
		if (hdrval != NULL) {
			(void)http_response_parse_retry_after
				(hdrval, parser->parser.msg.date, &retry_after);
			/* broken Retry-After header is ignored */
		}
	}

	parser->state = HTTP_RESPONSE_PARSE_STATE_INIT;

	memset(response, 0, sizeof(*response));
	response->status = parser->response_status;
	response->reason = parser->response_reason;
	response->version_major = parser->parser.msg.version_major;
	response->version_minor = parser->parser.msg.version_minor;
	response->location = parser->parser.msg.location;
	response->date = parser->parser.msg.date;
	response->retry_after = retry_after;
	response->payload = parser->parser.payload;
	response->header = parser->parser.msg.header;
	response->headers = *http_header_get_fields(response->header); /* FIXME: remove in v2.3 */
	response->connection_options = parser->parser.msg.connection_options;
	response->connection_close = parser->parser.msg.connection_close;
	return 1;
}
