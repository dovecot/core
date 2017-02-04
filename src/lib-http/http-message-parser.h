#ifndef HTTP_MESSAGE_PARSER_H
#define HTTP_MESSAGE_PARSER_H

#include "http-response.h"
#include "http-transfer.h"

#include "http-header.h"

enum http_message_parse_error {
	HTTP_MESSAGE_PARSE_ERROR_NONE = 0,          /* no error */
	HTTP_MESSAGE_PARSE_ERROR_BROKEN_STREAM,     /* stream error */
	HTTP_MESSAGE_PARSE_ERROR_BROKEN_MESSAGE,    /* unrecoverable generic error */
	HTTP_MESSAGE_PARSE_ERROR_BAD_MESSAGE,       /* recoverable generic error */
	HTTP_MESSAGE_PARSE_ERROR_NOT_IMPLEMENTED,   /* used unimplemented feature
	                                              (recoverable) */
	HTTP_MESSAGE_PARSE_ERROR_PAYLOAD_TOO_LARGE  /* message payload is too large
	                                              (fatal) */
};

struct http_message {
	pool_t pool;

	unsigned int version_major;
	unsigned int version_minor;

	struct http_header *header;

	time_t date;
	uoff_t content_length;
	const char *location;
	ARRAY_TYPE(http_transfer_coding) transfer_encoding;
	ARRAY_TYPE(const_string) connection_options;

	bool connection_close:1;
	bool have_content_length:1;
};

struct http_message_parser {
	struct istream *input;

	struct http_header_limits header_limits;
	uoff_t max_payload_size;

	const unsigned char *cur, *end;

	const char *error;
	enum http_message_parse_error error_code;

	struct http_header_parser *header_parser;
	struct istream *payload;

	pool_t msg_pool;
	struct http_message msg;

	bool lenient:1;
};

void http_message_parser_init(struct http_message_parser *parser,
	struct istream *input, const struct http_header_limits *hdr_limits,
	uoff_t max_payload_size, bool lenient) ATTR_NULL(3);
void http_message_parser_deinit(struct http_message_parser *parser);
void http_message_parser_restart(struct http_message_parser *parser,
	pool_t pool);

pool_t http_message_parser_get_pool(struct http_message_parser *parser);

int http_message_parse_finish_payload(struct http_message_parser *parser);
int http_message_parse_version(struct http_message_parser *parser);
int http_message_parse_headers(struct http_message_parser *parser);
int http_message_parse_body(struct http_message_parser *parser, bool request);

#endif
