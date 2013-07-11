#ifndef HTTP_MESSAGE_PARSER_H
#define HTTP_MESSAGE_PARSER_H

#include "http-response.h"

struct http_message {
	unsigned int version_major;
	unsigned int version_minor;

	ARRAY_TYPE(http_response_header) headers;
	time_t date;

	uoff_t content_length;
	const char *location;
	const char *transfer_encoding;

	unsigned int connection_close:1;
};

struct http_message_parser {
	struct istream *input;

	const unsigned char *cur, *end;

	struct http_header_parser *header_parser;
	struct istream *payload;

	pool_t msg_pool;
	struct http_message msg;
};

void http_message_parser_init(struct http_message_parser *parser,
			      struct istream *input);
void http_message_parser_deinit(struct http_message_parser *parser);
void http_message_parser_restart(struct http_message_parser *parser);

int http_message_parse_finish_payload(struct http_message_parser *parser,
				      const char **error_r);
int http_message_parse_version(struct http_message_parser *parser);
int http_message_parse_headers(struct http_message_parser *parser,
			       const char **error_r);
int http_message_parse_body(struct http_message_parser *parser,
			    const char **error_r);

#endif
