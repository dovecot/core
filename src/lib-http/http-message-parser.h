#ifndef HTTP_MESSAGE_PARSER_H
#define HTTP_MESSAGE_PARSER_H

#include "http-response.h"
#include "http-transfer.h"

struct http_header;

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

	unsigned int connection_close:1;
	unsigned int have_content_length:1;
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
void http_message_parser_restart(struct http_message_parser *parser,
	pool_t pool);

int http_message_parse_finish_payload(struct http_message_parser *parser,
				      const char **error_r);
int http_message_parse_version(struct http_message_parser *parser);
int http_message_parse_headers(struct http_message_parser *parser,
			       const char **error_r);
int http_message_parse_body(struct http_message_parser *parser, bool request,
			    const char **error_r);

#endif
