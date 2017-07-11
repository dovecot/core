#ifndef HTTP_RESPONSE_PARSER_H
#define HTTP_RESPONSE_PARSER_H

#include "http-response.h"

struct http_header_limits;
struct http_response_parser;

enum http_response_parse_flags {
	/* Strictly adhere to the HTTP protocol specification */
	HTTP_RESPONSE_PARSE_FLAG_STRICT = BIT(0)
};

struct http_response_parser *
http_response_parser_init(struct istream *input,
	const struct http_header_limits *hdr_limits,
	enum http_response_parse_flags flags) ATTR_NULL(2);
void http_response_parser_deinit(struct http_response_parser **_parser);

int http_response_parse_next(struct http_response_parser *parser,
			     enum http_response_payload_type payload_type,
			     struct http_response *response, const char **error_r);

#endif
