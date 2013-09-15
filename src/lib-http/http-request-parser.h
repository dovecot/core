#ifndef HTTP_REQUEST_PARSER_H
#define HTTP_REQUEST_PARSER_H

#include "http-request.h"

struct http_request_parser *
http_request_parser_init(struct istream *input,
	const struct http_header_limits *hdr_limits) ATTR_NULL(2);
void http_request_parser_deinit(struct http_request_parser **_parser);

int http_request_parse_next(struct http_request_parser *parser,
			    pool_t pool, struct http_request *request,
			    const char **error_r);

#endif
