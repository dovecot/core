#ifndef HTTP_RESPONSE_PARSER_H
#define HTTP_RESPONSE_PARSER_H

#include "http-response.h"

struct http_response_parser;

struct http_response_parser *
http_response_parser_init(struct istream *input);
void http_response_parser_deinit(struct http_response_parser **_parser);

int http_response_parse_next(struct http_response_parser *parser,
			     bool no_payload, struct http_response **response_r,
			     const char **error_r);

#endif
