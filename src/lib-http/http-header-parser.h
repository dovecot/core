#ifndef HTTP_HEADER_PARSER_H
#define HTTP_HEADER_PARSER_H

struct http_header_parser;

struct http_header_parser *http_header_parser_init(struct istream *input);
void http_header_parser_deinit(struct http_header_parser **_parser);

void http_header_parser_reset(struct http_header_parser *parser);

int http_header_parse_next_field(struct http_header_parser *parser,
	const char **name_r, const unsigned char **data_r, size_t *size_r,
	const char **error_r);

#endif
