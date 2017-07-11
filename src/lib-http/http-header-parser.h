#ifndef HTTP_HEADER_PARSER_H
#define HTTP_HEADER_PARSER_H

struct http_header_limits;
struct http_header_parser;

enum http_header_parse_flags {
	/* Strictly adhere to the HTTP protocol specification */
	HTTP_HEADER_PARSE_FLAG_STRICT = BIT(0)
};

struct http_header_parser *
http_header_parser_init(struct istream *input,
	const struct http_header_limits *limits,
	enum http_header_parse_flags flags);
void http_header_parser_deinit(struct http_header_parser **_parser);

void http_header_parser_reset(struct http_header_parser *parser);

int http_header_parse_next_field(struct http_header_parser *parser,
	const char **name_r, const unsigned char **data_r, size_t *size_r,
	const char **error_r);

#endif
