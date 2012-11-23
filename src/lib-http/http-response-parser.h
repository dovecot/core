#ifndef HTTP_RESPONSE_PARSER_H
#define HTTP_RESPONSE_PARSER_H

struct http_response_header {
	const char *key;
	const char *value;
	size_t size;
};

struct http_response {
	unsigned char version_major;
	unsigned char version_minor;

	unsigned int status;

	const char *reason;
	const char *location;

	time_t date;
	struct istream *payload;

	ARRAY(struct http_response_header) headers;

	unsigned int connection_close:1;
};

struct http_response_parser;

struct http_response_parser *
http_response_parser_init(struct istream *input);
void http_response_parser_deinit(struct http_response_parser **_parser);

int http_response_parse_next(struct http_response_parser *parser,
			     bool no_payload, struct http_response **response_r,
			     const char **error_r);

#endif
