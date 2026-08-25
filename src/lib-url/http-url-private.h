#ifndef HTTP_URL_PRIVATE
#define HTTP_URL_PRIVATE 1

#include "http-url.h"

/*
 * HTTP URL parser
 */

struct http_url_parser {
	struct uri_parser parser;

	enum http_url_parse_flags flags;

	struct http_url *url;
	struct http_url *base;

	enum http_request_target_format req_format;

	bool relative:1;
	bool request_target:1;
};

bool http_url_do_parse(struct http_url_parser *url_parser);

#endif
