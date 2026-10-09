/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "uri-util.h"

#include "http-request.h"
#include "http-url-private.h"

bool http_request_has_connection_option(const struct http_request *req,
	const char *option)
{
	const char *opt;

	if (!array_is_created(&req->connection_options))
		return FALSE;
	array_foreach_elem(&req->connection_options, opt) {
		if (strcasecmp(opt, option) == 0)
			return TRUE;
	}
	return FALSE;
}

int http_request_get_payload_size(const struct http_request *req,
	uoff_t *size_r)
{
	if (req->payload == NULL) {
		*size_r = 0;
		return 1;
	}

	return i_stream_get_size(req->payload, TRUE, size_r);
}

int http_url_request_target_parse(const char *request_target,
				  const char *host_header,
				  const struct http_url *default_base,
				  pool_t pool,
				  struct http_request_target *target,
				  const char **error_r)
{
	struct http_url_parser url_parser;
	struct uri_authority auth;
	struct http_url base;

	if (default_base == NULL)
		i_zero(&base);
	else
		http_url_init_authority_from(&base, default_base);
	if (host_header != NULL && *host_header != '\0') {
		struct uri_parser *parser;

		i_zero(&url_parser);
		parser = &url_parser.parser;
		uri_parser_init(parser, pool, host_header);

		if (uri_parse_host_authority(parser, &auth) <= 0) {
			*error_r = t_strdup_printf("Invalid Host header: %s",
						   parser->error);
			return -1;
		}

		if (parser->cur != parser->end) {
			*error_r = t_strdup_printf(
				"Invalid Host header: "
				"Contains invalid character %s",
				uri_char_sanitize(*parser->cur));
			return -1;
		}
		if (auth.enc_userinfo != NULL) {
			*error_r = "Invalid Host header: "
				"Contains inappropriate 'userinfo@' part";
			return -1;
		}

		base.host = auth.host;
		base.port = auth.port;
	} else if (default_base == NULL) {
		*error_r = "Empty Host header";
		return -1;
	} else {
		i_assert(default_base != NULL);
	}

	if (request_target[0] == '*' && request_target[1] == '\0') {
		struct http_url *url = p_new(pool, struct http_url, 1);

		uri_host_copy(pool, &url->host, &base.host);
		url->port = base.port;
		target->url = url;
		target->format = HTTP_REQUEST_TARGET_FORMAT_ASTERISK;
		return 0;
	}

	i_zero(&url_parser);
	uri_parser_init(&url_parser.parser, pool, request_target);

	url_parser.url = p_new(pool, struct http_url, 1);
	url_parser.request_target = TRUE;
	url_parser.req_format = HTTP_REQUEST_TARGET_FORMAT_ORIGIN;
	url_parser.base = &base;
	url_parser.flags = 0;

	if (!http_url_do_parse(&url_parser)) {
		*error_r = url_parser.parser.error;
		return -1;
	}

	target->url = url_parser.url;
	target->format = url_parser.req_format;
	return 0;
}
