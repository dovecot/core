/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "strfuncs.h"
#include "net.h"
#include "uri-util.h"
#include "http-url.h"

/*
 * HTTP URL parser
 */

struct http_url_parser {
	struct uri_parser parser;

	enum http_url_parse_flags flags;

	struct http_url *url;
	struct http_url *base;

	unsigned int relative:1;
};

static bool http_url_do_parse(struct http_url_parser *url_parser)
{
	struct uri_parser *parser = &url_parser->parser;
	struct http_url *url = url_parser->url, *base = url_parser->base;
	struct uri_authority auth;
	const char *const *path;
	bool relative = TRUE, have_path = FALSE;
	int path_relative;
	const char *part;
	int ret;

	/* RFC 2616 - Hypertext Transfer Protocol, Section 3.2:
	 *   
	 * http_URL = "http:" "//" host [ ":" port ] [ abs_path [ "?" query ]]
	 * 
	 * Translated to RFC 3986:
	 *
	 * absolute-http-URL = "http:" "//" host [ ":" port ] path-absolute
	 *                       ["?" query] [ "#" fragment ]
	 * relative-http-ref = relative-http-part [ "?" query ] [ "#" fragment ]
	 * relative-http-part = "//" host [ ":" port ] path-abempty
	 *                      / path-absolute
	 *                      / path-noscheme
	 *                      / path-empty
	 */

	/* "http:" / "https:" */
	if ((url_parser->flags & HTTP_URL_PARSE_SCHEME_EXTERNAL) == 0) {
		const char *scheme;

		if ((ret = uri_parse_scheme(parser, &scheme)) < 0)
			return FALSE;
		else if (ret > 0) {
			if (strcasecmp(scheme, "https") == 0) {
				if (url != NULL)
					url->have_ssl = TRUE;
			} else if (strcasecmp(scheme, "http") != 0) {
				parser->error = "Not an HTTP URL";
				return FALSE;
			}
			relative = FALSE;
		}
	} else {
		relative = FALSE;
	}

	/* "//" host [ ":" port ] */
	if ((ret = uri_parse_authority(parser, &auth)) < 0)
		return FALSE;
	if (ret > 0) {
		if (auth.enc_userinfo != NULL) {
			/* http://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging-20

				 Section 2.8.1:

			   {...} Senders MUST NOT include a userinfo subcomponent (and its "@"
			   delimiter) when transmitting an "http" URI in a message. Recipients
			   of HTTP messages that contain a URI reference SHOULD parse for the
			   existence of userinfo and treat its presence as an error, likely
			   indicating that the deprecated subcomponent is being used to
			   obscure the authority for the sake of phishing attacks.
			 */
			parser->error = "HTTP URL does not allow `userinfo@' part";
			return FALSE;
		}
		relative = FALSE;
	} else if (!relative) {
		parser->error = "Absolute HTTP URL requires `//' after `http:'";
		return FALSE;
	}

	if (ret > 0 && url != NULL) {
		url->host_name = p_strdup(parser->pool, auth.host_literal);
		url->host_ip = auth.host_ip;
		url->have_host_ip = auth.have_host_ip;
		url->port = auth.port;
		url->have_port = auth.have_port;
	}

	/* path-abempty / path-absolute / path-noscheme / path-empty */
	if ((ret = uri_parse_path(parser, &path_relative, &path)) < 0)
		return FALSE;

	/* Relative URLs are only valid when we have a base URL */
	if (relative) {
		if (base == NULL) {
			parser->error = "Relative URL not allowed";
			return FALSE;
		} else if (url != NULL) {
			url->host_name = p_strdup_empty(parser->pool, base->host_name); 
			url->host_ip = base->host_ip;
			url->have_host_ip = base->have_host_ip;
			url->port = base->port;
			url->have_port = base->have_port;
		}

		url_parser->relative = TRUE;
	}

	/* Resolve path */
	if (ret > 0) {
		string_t *fullpath = NULL;

		have_path = TRUE;

		if (url != NULL)
			fullpath = t_str_new(256);

		if (relative && path_relative > 0 && base->path != NULL) {
			const char *pbegin = base->path;
			const char *pend = base->path + strlen(base->path);
			const char *p = pend - 1;

			i_assert(*pbegin == '/');

			/* discard trailing segments of base path based on how many effective
			   leading '..' segments were found in the relative path.
			 */
			while (path_relative > 0 && p > pbegin) {
				while (p > pbegin && *p != '/') p--;
				if (p >= pbegin) {
					pend = p;
					path_relative--;
				}
				if (p > pbegin) p--;
			}

			if (url != NULL && pend > pbegin)
				str_append_n(fullpath, pbegin, pend-pbegin);
		}
	
		/* append relative path */
		while (*path != NULL) {
			if (!uri_data_decode(parser, *path, NULL, &part))
				return FALSE;

			if (url != NULL) {
				str_append_c(fullpath, '/');
				str_append(fullpath, part);
			}	
			path++;
		}

		if (url != NULL)
			url->path = p_strdup(parser->pool, str_c(fullpath));
	} else if (relative && url != NULL) {
		url->path = p_strdup(parser->pool, base->path);
	}
	
	/* [ "?" query ] */
	if ((ret = uri_parse_query(parser, &part)) < 0)
		return FALSE;
	if (ret > 0) {
		if (!uri_data_decode(parser, part, NULL, NULL)) // check only
			return FALSE;
		if (url != NULL)
			url->enc_query = p_strdup(parser->pool, part);
	} else if (relative && !have_path && url != NULL) {
		url->enc_query = p_strdup(parser->pool, base->enc_query);		
	}

	/* [ "#" fragment ] */
	if ((ret = uri_parse_fragment(parser, &part)) < 0) 
		return FALSE;
	if (ret > 0) {	
		if ((url_parser->flags & HTTP_URL_ALLOW_FRAGMENT_PART) == 0) {
			parser->error = "URL fragment not allowed for HTTP URL in this context";
			return FALSE;
		}
		if (!uri_data_decode(parser, part, NULL, NULL)) // check only
			return FALSE;
		if (url != NULL)
			url->enc_fragment =  p_strdup(parser->pool, part);
	} else if (relative && !have_path && url != NULL) {
		url->enc_fragment = p_strdup(parser->pool, base->enc_fragment);		
	}

	if (parser->cur != parser->end) {
		parser->error = "HTTP URL contains invalid character.";
		return FALSE;
	}
	return TRUE;
}

/* Public API */

int http_url_parse(const char *url, struct http_url *base,
		   enum http_url_parse_flags flags, pool_t pool,
		   struct http_url **url_r, const char **error_r)
{
	struct http_url_parser url_parser;

	/* base != NULL indicates whether relative URLs are allowed. However, certain
	   flags may also dictate whether relative URLs are allowed/required. */
	i_assert((flags & HTTP_URL_PARSE_SCHEME_EXTERNAL) == 0 || base == NULL);

	memset(&url_parser, '\0', sizeof(url_parser));
	uri_parser_init(&url_parser.parser, pool, url);

	url_parser.url = p_new(pool, struct http_url, 1);
	url_parser.base = base;
	url_parser.flags = flags;

	if (!http_url_do_parse(&url_parser)) {
		*error_r = url_parser.parser.error;
		return -1;
	}
	*url_r = url_parser.url;
	return 0;
}

/*
 * HTTP URL construction
 */

static void http_url_add_target(string_t *urlstr, const struct http_url *url)
{
	if (url->path == NULL || *url->path == '\0') {
		/* Older syntax of RFC 2616 requires this slash at all times for an
			 absolute URL
		 */
		str_append_c(urlstr, '/');
	} else {
		uri_append_path_data(urlstr, "", url->path);
	}

	/* query (pre-encoded) */
	if (url->enc_query != NULL) {
		str_append_c(urlstr, '?');
		str_append(urlstr, url->enc_query);
	}
}

const char *http_url_create(const struct http_url *url)
{
	string_t *urlstr = t_str_new(512);

	/* scheme */
	uri_append_scheme(urlstr, "http");
	str_append(urlstr, "//");

	/* host:port */
	if (url->host_name != NULL) {
		/* assume IPv6 literal if starts with '['; avoid encoding */
		if (*url->host_name == '[')
			str_append(urlstr, url->host_name);
		else
			uri_append_host_name(urlstr, url->host_name);
	} else if (url->have_host_ip) {
		uri_append_host_ip(urlstr, &url->host_ip);
	} else
		i_unreached();
	if (url->have_port)
		uri_append_port(urlstr, url->port);

	http_url_add_target(urlstr, url);

	/* fragment */
	if (url->enc_fragment != NULL) {
		str_append_c(urlstr, '#');
		str_append(urlstr, url->enc_fragment);
	}

	return str_c(urlstr);
}

const char *http_url_create_target(const struct http_url *url)
{
	string_t *urlstr = t_str_new(256);

	http_url_add_target(urlstr, url);

	return str_c(urlstr);
}

void http_url_escape_param(string_t *out, const char *data)
{
	uri_append_query_data(out, "&;/?=+", data);
}
