#ifndef URI_UTIL_H
#define URI_UTIL_H

/*
 * Generic URI parsing.
 */

struct uri_authority {
	const char *enc_userinfo;

	const char *host_literal;
	struct ip_addr host_ip;

	in_port_t port;

	unsigned int have_host_ip:1;
	unsigned int have_port:1;
};

struct uri_parser {
	pool_t pool;
	const char *error;

	const unsigned char *begin, *cur, *end;

	string_t *tmpbuf;
};

int uri_parse_unreserved(struct uri_parser *parser, string_t *part);

bool uri_data_decode(struct uri_parser *parser, const char *data,
		     const char *until, const char **decoded_r) ATTR_NULL(3);

int uri_cut_scheme(const char **uri_p, const char **scheme_r);
int uri_parse_scheme(struct uri_parser *parser, const char **scheme_r);
int uri_parse_authority(struct uri_parser *parser, struct uri_authority *auth);

int uri_parse_path_segment(struct uri_parser *parser, const char **segment_r);
int uri_parse_path(struct uri_parser *parser, int *relative_r,
		   const char *const **path_r);

int uri_parse_query(struct uri_parser *parser, const char **query_r);
int uri_parse_fragment(struct uri_parser *parser, const char **fragment_r);

void uri_parser_init(struct uri_parser *parser, pool_t pool, const char *data);
string_t *uri_parser_get_tmpbuf(struct uri_parser *parser, size_t size);

#endif

