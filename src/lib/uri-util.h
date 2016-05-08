#ifndef URI_UTIL_H
#define URI_UTIL_H

#include "net.h"

/*
 * Generic URI parsing.
 */

struct uri_host {
	const char *name;
	struct ip_addr ip;
};

struct uri_authority {
	const char *enc_userinfo;

	struct uri_host host;
	in_port_t port;
};

struct uri_parser {
	pool_t pool;
	const char *error;

	const unsigned char *begin, *cur, *end;

	string_t *tmpbuf;
};

int uri_parse_pct_encoded(struct uri_parser *parser,
		      unsigned char *ch_r);

int uri_parse_unreserved(struct uri_parser *parser, string_t *part);
int uri_parse_unreserved_pct(struct uri_parser *parser, string_t *part);

bool uri_data_decode(struct uri_parser *parser, const char *data,
		     const char *until, const char **decoded_r) ATTR_NULL(3);

int uri_cut_scheme(const char **uri_p, const char **scheme_r)
	ATTR_NULL(2);
int uri_parse_scheme(struct uri_parser *parser, const char **scheme_r)
	ATTR_NULL(2);

int uri_parse_host_name_dns(struct uri_parser *parser,
	const char **host_name_r) ATTR_NULL(2);
int uri_parse_host(struct uri_parser *parser,
	struct uri_host *host, bool dns_name) ATTR_NULL(2);

int uri_parse_authority(struct uri_parser *parser,
	struct uri_authority *auth, bool dns_name) ATTR_NULL(2);
int uri_parse_slashslash_authority(struct uri_parser *parser,
	struct uri_authority *auth, bool dns_name) ATTR_NULL(2);

int uri_parse_path_segment(struct uri_parser *parser,
	const char **segment_r) ATTR_NULL(2);
int uri_parse_path(struct uri_parser *parser, int *relative_r,
		   const char *const **path_r) ATTR_NULL(2,3);

int uri_parse_query(struct uri_parser *parser,
	const char **query_r) ATTR_NULL(2);
int uri_parse_fragment(struct uri_parser *parser,
	const char **fragment_r) ATTR_NULL(2);

void uri_parser_init_data(struct uri_parser *parser,
	pool_t pool, const unsigned char *data, size_t size);
void uri_parser_init(struct uri_parser *parser,
	pool_t pool, const char *uri);

string_t *uri_parser_get_tmpbuf(struct uri_parser *parser,
	size_t size);

/*
 * Generic URI manipulation
 */

void uri_host_copy(pool_t pool, struct uri_host *dest,
	const struct uri_host *src);

/*
 * Generic URI construction
 */

void uri_data_encode(string_t *out,
	const unsigned char esc_table[256],
	unsigned char esc_mask, const char *esc_extra,
	const char *data) ATTR_NULL(4);

void uri_append_scheme(string_t *out, const char *scheme);

void uri_append_user_data(string_t *out,
	const char *esc, const char *data) ATTR_NULL(2);
void uri_append_userinfo(string_t *out, const char *userinfo);

void uri_append_host_name(string_t *out, const char *name);
void uri_append_host_ip(string_t *out, const struct ip_addr *host_ip);
void uri_append_host(string_t *out, const struct uri_host *host);
void uri_append_port(string_t *out, in_port_t port);

void uri_append_path_segment_data(string_t *out,
	const char *esc, const char *data) ATTR_NULL(2);
void uri_append_path_segment(string_t *out, const char *segment);
void uri_append_path_data(string_t *out,
	const char *esc, const char *data) ATTR_NULL(2);
void uri_append_path(string_t *out, const char *path);

void uri_append_query_data(string_t *out,
	const char *esc, const char *data) ATTR_NULL(2);
void uri_append_query(string_t *out, const char *query);

void uri_append_fragment_data(string_t *out,
	const char *esc, const char *data) ATTR_NULL(2);
void uri_append_fragment(string_t *out, const char *fragment);

#endif
