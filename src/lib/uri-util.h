#ifndef URI_UTIL_H
#define URI_UTIL_H

#include "net.h"

/*
 * Generic URI parsing.
 */

enum uri_parse_flags {
	/* Scheme part 'scheme:' is already parsed externally. */
	URI_PARSE_SCHEME_EXTERNAL = BIT(0),
	/* Allow '#fragment' part in URI */
	URI_PARSE_ALLOW_FRAGMENT_PART = BIT(1),
};

struct uri_host {
	const char *name;
	struct ip_addr ip;
};

struct uri_authority {
	/* encoded userinfo part; e.g. "user:pass" */
	const char *enc_userinfo;

	struct uri_host host;
	in_port_t port; /* 0 means no port specified */
};

struct uri_parser {
	pool_t pool;
	const char *error;

	const unsigned char *begin, *cur, *end;

	string_t *tmpbuf;

	bool allow_pct_nul:1;
};

/* parse one instance of percent encoding. Returns 1 for success,
   0 if none is preset at the current parser position, and -1 in
   case of error. The decoded character is returned in ch_r upon
   success */
int uri_parse_pct_encoded(struct uri_parser *parser,
		      unsigned char *ch_r);

/* parse characters as long as these comply with the the 'unreserved'
   syntax. Returns 1 if characters were found, 0 if none were found,
   and -1 if there was an error */
int uri_parse_unreserved(struct uri_parser *parser, string_t *part);
/* the same as uri_parse_unreserved(), but the allowed characters are
   extended to 'unreserved / pct-encoded', meaning that percent encoding
   is allowed */
int uri_parse_unreserved_pct(struct uri_parser *parser, string_t *part);

/* decode percent-encoded data from the 'data' parameter, up until the
   'until' parameter. If the latter is NULL, data is decoded up until the
   '\0' character. The decoded data is allocated on the parser pool and
   returned in decoded_r. Any errors are written to the parser object. */
bool uri_data_decode(struct uri_parser *parser, const char *data,
		     const char *until, const char **decoded_r) ATTR_NULL(3);

/* cut the 'scheme ":"' part from the URI. The uri_p pointer is updated to
   point just past the ":". Returns 0 on success and -1 on error. The
   result is returned in the scheme_r parameter. This can be NULL to use
   this function for merely checking the presence of a valid scheme. */
int uri_cut_scheme(const char **uri_p, const char **scheme_r)
	ATTR_NULL(2);

/* parse the URI 'scheme ":"' part. Returns 1 if successful, 0 if the first
   character is not valid for a scheme, and -1 in case of error. The
   result parameter scheme_r can be NULL to use this function for merely
   checking the presence of a valid scheme. */
int uri_parse_scheme(struct uri_parser *parser, const char **scheme_r)
	ATTR_NULL(2);

/* parse the URI 'reg-name' syntax. Returns 1 if successful, 0 if the first
   character is not valid for a host name, and -1 in case of error. The
   result parameter reg_name_r can be NULL to use this function for merely
   checking the presence of a valid host name. The result is allocated from
   the data stack.
 */
int uri_parse_reg_name(struct uri_parser *parser,
	const char **reg_name_r) ATTR_NULL(2);
/* parse the URI 'reg-name' part as an Internet host name, which is a
   sequence of domain name labels separated by '.', as defined in
   Section 3.5 of RFC 1034 and Section 2.1 of RFC 1123. Returns 1 if
   successful, 0 if the first character is not valid for a host name,
   and -1 in case of error. The result parameter host_name_r can be NULL
   to use this function for merely checking the presence of a valid host
   name. The result is allocated from the data stack.
 */
int uri_parse_host_name(struct uri_parser *parser,
	const char **host_name_r) ATTR_NULL(2);
/* parse the URI 'host' syntax, which is either an IP address literal or
   a an Internet host name, as defined in Section 3.5 of RFC 1034 and
   Section 2.1 of RFC 1123. An IP address literal is always allowed.
   Returns 1 if successful, 0 if the first character is not valid for a
   host name, and -1 in case of error. The provided host struct is filled
   in with the parsed data, all allocated from the parser pool. The host
   parameter can be NULL to use this function for merely checking for
   valid 'host' syntax.
 */
int uri_parse_host(struct uri_parser *parser,
	struct uri_host *host) ATTR_NULL(2);

/* parse the URI 'authority' syntax. Returns 1 if successful, 0 if the
   first character is not valid for the 'authority' syntax and -1 in case
   of error. The provided uri_authority struct is filled in with the parsed
   data, all allocated from the parser pool. The auth parameter can be
   NULL to use this function for merely checking for valid 'authority'
   syntax.
 */
int uri_parse_authority(struct uri_parser *parser,
	struct uri_authority *auth) ATTR_NULL(2);
/* identical to uri_parse_authority(), except that this function parses
   '"//" authority', rather than 'authority'.
 */
int uri_parse_slashslash_authority(struct uri_parser *parser,
	struct uri_authority *auth) ATTR_NULL(2);
/* identical to uri_parse_authority(), except that this function parses
   the registered name ('reg-name' syntax) as an Internet host name, as
   defined in Section 3.5 of RFC 1034 and Section 2.1 of RFC 1123.
 */
int uri_parse_host_authority(struct uri_parser *parser,
	struct uri_authority *auth) ATTR_NULL(2);
/* identical to uri_parse_slashslash_authority(), except that this
   function parses the registered name ('reg-name' syntax) as an Internet
   host name, as defined in Section 3.5 of RFC 1034 and Section 2.1 of
   RFC 1123.
 */
int uri_parse_slashslash_host_authority(struct uri_parser *parser,
	struct uri_authority *auth) ATTR_NULL(2);

/* parse the URI 'segment' syntax. Returns 1 if successful, 0 if the first
   character is not valid for the 'segment' syntax and -1 in case of
   error. The result is allocated from the parser pool. Percent encoding is
   not decoded in the result. The result parameter can be NULL to use this
   function for merely checking for valid 'segment' syntax.
 */
int uri_parse_path_segment(struct uri_parser *parser,
	const char **segment_r) ATTR_NULL(2);
/* parse the URI 'path' syntax. This also resolves '..' and '.' segments in
   the path. If the path is relative, the relative_r parameter indicates
   how many segments the base path must be moved towards root (as caused by
   leading '..' segments). Returns 1 if successful, 0 if the first character
   is not valid for the 'segment' syntax and -1 in case of error. The result
   is a NULL-terminated string list allocated from the parser pool. Percent
   encoding is not decoded in the result. The result parameter can be NULL
   to use this function for merely checking for valid 'path' syntax.
 */
int uri_parse_path(struct uri_parser *parser, int *relative_r,
		   const char *const **path_r) ATTR_NULL(2,3);

/* parse the URI 'query' syntax. Returns 1 if successful, 0 if the first
   character is not valid for the 'query' syntax and -1 in case of
   error. The result is allocated from the parser pool. Percent encoding is
   not decoded in the result. The result parameter can be NULL to use this
   function for merely checking for valid 'query' syntax.
 */
int uri_parse_query(struct uri_parser *parser,
	const char **query_r) ATTR_NULL(2);
/* parse the URI 'fragment' syntax. Returns 1 if successful, 0 if the first
   character is not valid for the 'fragment' syntax and -1 in case of
   error. The result is allocated from the parser pool. Percent encoding is
   not decoded in the result. The result parameter can be NULL to use this
   function for merely checking for valid 'fragment' syntax.
 */
int uri_parse_fragment(struct uri_parser *parser,
	const char **fragment_r) ATTR_NULL(2);

/* initialize the URI parser with the provided data */
void uri_parser_init_data(struct uri_parser *parser,
	pool_t pool, const unsigned char *data, size_t size);
/* initialize the URI parser with the provided '\0'-terminated string */
void uri_parser_init(struct uri_parser *parser,
	pool_t pool, const char *uri);

/* returns the temporary buffer associated with this parser. Can be used
   for higher-level parsing activities. */
string_t *uri_parser_get_tmpbuf(struct uri_parser *parser,
	size_t size);

/* Parse a generic (RFC3986) absolute URI for validity.
   Returns 0 if valid and -1 otherwise. Note that some URI formats like
   "sip", "aix" and "aaa" violate RFC3986 and will currently fail with
   this function.
 */
int uri_parse_absolute_generic(struct uri_parser *parser,
	enum uri_parse_flags flags);

/*
 * Generic URI manipulation
 */

/* copy uri_host struct from src to dest and allocate it on pool */
void uri_host_copy(pool_t pool, struct uri_host *dest,
	const struct uri_host *src);

/*
 * Generic URI validation
 */

/* Check whether the provided data is a valid absolute RFC3986 URI.
   Returns 0 if valid and -1 otherwise. */
int uri_check_data(const unsigned char *data, size_t size,
	enum uri_parse_flags flags, const char **error_r);
/* Check whether the provided string is a valid absolute RFC3986 URI.
   Returns 0 if valid and -1 otherwise. */
int uri_check(const char *uri, enum uri_parse_flags,
	const char **error_r);

/*
 * Generic URI construction
 */

/* encodes the '\0'-terminated data using the percent encoding. The
   esc_table is a 256 byte lookup table. If none of the esc_mask bits are
   set at the character's position in the esc_table, a character needs
   to be encoded. Also, when esc_extra contains a character, it needs to
   be encoded. All other characters are copied verbatim to the out buffer.
 */
void uri_data_encode(string_t *out,
	const unsigned char esc_table[256],
	unsigned char esc_mask, const char *esc_extra,
	const char *data) ATTR_NULL(4);

/* append the provided scheme to the out buffer */
void uri_append_scheme(string_t *out, const char *scheme);

/* append partial user data (i.e. some part of what comes before '@') to
   the out buffer. No '@' is produced. Characters are percent-encoded when
   necessary. Characters in esc are always percent-encoded, even when these
   are valid 'userinfo' characters. */
void uri_append_user_data(string_t *out,
	const char *esc, const char *data) ATTR_NULL(2);
/* append userinfo and '@' to the out buffer. Characters in userinfo are
   percent-encoded when necessary.*/
void uri_append_userinfo(string_t *out, const char *userinfo);

/* append the host name to the out buffer. Characters are percent-encoded
   when necessary.*/
void uri_append_host_name(string_t *out, const char *name);
/* append the host IP address to the out buffer. */
void uri_append_host_ip(string_t *out, const struct ip_addr *host_ip);
/* encode the URI host struct to the out buffer. */
void uri_append_host(string_t *out, const struct uri_host *host);
/* append the port to the out buffer. */
void uri_append_port(string_t *out, in_port_t port);

/* append partial path segment data to the out buffer. No '/' is produced.
   Characters are percent-encoded when necessary. Characters in esc are
   always percent-encoded, even when these are valid 'segment' characters.
 */
void uri_append_path_segment_data(string_t *out,
	const char *esc, const char *data) ATTR_NULL(2);
/* append a full path segment to the out buffer. A leading '/' is
   produced. Characters are percent-encoded when necessary. */
void uri_append_path_segment(string_t *out, const char *segment);
/* append partial path data to the out buffer. The data may include '/',
   which is not encoded. Characters are percent-encoded when necessary.
   Characters in esc are always percent-encoded, even when these are
   valid 'path' characters.*/
void uri_append_path_data(string_t *out,
	const char *esc, const char *data) ATTR_NULL(2);
/* append a full path to the out buffer. A leading '/' is produced. The
   data may include more '/', which is not encoded. Characters are
   percent-encoded when necessary.
 */
void uri_append_path(string_t *out, const char *path);

/* append partial query data to the out buffer. No leading '?' is
   produced. Characters are percent-encoded when necessary. Characters
   in esc are always percent-encoded, even when these are valid 'query'
   characters.*/
void uri_append_query_data(string_t *out,
	const char *esc, const char *data) ATTR_NULL(2);
/* append a full URI query part to the out buffer. A leading '?' is
   produced. Characters are percent-encoded when necessary. */
void uri_append_query(string_t *out, const char *query);

/* append partial fragment data to the out buffer. No leading '#' is
   produced. Characters are percent-encoded when necessary. Characters
   in esc are always percent-encoded, even when these are valid
  'fragment' characters.*/
void uri_append_fragment_data(string_t *out,
	const char *esc, const char *data) ATTR_NULL(2);
/* append a full URI fragment part to the out buffer. A leading '#' is
   produced. Characters are percent-encoded when necessary. */
void uri_append_fragment(string_t *out, const char *fragment);

/* append data to the out buffer and escape any reserved character */
void uri_append_unreserved(string_t *out, const char *data);
/* append data to the out buffer and escape any reserved character except '/' */
void uri_append_unreserved_path(string_t *out, const char *data);

#endif
