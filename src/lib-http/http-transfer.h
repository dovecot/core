#ifndef HTTP_TRANSFER_H
#define HTTP_TRANSFER_H

#include "http-header.h"

/* Total Size (256 KB): This is very generous. Most trailers are just a few
 * hundred bytes (e.g., a hash or a signature). 256 KB allows for complex
 * metadata while preventing a single request from consuming significant
 * memory. */
#define HTTP_TRANSFER_CHUNKED_DEFAULT_MAX_TRAILER_SIZE (256 * 1024)
/* Field Size (8 KB): This is a standard limit for individual HTTP headers
 * in many web servers (like Apache and Nginx). It's enough for long tokens
 * or signatures but prevents "large header" attacks. */
#define HTTP_TRANSFER_CHUNKED_DEFAULT_MAX_TRAILER_FIELD_SIZE (8 * 1024)
/* Field Count (50): Most trailers only contain 1–5 fields. 50 is a safe
 * upper bound that prevents a "slow-read" or "infinite-header" attack where
 * a client sends thousands of small headers to keep a connection open
 * and consume CPU. */
#define HTTP_TRANSFER_CHUNKED_DEFAULT_MAX_TRAILER_FIELDS 50

struct http_transfer_param {
	const char *attribute;
	const char *value;
};
ARRAY_DEFINE_TYPE(http_transfer_param, struct http_transfer_param);

struct http_transfer_coding {
	const char *name;
	ARRAY_TYPE(http_transfer_param) parameters;

};
ARRAY_DEFINE_TYPE(http_transfer_coding, struct http_transfer_coding);


// FIXME: we currently lack a means to get error strings from the input stream

struct istream *
http_transfer_chunked_istream_create(struct istream *input, uoff_t max_size,
	const struct http_header_limits *hdr_limits);
struct ostream *
	http_transfer_chunked_ostream_create(struct ostream *output);

#endif

