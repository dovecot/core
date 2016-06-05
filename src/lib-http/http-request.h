#ifndef HTTP_REQUEST_H
#define HTTP_REQUEST_H

#include "http-header.h"

struct http_url;

#define HTTP_REQUEST_DEFAULT_MAX_TARGET_LENGTH      (8 * 1024)
#define HTTP_REQUEST_DEFAULT_MAX_HEADER_SIZE        (200 * 1024)
#define HTTP_REQUEST_DEFAULT_MAX_HEADER_FIELD_SIZE  (8 * 1024)
#define HTTP_REQUEST_DEFAULT_MAX_HEADER_FIELDS      50
#define HTTP_REQUEST_DEFAULT_MAX_PAYLOAD_SIZE       (1 * 1024 * 1024)

struct http_request_limits {
	uoff_t max_target_length;
	uoff_t max_payload_size;

	struct http_header_limits header;
};

enum http_request_target_format {
	HTTP_REQUEST_TARGET_FORMAT_ORIGIN = 0,
	HTTP_REQUEST_TARGET_FORMAT_ABSOLUTE,
	HTTP_REQUEST_TARGET_FORMAT_AUTHORITY,
	HTTP_REQUEST_TARGET_FORMAT_ASTERISK
};

struct http_request_target {
	enum http_request_target_format format;
	struct http_url *url;
};

struct http_request {
	const char *method;

	const char *target_raw;
	struct http_request_target target;

	unsigned char version_major;
	unsigned char version_minor;

	time_t date;
	const struct http_header *header;
	struct istream *payload;

	ARRAY_TYPE(const_string) connection_options;

	bool connection_close:1;
	bool expect_100_continue:1;
};

static inline bool
http_request_method_is(const struct http_request *req, const char *method)
{
	if (req->method == NULL)
		return FALSE;

	return (strcmp(req->method, method) == 0);
}

static inline const struct http_header_field *
http_request_header_find(const struct http_request *req, const char *name)
{
	return http_header_field_find(req->header, name);
}

static inline const char *
http_request_header_get(const struct http_request *req, const char *name)
{
	return http_header_field_get(req->header, name);
}

static inline const ARRAY_TYPE(http_header_field) *
http_request_header_get_fields(const struct http_request *req)
{
	return http_header_get_fields(req->header);
}

bool http_request_has_connection_option(const struct http_request *req,
	const char *option);
int http_request_get_payload_size(const struct http_request *req,
	uoff_t *size_r);

#endif
