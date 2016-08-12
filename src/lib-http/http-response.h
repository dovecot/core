#ifndef HTTP_RESPONSE_H
#define HTTP_RESPONSE_H

#include "array.h"

#include "http-header.h"

enum http_response_payload_type {
	HTTP_RESPONSE_PAYLOAD_TYPE_ALLOWED,
	HTTP_RESPONSE_PAYLOAD_TYPE_NOT_PRESENT,
	HTTP_RESPONSE_PAYLOAD_TYPE_ONLY_UNSUCCESSFUL
};

struct http_response {
	unsigned char version_major;
	unsigned char version_minor;

	unsigned int status;

	const char *reason;
	const char *location;

	time_t date, retry_after;
	const struct http_header *header;
	struct istream *payload;

	ARRAY_TYPE(const_string) connection_options;

	bool connection_close:1;
};

void
http_response_init(struct http_response *resp,
	unsigned int status, const char *reason);

static inline const struct http_header_field *
http_response_header_find(const struct http_response *resp, const char *name)
{
	if (resp->header == NULL)
		return NULL;
	return http_header_field_find(resp->header, name);
}

static inline const char *
http_response_header_get(const struct http_response *resp, const char *name)
{
	if (resp->header == NULL)
		return NULL;
	return http_header_field_get(resp->header, name);
}

static inline const ARRAY_TYPE(http_header_field) *
http_response_header_get_fields(const struct http_response *resp)
{
	if (resp->header == NULL)
		return NULL;
	return http_header_get_fields(resp->header);
}

bool http_response_has_connection_option(const struct http_response *resp,
	const char *option);
int http_response_get_payload_size(const struct http_response *resp,
	uoff_t *size_r);

#endif
