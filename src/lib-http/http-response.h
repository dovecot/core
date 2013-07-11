#ifndef HTTP_RESPONSE_H
#define HTTP_RESPONSE_H

struct http_response_header {
	const char *key;
	const char *value;
	size_t size;
};
ARRAY_DEFINE_TYPE(http_response_header, struct http_response_header);

struct http_response {
	unsigned char version_major;
	unsigned char version_minor;

	unsigned int status;

	const char *reason;
	const char *location;

	time_t date;
	struct istream *payload;

	ARRAY_TYPE(http_response_header) headers;

	unsigned int connection_close:1;
};

#endif
