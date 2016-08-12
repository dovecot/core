#ifndef HTTP_HEADER_H
#define HTTP_HEADER_H

struct http_header;

struct http_header_limits {
	uoff_t max_size;
	uoff_t max_field_size;
	unsigned int max_fields;
};

struct http_header_field {
	const char *name;
	const char *value;
	size_t size;
};
ARRAY_DEFINE_TYPE(http_header_field, struct http_header_field);

static inline bool http_header_field_is(const struct http_header_field *hfield,
	const char *name)
{
	return (strcasecmp(hfield->name, name) == 0);
}

struct http_header *
http_header_create(pool_t pool, unsigned int init_count);

const struct http_header_field *
http_header_field_add(struct http_header *header,
	const char *name, const unsigned char *data, size_t size);
void http_header_field_delete(struct http_header *header, const char *name);

const ARRAY_TYPE(http_header_field) *
http_header_get_fields(const struct http_header *header) ATTR_PURE;

const struct http_header_field *
http_header_field_find(const struct http_header *header, const char *name)
	ATTR_PURE;
const char *
http_header_field_get(const struct http_header *header, const char *name)
	ATTR_PURE;
int http_header_field_find_unique(const struct http_header *header,
	const char *name, const struct http_header_field **hfield_r);

#endif
