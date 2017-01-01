/* Copyright (c) 2013-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"

#include "http-header.h"

struct http_header {
	ARRAY_TYPE(http_header_field) fields;
	/* FIXME: ARRAY(struct http_header_field *) *btree; */
};

struct http_header *
http_header_create(pool_t pool, unsigned int init_count)
{
	struct http_header *header;

	header = p_new(pool, struct http_header, 1);
	p_array_init(&header->fields, pool, init_count);

	return header;
}

const struct http_header_field *
http_header_field_add(struct http_header *header,
	const char *name, const unsigned char *data, size_t size)
{
	struct http_header_field *hfield;
	pool_t pool = array_get_pool(&header->fields);
	void *value;

	hfield = array_append_space(&header->fields);
	hfield->name = p_strdup(pool, name);
	hfield->size = size;

	value = p_malloc(pool, size+1);
	memcpy(value, data, size);
	hfield->value = (const char *)value;

	return hfield;
}

void http_header_field_delete(struct http_header *header, const char *name)
{
	ARRAY_TYPE(http_header_field) *hfields = &header->fields;
	const struct http_header_field *hfield;

	array_foreach(hfields, hfield) {
		if (http_header_field_is(hfield, name)) {
			array_delete(hfields, array_foreach_idx(hfields, hfield), 1);
		}
	}
}

const ARRAY_TYPE(http_header_field) *
http_header_get_fields(const struct http_header *header)
{
	return &header->fields;
}

const struct http_header_field *
http_header_field_find(const struct http_header *header, const char *name)
{
	const struct http_header_field *hfield;

	array_foreach(&header->fields, hfield) {
		if (http_header_field_is(hfield, name))
			return hfield;
	}

	return NULL;
}

const char *
http_header_field_get(const struct http_header *header, const char *name)
{
	const struct http_header_field *hfield =
		http_header_field_find(header, name);
	return (hfield == NULL ? NULL : hfield->value);
}

int http_header_field_find_unique(const struct http_header *header,
	const char *name, const struct http_header_field **hfield_r)
{
	const struct http_header_field *hfield, *hfield_found = NULL;

	array_foreach(&header->fields, hfield) {
		if (http_header_field_is(hfield, name)) {
			if (hfield_found != NULL)
				return -1;
			hfield_found = hfield;
		}
	}

	*hfield_r = hfield_found;
	return (hfield_found == NULL ? 0 : 1);
}

