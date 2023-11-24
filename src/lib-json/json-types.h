#ifndef JSON_TYPES_H
#define JSON_TYPES_H

#include "istream.h"

struct json_tree;
struct json_tree_node;
struct json_tree_node_list;

struct json_data;
struct json_value;
struct json_node;

/*
 * Value
 */

/* The type of the JSON value */
enum json_type {
	/* no value */
	JSON_TYPE_NONE = 0,
	/* object */
	JSON_TYPE_OBJECT,
	/* array */
	JSON_TYPE_ARRAY,
	/* string */
	JSON_TYPE_STRING,
	/* number */
	JSON_TYPE_NUMBER,
	/* true */
	JSON_TYPE_TRUE,
	/* false */
	JSON_TYPE_FALSE,
	/* null */
	JSON_TYPE_NULL,
	/* JSON-text; either sub-tree or literal JSON text */
	JSON_TYPE_TEXT,
};

/* The content representation of the JSON value */
enum json_content_type {
	/* true, false, null */
	JSON_CONTENT_TYPE_NONE = 0,
	/* object, array */
	JSON_CONTENT_TYPE_LIST,
	/* literal/string/text */
	JSON_CONTENT_TYPE_STRING,
	/* data buffer (for string/text containing \u0000) */
	JSON_CONTENT_TYPE_DATA,
	/* data stream (for potentially very long string/text) */
	JSON_CONTENT_TYPE_STREAM,
	/* integer number */
	JSON_CONTENT_TYPE_INTEGER,
	/* sub-tree */
	JSON_CONTENT_TYPE_TREE,
};

struct json_data {
	/* data[size] == 0x00 */
	const unsigned char *data;
	size_t size;

	/* data contains 0x00 */
	bool contains_nul:1;
	/* data contains control character */
	bool contains_control:1;
};

struct json_value {
	enum json_content_type content_type;
	union {
		/* JSON_CONTENT_TYPE_LIST */
		struct json_tree_node_list *list; /* only used by trees */
		/* JSON_CONTENT_TYPE_STRING */
		const char *str;
		/* JSON_CONTENT_TYPE_DATA */
		struct json_data *data;
		/* JSON_CONTENT_TYPE_STREAM */
		struct istream *stream;
		/* JSON_CONTENT_TYPE_INTEGER */
		intmax_t intnum;
		/* JSON_CONTENT_TYPE_TREE */
		struct json_tree *tree;
	} content;
};

const char *json_type_get_name(enum json_type type);
const char *json_content_type_get_name(enum json_content_type ctype);

/* number */

static inline int
json_value_get_uintmax(const struct json_value *jvalue, uintmax_t *num_r)
{
	i_assert(jvalue->content_type == JSON_CONTENT_TYPE_INTEGER);
	if (jvalue->content.intnum < 0)
		return -1;
	*num_r = (uintmax_t)jvalue->content.intnum;
	return 0;
}

static inline int
json_value_get_intmax(const struct json_value *jvalue, intmax_t *num_r)
{
	i_assert(jvalue->content_type == JSON_CONTENT_TYPE_INTEGER);
	*num_r = jvalue->content.intnum;
	return 0;
}

#define JSON_VALUE_GET_U__TEMPLATE(name, type, uint_max)                \
static inline int                                                       \
name(const struct json_value *jvalue, type *num_r)                      \
{                                                                       \
	intmax_t l;                                                     \
	i_assert(jvalue->content_type == JSON_CONTENT_TYPE_INTEGER);    \
	l = jvalue->content.intnum;                                     \
	if (l < 0 || (uintmax_t)l > uint_max)                           \
		return -1;                                              \
	*num_r = (type)l;                                               \
	return 0;                                                       \
}

JSON_VALUE_GET_U__TEMPLATE(json_value_get_uint,
			   unsigned int, UINT_MAX)
JSON_VALUE_GET_U__TEMPLATE(json_value_get_ulong,
			   unsigned long, ULONG_MAX)
JSON_VALUE_GET_U__TEMPLATE(json_value_get_ullong,
			   unsigned long long, ULLONG_MAX)
JSON_VALUE_GET_U__TEMPLATE(json_value_get_uint32,
			   uint32_t, UINT32_MAX)
JSON_VALUE_GET_U__TEMPLATE(json_value_get_uint64,
			   uint64_t, UINT64_MAX)

#define JSON_VALUE_GET_S__TEMPLATE(name, type, int_min, int_max)        \
static inline int                                                       \
name(const struct json_value *jvalue, type *num_r)                      \
{                                                                       \
	intmax_t l;                                                     \
	i_assert(jvalue->content_type == JSON_CONTENT_TYPE_INTEGER);    \
	l = jvalue->content.intnum;                                     \
	if (l < int_min || l > int_max)                                 \
		return -1;                                              \
	*num_r = (type)l;                                               \
	return 0;                                                       \
}

JSON_VALUE_GET_S__TEMPLATE(json_value_get_int,
			   int, INT_MIN, INT_MAX)
JSON_VALUE_GET_S__TEMPLATE(json_value_get_long,
			   long, LONG_MIN, LONG_MAX)
JSON_VALUE_GET_S__TEMPLATE(json_value_get_llong,
			   long long, LLONG_MIN, LLONG_MAX)
JSON_VALUE_GET_S__TEMPLATE(json_value_get_int32,
			   int32_t, INT32_MIN, INT32_MAX)
JSON_VALUE_GET_S__TEMPLATE(json_value_get_int64,
			   int64_t, INT64_MIN, INT64_MAX)

/* string */

static inline ATTR_PURE const char *
json_value_get_str(const struct json_value *jvalue)
{
	i_assert(jvalue->content_type == JSON_CONTENT_TYPE_STRING);
	return jvalue->content.str;
}
static inline ATTR_PURE const char *
json_value_as_str(const struct json_value *jvalue)
{
	switch (jvalue->content_type) {
	case JSON_CONTENT_TYPE_STRING:
		break;
	case JSON_CONTENT_TYPE_INTEGER:
		return t_strdup_printf("%"PRIdMAX, jvalue->content.intnum);
	default:
		i_unreached();
	}
	return jvalue->content.str;
}
static inline ATTR_PURE const unsigned char *
json_value_get_data(const struct json_value *jvalue, size_t *size_r)
{
	switch (jvalue->content_type) {
	case JSON_CONTENT_TYPE_STRING:
		*size_r = strlen(jvalue->content.str);
		return (const unsigned char *)jvalue->content.str;
	case JSON_CONTENT_TYPE_DATA:
		*size_r = jvalue->content.data->size;
		return jvalue->content.data->data;
	default:
		break;
	}
	i_unreached();
}

static inline ATTR_PURE int
json_value_get_stream(const struct json_value *jvalue,
		       struct istream **stream_r)
{
	if (jvalue->content_type != JSON_CONTENT_TYPE_STREAM)
		return -1;
	*stream_r = jvalue->content.stream;
	i_stream_ref(*stream_r);
	return 0;
}

/*
 * Node
 */

struct json_node {
	/* object member name */
	const char *name;
	/* node type */
	enum json_type type;
	/* node value */
	struct json_value value;
};

static inline ATTR_PURE bool
json_node_is_none(const struct json_node *jnode)
{
	return (jnode->type == JSON_TYPE_NONE);
}

const char *json_node_get_label(const struct json_node *jnode);

/* object, array */

static inline ATTR_PURE bool
json_node_is_object(const struct json_node *jnode)
{
	return (jnode->type == JSON_TYPE_OBJECT &&
		jnode->value.content_type != JSON_CONTENT_TYPE_NONE);
}

static inline ATTR_PURE bool
json_node_is_array(const struct json_node *jnode)
{
	return (jnode->type == JSON_TYPE_ARRAY &&
		jnode->value.content_type != JSON_CONTENT_TYPE_NONE);
}

static inline ATTR_PURE bool
json_node_is_object_end(const struct json_node *jnode)
{
	return (jnode->type == JSON_TYPE_OBJECT &&
		jnode->value.content_type == JSON_CONTENT_TYPE_NONE);
}

static inline ATTR_PURE bool
json_node_is_array_end(const struct json_node *jnode)
{
	return (jnode->type == JSON_TYPE_ARRAY &&
		jnode->value.content_type == JSON_CONTENT_TYPE_NONE);
}

static inline ATTR_PURE bool
json_node_is_end(const struct json_node *jnode)
{
	switch (jnode->type) {
	case JSON_TYPE_OBJECT:
	case JSON_TYPE_ARRAY:
		return (jnode->value.content_type == JSON_CONTENT_TYPE_NONE);
	default:
		break;
	}
	return FALSE;
}

/* string */

static inline ATTR_PURE bool
json_node_is_string(const struct json_node *jnode)
{
	return (jnode->type == JSON_TYPE_STRING);
}

static inline ATTR_PURE const char *
json_node_get_str(const struct json_node *jnode)
{
	switch (jnode->type) {
	case JSON_TYPE_STRING:
	case JSON_TYPE_NUMBER:
	case JSON_TYPE_TEXT:
		break;
	case JSON_TYPE_TRUE:
		return "true";
	case JSON_TYPE_FALSE:
		return "false";
	case JSON_TYPE_NULL:
		return "null";
	default:
		i_unreached();
	}
	return json_value_get_str(&jnode->value);
}
static inline ATTR_PURE const char *
json_node_as_str(const struct json_node *jnode)
{
	switch (jnode->type) {
	case JSON_TYPE_STRING:
	case JSON_TYPE_NUMBER:
	case JSON_TYPE_TEXT:
		break;
	case JSON_TYPE_TRUE:
		return "true";
	case JSON_TYPE_FALSE:
		return "false";
	case JSON_TYPE_NULL:
		return "null";
	default:
		i_unreached();
	}
	return json_value_as_str(&jnode->value);
}

static inline ATTR_PURE const unsigned char *
json_node_get_data(const struct json_node *jnode, size_t *size_r)
{
	const char *literal;

	switch (jnode->type) {
	case JSON_TYPE_STRING:
	case JSON_TYPE_NUMBER:
	case JSON_TYPE_TEXT:
		break;
	case JSON_TYPE_TRUE:
		literal = "true";
		*size_r = strlen(literal);
		return (const unsigned char *)literal;
	case JSON_TYPE_FALSE:
		literal = "false";
		*size_r = strlen(literal);
		return (const unsigned char *)literal;
	case JSON_TYPE_NULL:
		literal = "null";
		*size_r = strlen(literal);
		return (const unsigned char *)literal;
	default:
		i_unreached();
	}
	return json_value_get_data(&jnode->value, size_r);
}

static inline int
json_node_get_stream(const struct json_node *jnode,
		      struct istream **stream_r)
{
	if (jnode->type != JSON_TYPE_STRING)
		return -1;

	return json_value_get_stream(&jnode->value, stream_r);
}

/* number */

static inline ATTR_PURE bool
json_node_is_number(const struct json_node *jnode)
{
	return (jnode->type == JSON_TYPE_NUMBER);
}

static inline int
json_node_get_intmax(const struct json_node *jnode, intmax_t *num_r)
{
	if (jnode->type != JSON_TYPE_NUMBER)
		return -1;
	if (jnode->value.content_type != JSON_CONTENT_TYPE_INTEGER)
		return -1;
	return json_value_get_intmax(&jnode->value, num_r);
}
static inline int
json_node_get_int(const struct json_node *jnode, int *num_r)
{
	if (jnode->type != JSON_TYPE_NUMBER)
		return -1;
	if (jnode->value.content_type != JSON_CONTENT_TYPE_INTEGER)
		return -1;
	return json_value_get_int(&jnode->value, num_r);
}
static inline int
json_node_get_long(const struct json_node *jnode, long *num_r)
{
	if (jnode->type != JSON_TYPE_NUMBER)
		return -1;
	if (jnode->value.content_type != JSON_CONTENT_TYPE_INTEGER)
		return -1;
	return json_value_get_long(&jnode->value, num_r);
}
static inline int
json_node_get_llong(const struct json_node *jnode, long long *num_r)
{
	if (jnode->type != JSON_TYPE_NUMBER)
		return -1;
	if (jnode->value.content_type != JSON_CONTENT_TYPE_INTEGER)
		return -1;
	return json_value_get_llong(&jnode->value, num_r);
}
static inline int
json_node_get_int32(const struct json_node *jnode, int32_t *num_r)
{
	if (jnode->type != JSON_TYPE_NUMBER)
		return -1;
	if (jnode->value.content_type != JSON_CONTENT_TYPE_INTEGER)
		return -1;
	return json_value_get_int32(&jnode->value, num_r);
}
static inline int
json_node_get_int64(const struct json_node *jnode, int64_t *num_r)
{
	if (jnode->type != JSON_TYPE_NUMBER)
		return -1;
	if (jnode->value.content_type != JSON_CONTENT_TYPE_INTEGER)
		return -1;
	return json_value_get_int64(&jnode->value, num_r);
}

static inline int
json_node_get_uintmax(const struct json_node *jnode, uintmax_t *num_r)
{
	if (jnode->type != JSON_TYPE_NUMBER)
		return -1;
	if (jnode->value.content_type != JSON_CONTENT_TYPE_INTEGER)
		return -1;
	return json_value_get_uintmax(&jnode->value, num_r);
}
static inline int
json_node_get_uint(const struct json_node *jnode, unsigned int *num_r)
{
	if (jnode->type != JSON_TYPE_NUMBER)
		return -1;
	if (jnode->value.content_type != JSON_CONTENT_TYPE_INTEGER)
		return -1;
	return json_value_get_uint(&jnode->value, num_r);
}
static inline int
json_node_get_ulong(const struct json_node *jnode, unsigned long *num_r)
{
	if (jnode->type != JSON_TYPE_NUMBER)
		return -1;
	if (jnode->value.content_type != JSON_CONTENT_TYPE_INTEGER)
		return -1;
	return json_value_get_ulong(&jnode->value, num_r);
}
static inline int
json_node_get_ullong(const struct json_node *jnode, unsigned long long *num_r)
{
	if (jnode->type != JSON_TYPE_NUMBER)
		return -1;
	if (jnode->value.content_type != JSON_CONTENT_TYPE_INTEGER)
		return -1;
	return json_value_get_ullong(&jnode->value, num_r);
}
static inline int
json_node_get_uint32(const struct json_node *jnode, uint32_t *num_r)
{
	if (jnode->type != JSON_TYPE_NUMBER)
		return -1;
	if (jnode->value.content_type != JSON_CONTENT_TYPE_INTEGER)
		return -1;
	return json_value_get_uint32(&jnode->value, num_r);
}
static inline int
json_node_get_uint64(const struct json_node *jnode, uint64_t *num_r)
{
	if (jnode->type != JSON_TYPE_NUMBER)
		return -1;
	if (jnode->value.content_type != JSON_CONTENT_TYPE_INTEGER)
		return -1;
	return json_value_get_uint64(&jnode->value, num_r);
}

/* true, false */

static inline ATTR_PURE bool
json_node_is_true(const struct json_node *jnode)
{
	return (jnode->type == JSON_TYPE_TRUE);
}

static inline ATTR_PURE bool
json_node_is_false(const struct json_node *jnode)
{
	return (jnode->type == JSON_TYPE_FALSE);
}

static inline ATTR_PURE bool
json_node_is_boolean(const struct json_node *jnode)
{
	switch (jnode->type) {
	case JSON_TYPE_TRUE:
	case JSON_TYPE_FALSE:
		return TRUE;
	default:
		break;
	}
	return FALSE;
}

static inline ATTR_PURE int
json_node_get_boolean(const struct json_node *jnode, bool *bool_r)
{
	switch (jnode->type) {
	case JSON_TYPE_TRUE:
		*bool_r = TRUE;
		return 0;
	case JSON_TYPE_FALSE:
		*bool_r = FALSE;
		return 0;
	default:
		break;
	}
	return -1;
}

/* null */

static inline ATTR_PURE bool
json_node_is_null(const struct json_node *jnode)
{
	return (jnode->type == JSON_TYPE_NULL);
}

/* utility */

static inline ATTR_PURE bool
json_node_is_singular(const struct json_node *jnode)
{
	switch (jnode->type) {
	case JSON_TYPE_OBJECT:
	case JSON_TYPE_ARRAY:
		return FALSE;
	default:
		break;
	}
	return TRUE;
}

/*
 * Limits
 */

// NOTE: There is currently no support for reading enormous object member names
//       incrementally. This is usually not needed, but it could sometimes be
//       nice to have.

#define JSON_DEFAULT_MAX_NAME_SIZE 1024
#define JSON_DEFAULT_MAX_STRING_SIZE 32*1024
#define JSON_DEFAULT_MAX_NESTING 32
#define JSON_DEFAULT_MAX_LIST_ITEMS 1024

struct json_limits {
	/* Maximum size of object member name */
	size_t max_name_size;
	/* Maximum length of a string */
	size_t max_string_size;
	/* Maximum depth of object/array nesting */
	unsigned int max_nesting;
	/* Maximum number of object/array items */
	unsigned int max_list_items;
};

/*
 * Format
 */

struct json_format {
	/* Number of indent characters (either TAB or SPACE) */
	unsigned int indent_chars;

	/* Indent character is TAB instead of SPACE */
	bool indent_tab:1;
	/* Insert whitespace at appropriate places around separators */
	bool whitespace:1;
	/* Insert newlines */
	bool new_line:1;
	/* Newlines are CRLF rather than the default LF */
	bool crlf:1;
};

#endif
