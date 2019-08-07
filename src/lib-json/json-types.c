/* Copyright (c) 2017-2023 Dovecot authors, see the included COPYING file */

#include "lib.h"

#include "json-types.h"

static const char *json_type_names[] = {
	[JSON_TYPE_NONE] = "<unassigned>",
	[JSON_TYPE_OBJECT] = "object",
	[JSON_TYPE_ARRAY] = "array",
	[JSON_TYPE_STRING] = "string",
	[JSON_TYPE_NUMBER] = "number",
	[JSON_TYPE_TRUE] = "true",
	[JSON_TYPE_FALSE] = "false",
	[JSON_TYPE_NULL] = "null",
	[JSON_TYPE_TEXT] = "<JSON-text>",
};
static_assert_array_size(json_type_names, JSON_TYPE_TEXT + 1);

static const char *json_content_type_names[] = {
	[JSON_CONTENT_TYPE_NONE] = "<NONE>",
	[JSON_CONTENT_TYPE_LIST] = "<LIST>",
	[JSON_CONTENT_TYPE_STRING] = "<STRING>",
	[JSON_CONTENT_TYPE_DATA] = "<DATA>",
	[JSON_CONTENT_TYPE_STREAM] = "<STREAM>",
	[JSON_CONTENT_TYPE_INTEGER] = "<INTEGER>",
	[JSON_CONTENT_TYPE_TREE] = "<TREE>",
};
static_assert_array_size(json_content_type_names,
			 JSON_CONTENT_TYPE_TREE + 1);

const char *json_type_get_name(enum json_type type)
{
	i_assert(type <= JSON_TYPE_TEXT);
	return json_type_names[type];
}

const char *json_content_type_get_name(enum json_content_type ctype)
{
	i_assert(ctype <= JSON_CONTENT_TYPE_TREE);
	return json_content_type_names[ctype];
}

const char *json_node_get_label(const struct json_node *jnode)
{
	switch (jnode->type) {
	case JSON_TYPE_NONE:
		return "<unassigned>";
	case JSON_TYPE_OBJECT:
		switch (jnode->value.content_type) {
		case JSON_CONTENT_TYPE_NONE:
			return "object end";
		case JSON_CONTENT_TYPE_LIST:
			return "object";
		default:
			break;
		}
		break;
	case JSON_TYPE_ARRAY:
		switch (jnode->value.content_type) {
		case JSON_CONTENT_TYPE_NONE:
			return "array end";
		case JSON_CONTENT_TYPE_LIST:
			return "array";
		default:
			break;
		}
		break;
	case JSON_TYPE_STRING:
	case JSON_TYPE_NUMBER:
	case JSON_TYPE_TEXT:
		return t_strconcat(
			json_type_get_name(jnode->type), " (",
			json_content_type_get_name(jnode->value.content_type),
			")", NULL);
	case JSON_TYPE_TRUE:
		return "true";
	case JSON_TYPE_FALSE:
		return "false";
	case JSON_TYPE_NULL:
		return "null";
	}
	i_unreached();
}
