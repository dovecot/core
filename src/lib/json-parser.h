#ifndef JSON_PARSER_H
#define JSON_PARSER_H

enum json_type {
	JSON_TYPE_OBJECT_KEY,
	JSON_TYPE_STRING,
	JSON_TYPE_NUMBER,
	JSON_TYPE_TRUE,
	JSON_TYPE_FALSE,
	JSON_TYPE_NULL
};

/* A really simple JSON parser, which for now only needs to be able to parse
   a single { key: value, .. } object. */
struct json_parser *
json_parser_init(const unsigned char *data, unsigned int len);
int json_parser_deinit(struct json_parser **parser, const char **error_r);

bool json_parse_next(struct json_parser *parser, enum json_type *type_r,
		     const char **value_r);

#endif
