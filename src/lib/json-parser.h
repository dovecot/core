#ifndef JSON_PARSER_H
#define JSON_PARSER_H

enum json_type {
	/* { key: */
	JSON_TYPE_OBJECT_KEY,
	/* : { new object */
	JSON_TYPE_OBJECT,
	/* } (not returned for the root object) */
	JSON_TYPE_OBJECT_END,

	JSON_TYPE_STRING,
	JSON_TYPE_NUMBER,
	JSON_TYPE_TRUE,
	JSON_TYPE_FALSE,
	JSON_TYPE_NULL
};

/* Parse JSON tokens from the input stream. Currently arrays aren't
   supported. */
struct json_parser *json_parser_init(struct istream *input);
int json_parser_deinit(struct json_parser **parser, const char **error_r);

/* Parse the next token. Returns 1 if found, 0 if more input stream is
   non-blocking and needs more input, -1 if input stream is at EOF. */
int json_parse_next(struct json_parser *parser, enum json_type *type_r,
		    const char **value_r);

/* Return the following string as input stream. Returns 1 if ok, 0 if
   input stream is non-blocking and needs more input, -1 if the next token
   isn't a string (call json_parse_next()). */
int json_parse_next_stream(struct json_parser *parser,
			   struct istream **input_r);

#endif
