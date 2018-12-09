#ifndef JSON_PARSER_H
#define JSON_PARSER_H

#include "unichar.h"

enum json_type {
	/* { key: */
	JSON_TYPE_OBJECT_KEY,
	/* : { new object */
	JSON_TYPE_OBJECT,
	/* } (not returned for the root object) */
	JSON_TYPE_OBJECT_END,

	JSON_TYPE_ARRAY,
	JSON_TYPE_ARRAY_END,

	JSON_TYPE_STRING,
	JSON_TYPE_NUMBER,
	JSON_TYPE_TRUE,
	JSON_TYPE_FALSE,
	JSON_TYPE_NULL
};

enum json_parser_flags {
	/* By default we assume that the input is an object and parsing skips
	   the root level "{" and "}". If this flag is set, it's possible to
	   parse any other type of JSON values directly. */
	JSON_PARSER_NO_ROOT_OBJECT	= 0x01
};

/* Parse JSON tokens from the input stream. */
struct json_parser *json_parser_init(struct istream *input);
struct json_parser *json_parser_init_flags(struct istream *input,
					   enum json_parser_flags flags);

int json_parser_deinit(struct json_parser **parser, const char **error_r);

/* Parse the next token. Returns 1 if found, 0 if more input stream is
   non-blocking and needs more input, -1 if input stream is at EOF. */
int json_parse_next(struct json_parser *parser, enum json_type *type_r,
		    const char **value_r);
/* Skip the next object value. If it's an object, its members are also
   skipped. */
void json_parse_skip_next(struct json_parser *parser);
/* Skip the remainder of the value parsed earlier by json_parse_next(). */
void json_parse_skip(struct json_parser *parser);
/* Return the following string as input stream. Returns 1 if ok, 0 if
   input stream is non-blocking and needs more input, -1 if the next token
   isn't a string (call json_parse_next()). */
int json_parse_next_stream(struct json_parser *parser,
			   struct istream **input_r);

/* Append UCS4 to already opened JSON string. */
void json_append_escaped_ucs4(string_t *dest, unichar_t chr);
/* Append data to already opened JSON string. src should be valid UTF-8 data. */
void json_append_escaped(string_t *dest, const char *src);
/* Same as json_append_escaped(), but append non-\0 terminated input. */
void json_append_escaped_data(string_t *dest, const unsigned char *src, size_t size);
void ostream_escaped_json_format(string_t *dest, unsigned char src);

#endif
