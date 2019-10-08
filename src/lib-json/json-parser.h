#ifndef JSON_PARSER_H
#define JSON_PARSER_H

#include "json-types.h"

// FIXME: don't bother recording values if we're only validating.

/*
 * JSON parser
 */

struct json_parser;
struct json_parser_state;

enum json_parser_flags {
	/* Strictly adhere to RFC 7159 */
	JSON_PARSER_FLAG_STRICT = BIT(0),
	/* Allow the \0 character in string values */
	JSON_PARSER_FLAG_STRINGS_ALLOW_NUL = BIT(1),
	/* Return all string values in a data buffer. Normally, this is
	   only done for strings containing \0 characters. */
	JSON_PARSER_FLAG_STRINGS_AS_DATA = BIT(2),
	/* Return number values as a string (by default, numbers are truncated
	   to an integer).
	 */
	JSON_PARSER_FLAG_NUMBERS_AS_STRING = BIT(3),
	/* Allow Byte Order Mark at beginning of input */
	JSON_PARSER_FLAG_ALLOW_BOM = BIT(4)
};

struct json_parser_callbacks {
	/* The `context' parameter is always the context value that was
	   originally passed to json_parser_init(). The `parent_context' is
	   always the context of the array/object the parsed value is nested
	   within. The `name' parameter is the object member name for this field
	   if the surrounding syntax is an object. */

	/* Called when the parser encounters the opening of an array or object
	   (as indicated by the `object' parameter. The list_context_r return
	   parameter can be used to set the context for this object/array,
	   making it available as `parent_context' to the contained values once
	   parsed.
	 */
	void (*parse_list_open)(void *context, void *parent_context,
				const char *name, bool object,
				void **list_context_r);
	/* Called when the parser encounters the closing of an array or object
	   (as indicated by the `object' parameter.
	 */
	void (*parse_list_close)(void *context, void *parent_context,
				 bool object);

	/* (optional) Called when the parser parses an object member name. This
	   allows a preview on the member name, before its value is fully
	   parsed.
	 */
	void (*parse_object_member)(void *context, void *parent_context,
				    const char *name);
	/* Called when the parser parses a value that is not an object or array.
	   The type and content of the value are provided.
	 */
	void (*parse_value)(void *context, void *parent_context,
			    const char *name, enum json_type type,
			    const struct json_value *value);
};

struct json_parser_location {
	/* Octet offset in the input stream relative to the position at the
	   creation of the parser */
	uoff_t offset;
	/* The current line number */
	uoff_t line;
	/* The line number for the start of the current value */
	uoff_t value_line;
	/* Unicode character (codepoint!) offset in the current line */
	uoff_t column;
};

struct json_parser *
json_parser_init(struct istream *input, const struct json_limits *limits,
		 enum json_parser_flags flags,
		 const struct json_parser_callbacks *callbacks,
		 void *context);
void json_parser_deinit(struct json_parser **_parser);

/* Report a parse error (from within a callback). */
void ATTR_FORMAT(2, 3)
json_parser_error(struct json_parser *parser, const char *format, ...);
/* Interrupt parser and return from json_parse_more(). This function can
   only be called from a parse callback. Until json_parse_more() is called
   again, any values (strings,buffers) passed in the callback remain valid.
 */
void json_parser_interrupt(struct json_parser *parser);

/* Returns -1 on error, 0 if parser is interrupted or needs more data,
   or 1 if the complete JSON text is parsed. */
int json_parse_more(struct json_parser *parser, const char **error_r);

/* Get the current location of the parser */
void json_parser_get_location(struct json_parser *parser,
			      struct json_parser_location *loc_r);

/* Enable parsing strings as a stream if the length of the string equals or
   exceeds `threshold' octets. This disables the normal string size limit. The
   stream will buffer at most `max_buffer_size' bytes. */
void json_parser_enable_string_stream(struct json_parser *parser,
				      size_t threshold, size_t max_buffer_size);
/* Disable parsing strings as a stream. */
void json_parser_disable_string_stream(struct json_parser *parser);

#endif
