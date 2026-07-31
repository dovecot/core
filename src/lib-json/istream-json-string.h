#ifndef ISTREAM_JSON_STRING_H
#define ISTREAM_JSON_STRING_H

#include "json-parser.h"

/* Create a filter istream that decodes JSON string escape sequences.
 * The input must contain the raw JSON string bytes (without surrounding
 * quotes, as they appear between '"' chars in a JSON text).  The output
 * stream yields the fully decoded byte sequence. */
struct istream *i_stream_create_json_string(struct istream *input);

/* Like i_stream_create_json_string(), but forwards the given string-content
 * validation flags (e.g. JSON_PARSER_FLAG_STRINGS_ALLOW_NUL) to the nested
 * parser - only JSON_PARSER_FLAG_STRINGS_* bits are meaningful here.  Used
 * when this stream decodes a string that was already accepted by an outer
 * parser configured with those flags, so the nested parser doesn't
 * re-validate the content more strictly than the outer parser did. */
struct istream *
i_stream_create_json_string_with_flags(struct istream *input,
				       enum json_parser_flags flags);

#endif
