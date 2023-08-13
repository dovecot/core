#ifndef JSON_TEXT_H
#define JSON_TEXT_H

#include "json-parser.h"
#include "json-generator.h"

int json_text_format_data(const void *data, size_t size,
			  enum json_parser_flags parser_flags,
			  const struct json_limits *limits,
			  const struct json_format *format,
			  buffer_t *outbuf, const char **error_r);
int json_text_format_buffer(const buffer_t *buf,
			    enum json_parser_flags parser_flags,
			    const struct json_limits *limits,
			    const struct json_format *format,
			    buffer_t *outbuf, const char **error_r);
int json_text_format_cstr(const char *str, enum json_parser_flags parser_flags,
			  const struct json_limits *limits,
			  const struct json_format *format,
			  buffer_t *outbuf, const char **error_r);

#endif
