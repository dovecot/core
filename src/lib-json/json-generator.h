#ifndef JSON_GENERATOR_H
#define JSON_GENERATOR_H

#include "json-types.h"

// FIXME: add settings for formatting/indenting the output

struct json_generator;

enum json_generator_flags {
	/* Hide the root array or object node. So, the top-level '[' and ']' or
	   '{' and '}' will not be written to the output. Generating a nomal
	   value as root with this flag set will trigger an assertion failure.
	 */
	JSON_GENERATOR_FLAG_HIDE_ROOT = BIT(0),
};

struct json_generator *
json_generator_init(struct ostream *output, enum json_generator_flags flags);
struct json_generator *
json_generator_init_str(string_t *buf, enum json_generator_flags flags);

void json_generator_deinit(struct json_generator **_generator);

void json_generator_set_format(struct json_generator *generator,
				const struct json_format *format);

int json_generator_flush(struct json_generator *generator);

/* number */

int json_generate_number(struct json_generator *generator,
			 intmax_t number);
int json_generate_number_raw(struct json_generator *generator,
			     const char *number);

/* string */

void json_generate_string_open(struct json_generator *generator);
ssize_t json_generate_string_more(struct json_generator *generator,
				  const void *data, size_t size, bool last);
void json_generate_string_close(struct json_generator *generator);
int json_generate_string_write_close(struct json_generator *generator);

int json_generate_string_data(struct json_generator *generator,
			      const void *data, size_t size);
int json_generate_string(struct json_generator *generator, const char *str);

int json_generate_string_stream(struct json_generator *generator,
				struct istream *input);

/* null */

int json_generate_null(struct json_generator *generator);

/* false */

int json_generate_false(struct json_generator *generator);

/* true */

int json_generate_true(struct json_generator *generator);

/* object */

void json_generate_object_open(struct json_generator *generator);
int json_generate_object_member(struct json_generator *generator,
				const char *name);
int json_generate_object_close(struct json_generator *generator);

/* array */

void json_generate_array_open(struct json_generator *generator);
int json_generate_array_close(struct json_generator *generator);

/* JSON-text */

void json_generate_text_open(struct json_generator *generator);
ssize_t json_generate_text_more(struct json_generator *generator,
				const void *data, size_t size);
int json_generate_text_close(struct json_generator *generator);

int json_generate_text_data(struct json_generator *generator,
			    const void *data, size_t size);
int json_generate_text(struct json_generator *generator, const char *str);

int json_generate_text_stream(struct json_generator *generator,
			      struct istream *input);

/* <space> */

int json_generate_space_open(struct json_generator *generator);
void json_generate_space_close(struct json_generator *generator);

/* value */

int json_generate_value(struct json_generator *generator,
			enum json_type type, const struct json_value *value);

/*
 * String value stream
 */

struct ostream *
json_generate_string_open_stream(struct json_generator *generator);

/*
 * Simple string output
 */

void json_append_escaped(string_t *dest, const char *src);
void json_append_escaped_data(string_t *dest, const unsigned char *src,
			      size_t size);

#endif
