#ifndef JSON_TREE_IO_H
#define JSON_TREE_IO_H

#include "json-tree.h"
#include "json-parser.h"
#include "json-generator.h"

/*
 * Input
 */

int json_tree_read_data(const void *data, size_t size,
			enum json_parser_flags parser_flags,
			struct json_tree **jtree_r, const char **error_r);

int json_tree_read_buffer(const buffer_t *buf,
			  enum json_parser_flags parser_flags,
			  struct json_tree **jtree_r, const char **error_r);
int json_tree_read_cstr(const char *str, enum json_parser_flags parser_flags,
			struct json_tree **jtree_r, const char **error_r);

/*
 * Output
 */

void json_tree_write_buffer(const struct json_tree *jtree, buffer_t *buf,
			    enum json_generator_flags gen_flags,
			    const struct json_format *format);

const char *
json_tree_to_text(const struct json_tree *jtree,
		  enum json_generator_flags gen_flags,
		  const struct json_format *format);
const char *json_tree_to_text_line(const struct json_tree *jtree);

#endif
