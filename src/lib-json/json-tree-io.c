/* Copyright (c) 2017-2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "buffer.h"
#include "istream.h"
#include "ostream.h"

#include "json-istream.h"
#include "json-ostream.h"

#include "json-tree-io.h"

/*
 * Input
 */

int json_tree_read_data(const void *data, size_t size,
			enum json_parser_flags parser_flags,
			struct json_tree **jtree_r, const char **error_r)
{
	struct istream *input = i_stream_create_from_data(data, size);
	struct json_istream *jinput;
	int ret;

	*jtree_r = NULL;

	jinput = json_istream_create(input, JSON_ISTREAM_TYPE_NORMAL, NULL,
				     parser_flags);
	ret = json_istream_read_tree(jinput, jtree_r);
	i_assert(ret != 0);
	ret = json_istream_finish(&jinput, error_r);
	i_assert(ret != 0);

	if (ret < 0)
		json_tree_unref(jtree_r);

	i_stream_unref(&input);
	return (ret > 0 ? 0 : -1);
}

int json_tree_read_buffer(const buffer_t *buf,
			  enum json_parser_flags parser_flags,
			  struct json_tree **jtree_r, const char **error_r)
{
	return json_tree_read_data(buf->data, buf->used, parser_flags,
				   jtree_r, error_r);
}

int json_tree_read_cstr(const char *str, enum json_parser_flags parser_flags,
			struct json_tree **jtree_r, const char **error_r)
{
	return json_tree_read_data(str, strlen(str), parser_flags,
				   jtree_r, error_r);
}

/*
 * Output
 */

void json_tree_write_buffer(const struct json_tree *jtree, buffer_t *buf,
			    enum json_generator_flags gen_flags,
			    const struct json_format *format)

{
	struct json_ostream *joutput;

	joutput = json_ostream_create_str(buf, gen_flags);
	if (format != NULL)
		json_ostream_set_format(joutput, format);
	json_ostream_nwrite_tree(joutput, NULL, jtree);
	json_ostream_nfinish_destroy(&joutput);
}

const char *
json_tree_to_text(const struct json_tree *jtree,
		  enum json_generator_flags gen_flags,
		  const struct json_format *format)
{
	string_t *str = t_str_new(1024);

	json_tree_write_buffer(jtree, str, gen_flags, format);
	return str_c(str);
}

const char *json_tree_to_text_line(const struct json_tree *jtree)
{
	string_t *str = t_str_new(1024);

	json_tree_write_buffer(jtree, str, 0, NULL);
	return str_c(str);
}
