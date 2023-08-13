/* Copyright (c) 2017-2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "istream.h"
#include "ostream.h"

#include "json-istream.h"
#include "json-ostream.h"
#include "json-text.h"

int json_text_format_data(const void *data, size_t size,
			  enum json_parser_flags parser_flags,
			  const struct json_limits *limits,
			  const struct json_format *format,
			  buffer_t *outbuf, const char **error_r)
{
	struct istream *input;
	struct ostream *output;
	struct json_istream *jinput;
	struct json_ostream *joutput;
	struct json_node jnode;
	int ret;

	*error_r = NULL;

	parser_flags |= JSON_PARSER_FLAG_NUMBERS_AS_STRING;

	input = i_stream_create_from_data(data, size);

	output = o_stream_create_buffer(outbuf);
	o_stream_set_no_error_handling(output, TRUE);

	jinput = json_istream_create(input, JSON_ISTREAM_TYPE_NORMAL, limits,
				      parser_flags);
	joutput = json_ostream_create(output, 0);
	if (format != NULL)
		json_ostream_set_format(joutput, format);

	i_zero(&jnode);
	for (;;) {
		ret = json_istream_walk_stream(jinput, 16 * IO_BLOCK_SIZE,
						IO_BLOCK_SIZE, NULL, &jnode);
		i_assert(ret != 0);
		if (ret < 0)
			break;
		json_ostream_nwrite_node(joutput, &jnode);
	}
	ret = json_ostream_nfinish(joutput);
	if (ret < 0)
		*error_r = json_ostream_get_error(joutput);
	json_ostream_destroy(&joutput);

	if (ret < 0)
		json_istream_destroy(&jinput);
	else
		ret = json_istream_finish(&jinput, error_r);

	i_stream_destroy(&input);
	o_stream_destroy(&output);
	return ret;
}

int json_text_format_buffer(const buffer_t *buf,
			    enum json_parser_flags parser_flags,
			    const struct json_limits *limits,
			    const struct json_format *format,
			    buffer_t *outbuf, const char **error_r)
{
	return json_text_format_data(buf->data, buf->used, parser_flags,
				     limits, format, outbuf, error_r);
}

int json_text_format_cstr(const char *str, enum json_parser_flags parser_flags,
			  const struct json_limits *limits,
			  const struct json_format *format,
			  buffer_t *outbuf, const char **error_r)
{
	return json_text_format_data(str, strlen(str), parser_flags,
				     limits, format, outbuf, error_r);
}
