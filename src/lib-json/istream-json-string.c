/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "buffer.h"
#include "unichar.h"
#include "istream-private.h"
#include "json-parser.h"

#include "istream-json-string.h"

struct json_string_decode_istream {
	struct istream_private istream;

	struct json_parser *parser;
	struct istream *str_stream;
};

static void
json_string_istream_parse_value(void *context, void *parent_context ATTR_UNUSED,
				const char *name ATTR_UNUSED,
				enum json_type type,
				const struct json_value *value)
{
	struct json_string_decode_istream *jstream = context;

	i_assert(type == JSON_TYPE_STRING);

	i_assert(jstream->str_stream == NULL);
	i_assert(value->content_type == JSON_CONTENT_TYPE_STREAM);
	jstream->str_stream = value->content.stream;
	i_stream_ref(jstream->str_stream);
	i_stream_set_max_buffer_size(jstream->str_stream,
				     jstream->istream.max_buffer_size);
	json_parser_interrupt(jstream->parser);
	return;
}

static const struct json_parser_callbacks json_string_istream_parser_callbacks = {
	.parse_value = json_string_istream_parse_value,
};

static void i_stream_json_string_destroy(struct iostream_private *stream)
{
	struct json_string_decode_istream *jstream =
		container_of(stream, struct json_string_decode_istream,
			     istream.iostream);

	i_stream_free_buffer(&jstream->istream);
	i_stream_destroy(&jstream->str_stream);
	json_parser_deinit(&jstream->parser);
}

static ssize_t i_stream_json_string_read(struct istream_private *stream)
{
	struct json_string_decode_istream *jstream =
		container_of(stream, struct json_string_decode_istream, istream);
	const char *error;
	const unsigned char *data;
	size_t avail_size, size;
	ssize_t sret;
	int ret;

	/* Run the parser to obtain the string stream */
	if (jstream->str_stream == NULL) {
		bool at_end;

		ret = json_parse_more(jstream->parser, &at_end, &error);
		if (ret < 0) {
			io_stream_set_error(&stream->iostream, "%s", error);
			stream->istream.stream_errno = (at_end ? EPIPE : EINVAL);
			return -1;
		}
		if (ret > 0 && jstream->str_stream == NULL) {
			stream->istream.eof = TRUE;
			return -1;
		}
		if (ret == 0 && jstream->str_stream == NULL)
			return 0;

	}

	/* Read more from the string stream if nothing from it is buffered
	   yet. */
	if (i_stream_get_data_size(jstream->str_stream) == 0) {
		if (jstream->str_stream->eof) {
			/* String stream fully drained. */
			stream->istream.eof = TRUE;
			return -1;
		}
		sret = i_stream_read(jstream->str_stream);
		if (jstream->str_stream->stream_errno != 0) {
			io_stream_set_error(&stream->iostream, "%s",
				i_stream_get_error(jstream->str_stream));
		}
		stream->istream.stream_errno = jstream->str_stream->stream_errno;
		if (sret <= 0) {
			stream->istream.eof = jstream->str_stream->eof &&
				i_stream_get_data_size(jstream->str_stream) == 0;
			return sret;
		}
	}

	/* Copy the newly available bytes into our own buffer instead of
	   aliasing str_stream's buffer directly: str_stream's underlying
	   storage can be reallocated by a later read (it decodes into a
	   plain string_t via a plain realloc, outside the istream
	   memarea/snapshot machinery), which would leave a caller-held
	   pointer into our previously exposed buffer dangling. Copying here
	   makes our own buffer growth go through the normal
	   i_stream_try_alloc()/memarea path, so it is actually protected. */
	data = i_stream_get_data(jstream->str_stream, &size);
	i_assert(size > 0);
	if (!i_stream_try_alloc(stream, size, &avail_size))
		return -2;
	if (size > avail_size)
		size = avail_size;
	i_assert(size > 0);

	memcpy(stream->w_buffer + stream->pos, data, size);
	stream->pos += size;
	i_stream_skip(jstream->str_stream, size);
	return size;
}

static void
i_stream_json_string_seek(struct istream_private *stream, uoff_t v_offset,
			   bool mark)
{
	struct json_string_decode_istream *jstream =
		container_of(stream, struct json_string_decode_istream, istream);

	if (v_offset == stream->istream.v_offset)
		return;
	if (v_offset < stream->istream.v_offset) {
		/* Restart the underlying decoder (if it was even created
		   yet) and read forward from there instead. */
		if (jstream->str_stream != NULL) {
			i_stream_seek(jstream->str_stream, 0);
			if (jstream->str_stream->stream_errno != 0) {
				io_stream_set_error(
					&stream->iostream, "%s",
					i_stream_get_error(jstream->str_stream));
				stream->istream.stream_errno =
					jstream->str_stream->stream_errno;
				return;
			}
		}
		stream->skip = stream->pos = 0;
		stream->istream.v_offset = 0;
	}
	/* Read and discard until we reach v_offset. This also bootstraps
	   str_stream via our own .read() if it doesn't exist yet. */
	i_stream_default_seek_nonseekable(stream, v_offset, mark);
}

static void
i_stream_json_string_set_max_buffer_size(struct iostream_private *stream,
					 size_t max_size)
{
	struct json_string_decode_istream *jstream =
		container_of(stream, struct json_string_decode_istream,
			     istream.iostream);

	jstream->istream.max_buffer_size = max_size;
	if (jstream->str_stream != NULL)
		i_stream_set_max_buffer_size(jstream->str_stream, max_size);
}

struct istream *
i_stream_create_json_string_with_flags(struct istream *input,
				       enum json_parser_flags flags)
{
	struct json_string_decode_istream *jstream;

	jstream = i_new(struct json_string_decode_istream, 1);

	/* Create JSON parser and immediately configure it for string content
	   stream.  Only JSON_PARSER_FLAG_STRINGS_* bits from `flags' are
	   meaningful for a nested string-content parser; INPUT_IS_STRING_
	   CONTENT is always forced on regardless of what the caller passed. */
	jstream->parser = json_parser_init(
		input, NULL,
		(flags & JSON_PARSER_FLAG_STRINGS_ALLOW_NUL) |
			JSON_PARSER_FLAG_INPUT_IS_STRING_CONTENT,
		&json_string_istream_parser_callbacks, jstream);
	json_parser_enable_string_stream(jstream->parser, 0,
					 input->real_stream->max_buffer_size);

	jstream->istream.iostream.destroy = i_stream_json_string_destroy;
	jstream->istream.iostream.set_max_buffer_size =
		i_stream_json_string_set_max_buffer_size;
	jstream->istream.max_buffer_size = input->real_stream->max_buffer_size;
	jstream->istream.read = i_stream_json_string_read;
	jstream->istream.seek = i_stream_json_string_seek;

	jstream->istream.istream.readable_fd = FALSE;
	jstream->istream.istream.blocking = input->blocking;
	jstream->istream.istream.seekable = input->seekable;

	/* We read `input' only indirectly, through the nested parser and its
	   delivered str_stream - neither of which is our istream-parent -
	   so declare `input' as our hidden input instead of passing it as
	   the normal parent (matching json_string_stream_create()'s same
	   situation in json-parser.c). */
	jstream->istream.io_parent = input;

	return i_stream_create(&jstream->istream, NULL,
			       i_stream_get_fd(input),
			       ISTREAM_HIDDEN_INPUTS_DECLARED, 0);
}

struct istream *i_stream_create_json_string(struct istream *input)
{
	return i_stream_create_json_string_with_flags(input, 0);
}
