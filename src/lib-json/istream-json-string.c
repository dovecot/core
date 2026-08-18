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
	size_t pos;
	ssize_t ret;

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

	/* Expose the string stream's buffer directly. It is a normal
	   memarea-backed istream buffer, so snapshots of it keep the data
	   alive (see i_stream_json_string_snapshot()). The string stream
	   isn't our istream-parent, so the data consumed from this stream
	   needs to be skipped from it explicitly. */
	i_stream_skip(jstream->str_stream, stream->skip);
	stream->pos -= stream->skip;
	stream->skip = 0;

	stream->buffer = i_stream_get_data(jstream->str_stream, &pos);
	if (pos > stream->pos)
		ret = 0;
	else do {
		ret = i_stream_read_memarea(jstream->str_stream);
		if (jstream->str_stream->stream_errno != 0) {
			io_stream_set_error(&stream->iostream, "%s",
				i_stream_get_error(jstream->str_stream));
		}
		stream->istream.stream_errno =
			jstream->str_stream->stream_errno;
		stream->istream.eof = jstream->str_stream->eof;
		stream->buffer = i_stream_get_data(jstream->str_stream, &pos);
	} while (pos <= stream->pos && ret > 0);
	if (ret == -2)
		return -2;

	ret = pos > stream->pos ? (ssize_t)(pos - stream->pos) :
		(ret == 0 ? 0 : -1);
	stream->pos = pos;
	return ret;
}

static struct istream_snapshot *
i_stream_json_string_snapshot(struct istream_private *stream,
			      struct istream_snapshot *prev_snapshot)
{
	struct json_string_decode_istream *jstream =
		container_of(stream, struct json_string_decode_istream, istream);
	struct istream_private *str_stream;

	if (jstream->str_stream == NULL) {
		/* Nothing was read yet */
		i_assert(stream->skip == stream->pos);
		return prev_snapshot;
	}
	/* The buffer belongs to the string stream, so snapshot that one. */
	str_stream = jstream->str_stream->real_stream;
	return str_stream->snapshot(str_stream, prev_snapshot);
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
	jstream->istream.snapshot = i_stream_json_string_snapshot;

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
