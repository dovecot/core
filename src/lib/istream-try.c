/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream-private.h"
#include "istream-try.h"

struct try_istream {
	struct istream_private istream;

	unsigned int try_input_count;
	struct istream **try_input;
	unsigned int try_idx;

	struct istream *final_input;
};

static void i_stream_unref_try_inputs(struct try_istream *tstream)
{
	for (unsigned int i = 0; i < tstream->try_input_count; i++) {
		if (tstream->try_input[i] != NULL)
			i_stream_unref(&tstream->try_input[i]);
	}
	tstream->try_input_count = 0;
	i_free(tstream->try_input);
}

static void i_stream_try_close(struct iostream_private *stream,
			       bool close_parent)
{
	struct try_istream *tstream = (struct try_istream *)stream;

	if (close_parent) {
		if (tstream->istream.parent != NULL)
			i_stream_close(tstream->istream.parent);
		for (unsigned int i = 0; i < tstream->try_input_count; i++) {
			if (tstream->try_input[i] != NULL)
				i_stream_close(tstream->try_input[i]);
		}
	}
	i_stream_unref_try_inputs(tstream);
}

static bool i_stream_try_is_buffer_full(struct istream *try_input)
{
	/* See if one of the parent istreams have their buffer full.
	   This is mainly intended to check with istream-tee whether its
	   parent is full. That means that the try_input has already seen
	   a full buffer of input, but it hasn't decided to return anything
	   yet. But it also hasn't failed, so we'll assume that the input is
	   correct for it and it simply needs a lot more input before it can
	   return anything (e.g. istream-bzlib). */
	while (try_input->real_stream->parent != NULL) {
		try_input = try_input->real_stream->parent;
		if (try_input->real_stream->pos == try_input->real_stream->buffer_size &&
		    try_input->real_stream->buffer_size > 0)
			return TRUE;
	}
	return FALSE;
}

static int i_stream_try_detect(struct try_istream *tstream)
{
	int ret;

	for (; tstream->try_idx < tstream->try_input_count; tstream->try_idx++) {
		struct istream *try_input =
			tstream->try_input[tstream->try_idx];

		ret = i_stream_read(try_input);
		if (ret == 0 && i_stream_try_is_buffer_full(try_input))
			ret = 1;
		if (ret > 0) {
			i_stream_init_parent(&tstream->istream, try_input);
			i_stream_unref_try_inputs(tstream);
			return 1;
		}
		if (ret == 0)
			return 0;
		if (try_input->stream_errno == 0) {
			/* empty file */
			tstream->istream.istream.eof = TRUE;
			return -1;
		}
		if (try_input->stream_errno != EINVAL) {
			tstream->istream.istream.stream_errno =
				try_input->stream_errno;
			io_stream_set_error(&tstream->istream.iostream,
				"Unexpected error while detecting stream format: %s",
				i_stream_get_error(try_input));
			return -1;
		}
	}

	/* All streams failed with EINVAL. */
	io_stream_set_error(&tstream->istream.iostream,
			    "Failed to detect stream format");
	tstream->istream.istream.stream_errno = EINVAL;
	return -1;
}

static ssize_t
i_stream_try_read(struct istream_private *stream)
{
	struct try_istream *tstream = (struct try_istream *)stream;
	int ret;

	if (stream->parent == NULL) {
		if ((ret = i_stream_try_detect(tstream)) <= 0)
			return ret;
	}

	i_stream_seek(stream->parent, stream->parent_start_offset +
		      stream->istream.v_offset);
	return i_stream_read_copy_from_parent(&stream->istream);
}

struct istream *istream_try_create(struct istream *const input[])
{
	struct try_istream *tstream;
	unsigned int count;
	size_t max_buffer_size = I_STREAM_MIN_SIZE;
	bool blocking = TRUE, seekable = TRUE;

	for (count = 0; input[count] != NULL; count++) {
		max_buffer_size = I_MAX(max_buffer_size,
					i_stream_get_max_buffer_size(input[count]));
		if (!input[count]->blocking)
			blocking = FALSE;
		if (!input[count]->seekable)
			seekable = FALSE;
		i_stream_ref(input[count]);
	}
	i_assert(count != 0);

	tstream = i_new(struct try_istream, 1);
	tstream->try_input_count = count;
	tstream->try_input = p_memdup(default_pool, input,
				      sizeof(*input) * count);

	tstream->istream.iostream.close = i_stream_try_close;

	tstream->istream.max_buffer_size = max_buffer_size;
	tstream->istream.read = i_stream_try_read;

	tstream->istream.istream.readable_fd = FALSE;
	tstream->istream.istream.blocking = blocking;
	tstream->istream.istream.seekable = seekable;
	return i_stream_create(&tstream->istream, NULL, -1);
}
