/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "istream-internal.h"

struct limit_istream {
	struct _istream istream;

	struct istream *input;
	uoff_t v_start_offset, v_size;
};

static void _close(struct _iostream *stream __attr_unused__)
{
}

static void _destroy(struct _iostream *stream)
{
	struct limit_istream *lstream = (struct limit_istream *) stream;

	/* get to same position in parent stream */
	i_stream_seek(lstream->input, lstream->v_start_offset +
		      lstream->istream.istream.v_offset);
	i_stream_unref(lstream->input);
}

static void _set_max_buffer_size(struct _iostream *stream, size_t max_size)
{
	struct limit_istream *lstream = (struct limit_istream *) stream;

	i_stream_set_max_buffer_size(lstream->input, max_size);
}

static ssize_t _read(struct _istream *stream)
{
	struct limit_istream *lstream = (struct limit_istream *) stream;
	uoff_t left;
	ssize_t ret;
	size_t pos;

	if (stream->istream.v_offset +
	    (stream->pos - stream->skip) >= lstream->v_size)
		return -1;

	if (lstream->input->v_offset !=
	    lstream->v_start_offset + stream->istream.v_offset) {
		i_stream_seek(lstream->input,
			      lstream->v_start_offset +
			      stream->istream.v_offset);
	}

	stream->buffer = i_stream_get_data(lstream->input, &pos);
	if (pos <= stream->pos) {
		if (i_stream_read(lstream->input) == -2) {
			if (stream->skip == 0)
				return -2;
		}
		stream->istream.eof = lstream->input->eof;
		stream->buffer = i_stream_get_data(lstream->input, &pos);
	}

	stream->pos -= stream->skip;
	stream->skip = 0;

	if (lstream->v_size != (uoff_t)-1) {
		left = lstream->v_size - stream->istream.v_offset;
		if (pos > left)
			pos = left;
	}

	ret = pos <= stream->pos ? -1 :
		(ssize_t) (pos - stream->pos);
	stream->pos = pos;
	return ret;
}

static void _seek(struct _istream *stream, uoff_t v_offset)
{
	stream->istream.stream_errno = 0;
	stream->istream.v_offset = v_offset;
	stream->skip = stream->pos = 0;
}

static uoff_t _get_size(struct _istream *stream)
{
	struct limit_istream *lstream = (struct limit_istream *) stream;

	return lstream->v_size != (uoff_t)-1 ? lstream->v_size :
		i_stream_get_size(lstream->input);
}

struct istream *i_stream_create_limit(pool_t pool, struct istream *input,
				      uoff_t v_start_offset, uoff_t v_size)
{
	struct limit_istream *lstream;

	i_stream_ref(input);

	lstream = p_new(pool, struct limit_istream, 1);
	lstream->input = input;
	lstream->v_start_offset = v_start_offset;
	lstream->v_size = v_size;

	lstream->istream.istream.v_offset =
		input->v_offset < v_start_offset ? 0 :
		input->v_offset - v_start_offset > v_size ? v_size :
		input->v_offset - v_start_offset;

	lstream->istream.iostream.close = _close;
	lstream->istream.iostream.destroy = _destroy;
	lstream->istream.iostream.set_max_buffer_size = _set_max_buffer_size;

	lstream->istream.read = _read;
	lstream->istream.seek = _seek;
	lstream->istream.get_size = _get_size;

	return _i_stream_create(&lstream->istream, pool, i_stream_get_fd(input),
				input->real_stream->abs_start_offset +
				v_start_offset);
}
