/* Copyright (c) 2022 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream-private.h"

struct noop_istream {
	struct istream_private istream;

};

static ssize_t
i_stream_noop_read(struct istream_private *stream)
{
	i_stream_seek(stream->parent, stream->parent_start_offset +
		      stream->istream.v_offset);

	return i_stream_read_copy_from_parent(&stream->istream);
}

static void
i_stream_noop_seek(struct istream_private *stream,
		   uoff_t v_offset, bool mark ATTR_UNUSED)
{
	stream->istream.v_offset = v_offset;
	stream->skip = stream->pos = 0;
}

struct istream *
i_stream_create_noop(struct istream *input)
{
	struct noop_istream *nstream;

	nstream = i_new(struct noop_istream, 1);
	nstream->istream.max_buffer_size = input->real_stream->max_buffer_size;
	nstream->istream.stream_size_passthrough = TRUE;

	nstream->istream.read = i_stream_noop_read;
	nstream->istream.seek = i_stream_noop_seek;

	nstream->istream.istream.readable_fd = input->readable_fd;
	nstream->istream.istream.blocking = input->blocking;
	nstream->istream.istream.seekable = input->seekable;

	return i_stream_create(&nstream->istream, input,
			       i_stream_get_fd(input), 0);
}
