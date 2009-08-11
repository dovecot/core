/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "ostream-internal.h"

struct buffer_ostream {
	struct ostream_private ostream;
	buffer_t *buf;
	size_t max_buffer_size;
};

static void
o_stream_buffer_set_max_buffer_size(struct iostream_private *stream,
				 size_t max_size)
{
	struct buffer_ostream *bstream = (struct buffer_ostream *)stream;

	bstream->max_buffer_size = max_size;
}

static void o_stream_buffer_cork(struct ostream_private *stream ATTR_UNUSED,
				 bool set ATTR_UNUSED)
{
}

static int o_stream_buffer_flush(struct ostream_private *stream ATTR_UNUSED)
{
	return 1;
}

static void
o_stream_buffer_flush_pending(struct ostream_private *stream ATTR_UNUSED,
			      bool set ATTR_UNUSED)
{
}

static size_t
o_stream_buffer_get_used_size(const struct ostream_private *stream ATTR_UNUSED)
{
	return 0;
}

static int o_stream_buffer_seek(struct ostream_private *stream, uoff_t offset)
{
	stream->ostream.offset = offset;
	return 1;
}

static int
o_stream_buffer_write_at(struct ostream_private *stream,
			 const void *data, size_t size, uoff_t offset)
{
	struct buffer_ostream *bstream = (struct buffer_ostream *)stream;

	buffer_write(bstream->buf, offset, data, size);
	return 0;
}

static ssize_t
o_stream_buffer_sendv(struct ostream_private *stream,
		      const struct const_iovec *iov, unsigned int iov_count)
{
	struct buffer_ostream *bstream = (struct buffer_ostream *)stream;
	size_t left, n;
	ssize_t ret = 0;
	unsigned int i;

	for (i = 0; i < iov_count; i++) {
		left = bstream->max_buffer_size - stream->ostream.offset;
		n = I_MIN(left, iov[i].iov_len);
		buffer_write(bstream->buf, stream->ostream.offset,
			     iov[i].iov_base, n);
		ret += n;
		if (n != iov[i].iov_len)
			break;
	}
	stream->ostream.offset += ret;
	return ret;
}

static off_t o_stream_buffer_send_istream(struct ostream_private *outstream,
					  struct istream *instream)
{
	return io_stream_copy(&outstream->ostream, instream, 1024);
}

struct ostream *o_stream_create_buffer(buffer_t *buf)
{
	struct buffer_ostream *bstream;

	bstream = i_new(struct buffer_ostream, 1);
	bstream->ostream.iostream.set_max_buffer_size =
		o_stream_buffer_set_max_buffer_size;

	bstream->ostream.cork = o_stream_buffer_cork;
	bstream->ostream.flush = o_stream_buffer_flush;
	bstream->ostream.flush_pending = o_stream_buffer_flush_pending;
	bstream->ostream.get_used_size = o_stream_buffer_get_used_size;
	bstream->ostream.seek = o_stream_buffer_seek;
	bstream->ostream.sendv = o_stream_buffer_sendv;
	bstream->ostream.write_at = o_stream_buffer_write_at;
	bstream->ostream.send_istream = o_stream_buffer_send_istream;

	bstream->buf = buf;
	bstream->max_buffer_size = (size_t)-1;
	return o_stream_create(&bstream->ostream);
}
