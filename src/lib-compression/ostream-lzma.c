/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"

#ifdef HAVE_LZMA

#include "ostream-private.h"
#include "ostream-zlib.h"
#include <lzma.h>

#define CHUNK_SIZE (1024*64)

struct lzma_ostream {
	struct ostream_private ostream;
	lzma_stream strm;

	unsigned char outbuf[CHUNK_SIZE];
	unsigned int outbuf_offset, outbuf_used;

	bool flushed:1;
};

static void o_stream_lzma_close(struct iostream_private *stream,
				bool close_parent)
{
	struct lzma_ostream *zstream = (struct lzma_ostream *)stream;

	lzma_end(&zstream->strm);
	if (close_parent)
		o_stream_close(zstream->ostream.parent);
}

static int o_stream_zlib_send_outbuf(struct lzma_ostream *zstream)
{
	ssize_t ret;
	size_t size;

	if (zstream->outbuf_used == 0)
		return 1;

	size = zstream->outbuf_used - zstream->outbuf_offset;
	i_assert(size > 0);
	ret = o_stream_send(zstream->ostream.parent,
			    zstream->outbuf + zstream->outbuf_offset, size);
	if (ret < 0) {
		o_stream_copy_error_from_parent(&zstream->ostream);
		return -1;
	}
	if ((size_t)ret != size) {
		zstream->outbuf_offset += ret;
		return 0;
	}
	zstream->outbuf_offset = 0;
	zstream->outbuf_used = 0;
	return 1;
}

static ssize_t
o_stream_lzma_send_chunk(struct lzma_ostream *zstream,
			  const void *data, size_t size)
{
	lzma_stream *zs = &zstream->strm;
	int ret;

	i_assert(zstream->outbuf_used == 0);

	zs->next_in = (void *)data;
	zs->avail_in = size;
	while (zs->avail_in > 0) {
		if (zs->avail_out == 0) {
			/* previous block was compressed. send it and start
			   compression for a new block. */
			zs->next_out = zstream->outbuf;
			zs->avail_out = sizeof(zstream->outbuf);

			zstream->outbuf_used = sizeof(zstream->outbuf);
			if ((ret = o_stream_zlib_send_outbuf(zstream)) < 0)
				return -1;
			if (ret == 0) {
				/* parent stream's buffer full */
				break;
			}
		}

		ret = lzma_code(zs, LZMA_RUN);
		switch (ret) {
		case LZMA_OK:
			break;
		case LZMA_MEM_ERROR:
			i_fatal_status(FATAL_OUTOFMEM,
				       "lzma.write(%s): Out of memory",
				       o_stream_get_name(&zstream->ostream.ostream));
		default:
			i_panic("lzma.write(%s) failed with unexpected code %d",
				o_stream_get_name(&zstream->ostream.ostream), ret);
		}
	}
	size -= zs->avail_in;

	zstream->flushed = FALSE;
	return size;
}

static int o_stream_lzma_send_flush(struct lzma_ostream *zstream)
{
	lzma_stream *zs = &zstream->strm;
	size_t len;
	bool done = FALSE;
	int ret;

	i_assert(zs->avail_in == 0);

	if (zstream->flushed)
		return 0;

	if ((ret = o_stream_flush_parent_if_needed(&zstream->ostream)) <= 0)
		return ret;
	if ((ret = o_stream_zlib_send_outbuf(zstream)) <= 0)
		return ret;

	i_assert(zstream->outbuf_used == 0);
	do {
		ret = lzma_code(zs, LZMA_FINISH);
		switch (ret) {
		case LZMA_OK:
			break;
		case LZMA_STREAM_END:
			done = TRUE;
			break;
		case LZMA_MEM_ERROR:
			i_fatal_status(FATAL_OUTOFMEM,
				       "lzma.write(%s): Out of memory",
				       o_stream_get_name(&zstream->ostream.ostream));
		default:
			i_panic("lzma.write(%s) flush failed with unexpected code %d",
				o_stream_get_name(&zstream->ostream.ostream), ret);
		}
		if (zs->avail_out == 0 || done) {
			len = sizeof(zstream->outbuf) - zs->avail_out;
			zs->next_out = zstream->outbuf;
			zs->avail_out = sizeof(zstream->outbuf);

			zstream->outbuf_used = len;
			if ((ret = o_stream_zlib_send_outbuf(zstream)) <= 0)
				return ret;
		}
	} while (!done);

	zstream->flushed = TRUE;
	return 0;
}

static int o_stream_lzma_flush(struct ostream_private *stream)
{
	struct lzma_ostream *zstream = (struct lzma_ostream *)stream;

	if (o_stream_lzma_send_flush(zstream) < 0)
		return -1;

	return o_stream_flush_parent(stream);
}

static size_t
o_stream_lzma_get_buffer_used_size(const struct ostream_private *stream)
{
	const struct lzma_ostream *zstream =
		(const struct lzma_ostream *)stream;

	/* outbuf has already compressed data that we're trying to send to the
	   parent stream. We're not including lzma's internal compression
	   buffer size. */
	return (zstream->outbuf_used - zstream->outbuf_offset) +
		o_stream_get_buffer_used_size(stream->parent);
}

static size_t
o_stream_lzma_get_buffer_avail_size(const struct ostream_private *stream)
{
	/* FIXME: not correct - this is counting compressed size, which may be
	   too larger than uncompressed size in some situations. Fixing would
	   require some kind of additional buffering. */
	return o_stream_get_buffer_avail_size(stream->parent);
}

static ssize_t
o_stream_lzma_sendv(struct ostream_private *stream,
		    const struct const_iovec *iov, unsigned int iov_count)
{
	struct lzma_ostream *zstream = (struct lzma_ostream *)stream;
	ssize_t ret, bytes = 0;
	unsigned int i;

	if ((ret = o_stream_zlib_send_outbuf(zstream)) <= 0) {
		/* error / we still couldn't flush existing data to
		   parent stream. */
		return ret;
	}

	for (i = 0; i < iov_count; i++) {
		ret = o_stream_lzma_send_chunk(zstream, iov[i].iov_base,
						iov[i].iov_len);
		if (ret < 0)
			return -1;
		bytes += ret;
		if ((size_t)ret != iov[i].iov_len)
			break;
	}
	stream->ostream.offset += bytes;

	/* avail_in!=0 check is used to detect errors. if it's non-zero here
	   it simply means we didn't send all the data */
	zstream->strm.avail_in = 0;
	return bytes;
}

struct ostream *o_stream_create_lzma(struct ostream *output, int level)
{
	struct lzma_ostream *zstream;
	lzma_ret ret;

	i_assert(level >= 1 && level <= 9);

	zstream = i_new(struct lzma_ostream, 1);
	zstream->ostream.sendv = o_stream_lzma_sendv;
	zstream->ostream.flush = o_stream_lzma_flush;
	zstream->ostream.get_buffer_used_size =
		o_stream_lzma_get_buffer_used_size;
	zstream->ostream.get_buffer_avail_size =
		o_stream_lzma_get_buffer_avail_size;
	zstream->ostream.iostream.close = o_stream_lzma_close;

	ret = lzma_easy_encoder(&zstream->strm, level, LZMA_CHECK_CRC64);
	switch (ret) {
	case LZMA_OK:
		break;
	case LZMA_MEM_ERROR:
		i_fatal_status(FATAL_OUTOFMEM, "lzma: Out of memory");
	case LZMA_OPTIONS_ERROR:
		i_fatal("lzma: Invalid level");
	default:
		i_fatal("lzma_easy_encoder() failed with %d", ret);
	}

	zstream->strm.next_out = zstream->outbuf;
	zstream->strm.avail_out = sizeof(zstream->outbuf);
	return o_stream_create(&zstream->ostream, output,
			       o_stream_get_fd(output));
}
#endif
