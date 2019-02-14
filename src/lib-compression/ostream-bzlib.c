/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"

#ifdef HAVE_BZLIB

#include "ostream-private.h"
#include "ostream-zlib.h"
#include <bzlib.h>

#define CHUNK_SIZE (1024*64)

struct bzlib_ostream {
	struct ostream_private ostream;
	bz_stream zs;

	char outbuf[CHUNK_SIZE];
	unsigned int outbuf_offset, outbuf_used;

	bool flushed:1;
};

static void o_stream_bzlib_close(struct iostream_private *stream,
				 bool close_parent)
{
	struct bzlib_ostream *zstream = (struct bzlib_ostream *)stream;

	(void)BZ2_bzCompressEnd(&zstream->zs);
	if (close_parent)
		o_stream_close(zstream->ostream.parent);
}

static int o_stream_zlib_send_outbuf(struct bzlib_ostream *zstream)
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
o_stream_bzlib_send_chunk(struct bzlib_ostream *zstream,
			  const void *data, size_t size)
{
	bz_stream *zs = &zstream->zs;
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

		switch (BZ2_bzCompress(zs, BZ_RUN)) {
		case BZ_RUN_OK:
			break;
		default:
			i_unreached();
		}
	}
	size -= zs->avail_in;

	zstream->flushed = FALSE;
	return size;
}

static int o_stream_bzlib_send_flush(struct bzlib_ostream *zstream)
{
	bz_stream *zs = &zstream->zs;
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
		len = sizeof(zstream->outbuf) - zs->avail_out;
		if (len != 0) {
			zs->next_out = zstream->outbuf;
			zs->avail_out = sizeof(zstream->outbuf);

			zstream->outbuf_used = len;
			if ((ret = o_stream_zlib_send_outbuf(zstream)) <= 0)
				return ret;
			if (done)
				break;
		}

		ret = BZ2_bzCompress(zs, BZ_FINISH);
		switch (ret) {
		case BZ_STREAM_END:
			done = TRUE;
			break;
		case BZ_FINISH_OK:
			break;
		default:
			i_unreached();
		}
	} while (zs->avail_out != sizeof(zstream->outbuf));

	zstream->flushed = TRUE;
	return 0;
}

static int o_stream_bzlib_flush(struct ostream_private *stream)
{
	struct bzlib_ostream *zstream = (struct bzlib_ostream *)stream;

	if (o_stream_bzlib_send_flush(zstream) < 0)
		return -1;

	return o_stream_flush_parent(stream);
}

static size_t
o_stream_bzlib_get_buffer_used_size(const struct ostream_private *stream)
{
	const struct bzlib_ostream *zstream =
		(const struct bzlib_ostream *)stream;

	/* outbuf has already compressed data that we're trying to send to the
	   parent stream. We're not including bzlib's internal compression
	   buffer size. */
	return (zstream->outbuf_used - zstream->outbuf_offset) +
		o_stream_get_buffer_used_size(stream->parent);
}

static size_t
o_stream_bzlib_get_buffer_avail_size(const struct ostream_private *stream)
{
	/* FIXME: not correct - this is counting compressed size, which may be
	   too larger than uncompressed size in some situations. Fixing would
	   require some kind of additional buffering. */
	return o_stream_get_buffer_avail_size(stream->parent);
}

static ssize_t
o_stream_bzlib_sendv(struct ostream_private *stream,
		    const struct const_iovec *iov, unsigned int iov_count)
{
	struct bzlib_ostream *zstream = (struct bzlib_ostream *)stream;
	ssize_t ret, bytes = 0;
	unsigned int i;

	if ((ret = o_stream_zlib_send_outbuf(zstream)) <= 0) {
		/* error / we still couldn't flush existing data to
		   parent stream. */
		return ret;
	}

	for (i = 0; i < iov_count; i++) {
		ret = o_stream_bzlib_send_chunk(zstream, iov[i].iov_base,
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
	zstream->zs.avail_in = 0;
	return bytes;
}

struct ostream *o_stream_create_bz2(struct ostream *output, int level)
{
	struct bzlib_ostream *zstream;
	int ret;

	if (level < 1 || level > 9) {
		i_warning("bzlib compression level must be between 1..9");
		level = 6;
	}

	zstream = i_new(struct bzlib_ostream, 1);
	zstream->ostream.sendv = o_stream_bzlib_sendv;
	zstream->ostream.flush = o_stream_bzlib_flush;
	zstream->ostream.get_buffer_used_size =
		o_stream_bzlib_get_buffer_used_size;
	zstream->ostream.get_buffer_avail_size =
		o_stream_bzlib_get_buffer_avail_size;
	zstream->ostream.iostream.close = o_stream_bzlib_close;

	ret = BZ2_bzCompressInit(&zstream->zs, level, 0, 0);
	switch (ret) {
	case BZ_OK:
		break;
	case BZ_MEM_ERROR:
		i_fatal_status(FATAL_OUTOFMEM,
			       "bzlib: Out of memory");
	case BZ_CONFIG_ERROR:
		i_fatal("Wrong bzlib library version (broken compilation)");
	case BZ_PARAM_ERROR:
		i_fatal("bzlib: Invalid parameters");
	default:
		i_fatal("BZ2_bzCompressInit() failed with %d", ret);
	}

	zstream->zs.next_out = zstream->outbuf;
	zstream->zs.avail_out = sizeof(zstream->outbuf);
	return o_stream_create(&zstream->ostream, output,
			       o_stream_get_fd(output));
}
#endif
