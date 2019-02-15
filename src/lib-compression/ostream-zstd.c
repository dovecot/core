/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"

#ifdef HAVE_ZSTD

#include "ostream-private.h"
#include "ostream-zlib.h"
#include <zstd.h>

struct zstd_ostream {
	struct ostream_private ostream;
	ZSTD_CStream *cstream;
	ZSTD_outBuffer output;

	bool flushed : 1;
};

static int o_stream_zstd_send_output(struct zstd_ostream *zstream)
{
	ssize_t ret;

	if (zstream->output.pos == 0)
		return 1;

	ret = o_stream_send(zstream->ostream.parent, zstream->output.dst,
			    zstream->output.pos);
	if (ret < 0) {
		o_stream_copy_error_from_parent(&zstream->ostream);
		return -1;
	}
	if (ret != (ssize_t)zstream->output.pos) {
		i_panic("o_stream_send(): Wrote %ld when expecting to write %ld.",
			ret, zstream->output.pos);
		return 0;
	}
	zstream->output.pos = 0;
	return 1;
}

static ssize_t o_stream_zstd_sendv(struct ostream_private *stream,
				   const struct const_iovec *iov,
				   unsigned int iov_count)
{
	struct zstd_ostream *zstream = (struct zstd_ostream *)stream;
	o_stream_zstd_send_output(zstream);
	ssize_t bytes = -zstream->output.pos;
	for (unsigned int i = 0; i < iov_count; i++) {
		ZSTD_inBuffer input = { iov[i].iov_base, iov[i].iov_len, 0 };
		while (input.pos < input.size) {
			if (zstream->output.pos == zstream->output.size) {
				if (o_stream_zstd_send_output(zstream) < 0) {
					i_panic("cant send to output");
				}
			}
			size_t ret = ZSTD_compressStream(
				zstream->cstream, &zstream->output, &input);
			if (ZSTD_isError(ret)) {
				i_fatal("ZSTD_compressStream(): %s",
					ZSTD_getErrorName(ret));
			}
		}
		bytes += input.size;
	}
	zstream->flushed = FALSE;

	stream->ostream.offset += bytes;
	return bytes;
}

static int o_stream_zstd_flush(struct ostream_private *stream)
{
	struct zstd_ostream *zstream = (struct zstd_ostream *)stream;
	int ret;
	size_t oret;
	if (zstream->flushed)
		return 0;

	if ((ret = o_stream_flush_parent_if_needed(&zstream->ostream)) <= 0)
		return ret;
	if ((ret = o_stream_zstd_send_output(zstream)) <= 0)
		return ret;

	oret = ZSTD_flushStream(zstream->cstream, &zstream->output);
	if (ZSTD_isError(oret)) {
		i_fatal("ZSTD_flushStream():%s", ZSTD_getErrorName(oret));
	}
	else {
		return o_stream_zstd_send_output(zstream);
	}
	zstream->flushed = TRUE;

	return 0;
}

static size_t
o_stream_zstd_get_buffer_used_size(const struct ostream_private *stream)
{
	struct zstd_ostream *zstream = (struct zstd_ostream *)stream;
	return zstream->output.pos +
	       o_stream_get_buffer_used_size(stream->parent);
}

static size_t
o_stream_zstd_get_buffer_avail_size(const struct ostream_private *stream)
{
	return o_stream_get_buffer_avail_size(stream->parent);
}

static void o_stream_zstd_close(struct iostream_private *stream,
				bool close_parent)
{
	struct zstd_ostream *zstream = (struct zstd_ostream *)stream;
	if(zstream->cstream) {
		size_t ret = ZSTD_endStream(zstream->cstream, &zstream->output);
		ZSTD_freeCStream(zstream->cstream);
		zstream->cstream = 0;
		if (ZSTD_isError(ret)) {
			i_fatal("ZSTD_endStream():%s", ZSTD_getErrorName(ret));
		}
		o_stream_zstd_send_output(zstream);
		i_free(zstream->output.dst);
	}
	if (close_parent)
		o_stream_close(zstream->ostream.parent);
}

struct ostream *o_stream_create_zstd(struct ostream *output, int level)
{
	struct zstd_ostream *zstream;
	zstream = i_new(struct zstd_ostream, 1);
	zstream->ostream.sendv = o_stream_zstd_sendv;
	zstream->ostream.flush = o_stream_zstd_flush;
	zstream->ostream.get_buffer_used_size =
		o_stream_zstd_get_buffer_used_size;
	zstream->ostream.get_buffer_avail_size =
		o_stream_zstd_get_buffer_avail_size;
	zstream->ostream.iostream.close = o_stream_zstd_close;
	zstream->cstream = ZSTD_createCStream();
	if (zstream->cstream == NULL)
		i_fatal("ZSTD_createCStream(): failed to create cstream.");

	zstream->output.dst = i_malloc(ZSTD_CStreamOutSize());
	zstream->output.size = ZSTD_CStreamOutSize();
	zstream->output.pos = 0;
	i_assert(1 >= 1 && level <= ZSTD_maxCLevel());

	ZSTD_initCStream(zstream->cstream, level);
	return o_stream_create(&zstream->ostream, output,
			       o_stream_get_fd(output));
}
#endif
