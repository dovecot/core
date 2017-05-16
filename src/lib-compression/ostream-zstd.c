/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"

#ifdef HAVE_ZSTD

#include "ostream.h"
#include "ostream-private.h"
#include "ostream-zlib.h"

#include "zstd.h"
#include "zstd_errors.h"

struct zstd_ostream {
	struct ostream_private ostream;

	ZSTD_CStream *cstream;
	ZSTD_outBuffer output;

	unsigned char *outbuf;

	bool flushed:1;
	bool log_errors:1;
	bool closed:1;
	bool finished:1;
};

static void o_stream_zstd_error(struct zstd_ostream *zstream, const char *error)
{
	io_stream_set_error(&zstream->ostream.iostream,
			    "zstd.write(%s): %s at %"PRIuUOFF_T,
			    o_stream_get_name(&zstream->ostream.ostream), error,
			    zstream->ostream.ostream.offset);
	if (zstream->log_errors)
		i_error("%s", zstream->ostream.iostream.error);
}

static void o_stream_zstd_write_error(struct zstd_ostream *zstream, size_t err)
{
	const char *error = ZSTD_getErrorName(err);
	if (err == ZSTD_error_memory_allocation)
		i_fatal_status(FATAL_OUTOFMEM, "zstd.write(%s): Out of memory",
			       o_stream_get_name(&zstream->ostream.ostream));
	o_stream_zstd_error(zstream, error);
}

static ssize_t o_stream_zstd_send_outbuf(struct zstd_ostream *zstream)
{
	ssize_t ret;
	/* nothing to send */
	if (zstream->output.pos == 0)
		return 1;
	ret = o_stream_send(zstream->ostream.parent, zstream->output.dst,
			    zstream->output.pos);
	if (ret < 0) {
		o_stream_copy_error_from_parent(&zstream->ostream);
		return -1;
	} else {
		memmove(zstream->outbuf, zstream->outbuf+ret, zstream->output.pos-ret);
		zstream->output.pos -= ret;
	}
	if (zstream->output.pos > 0)
		return 0;
	return 1;
}

static ssize_t
o_stream_zstd_sendv(struct ostream_private *stream,
		    const struct const_iovec *iov, unsigned int iov_count)
{
	struct zstd_ostream *zstream =
		container_of(stream, struct zstd_ostream, ostream);
	ssize_t total = 0;
	size_t ret;

	for (unsigned int i = 0; i < iov_count; i++) {
		/* does it actually fit there */
		if (zstream->output.pos + iov[i].iov_len >= zstream->output.size)
			break;
		ZSTD_inBuffer input = {
			.src = iov[i].iov_base,
			.pos = 0,
			.size = iov[i].iov_len
		};
		ret = ZSTD_compressStream(zstream->cstream, &zstream->output,
					  &input);
		if (ZSTD_isError(ret) != 0) {
			o_stream_zstd_write_error(zstream, ret);
			return -1;
		}
		total += input.pos;
	}
	if (o_stream_zstd_send_outbuf(zstream) < 0)
		return -1;
	stream->ostream.offset += total;
	return total;
}

static int o_stream_zstd_send_flush(struct zstd_ostream *zstream, bool final)
{
	int ret;

	if (zstream->flushed)
		return 1;

	if ((ret = o_stream_flush_parent_if_needed(&zstream->ostream)) <= 0)
		return ret;

	if (zstream->output.pos == 0)
		ZSTD_flushStream(zstream->cstream, &zstream->output);

	if ((ret = o_stream_zstd_send_outbuf(zstream)) <= 0)
		return ret;

	if (!final)
		return 1;

	if (!zstream->finished) {
		ret = ZSTD_endStream(zstream->cstream, &zstream->output);
		if (ZSTD_isError(ret) != 0) {
			o_stream_zstd_write_error(zstream, ret);
			return -1;
		}
		zstream->finished = TRUE;
	}

	if ((ret = o_stream_zstd_send_outbuf(zstream)) <= 0)
		return ret;

	if (final)
		zstream->flushed = TRUE;
	return 1;
}

static int o_stream_zstd_flush(struct ostream_private *stream)
{
	struct zstd_ostream *zstream =
		container_of(stream, struct zstd_ostream, ostream);

	int ret;
	if ((ret = o_stream_zstd_send_flush(zstream, stream->finished)) < 0)
		return -1;
	else if (ret > 0)
		return o_stream_flush_parent(stream);
	return ret;
}

static void o_stream_zstd_close(struct iostream_private *stream,
				bool close_parent)
{
	struct ostream_private *_ostream =
		container_of(stream, struct ostream_private, iostream);
	struct zstd_ostream *zstream =
		container_of(_ostream, struct zstd_ostream, ostream);

	i_assert(zstream->ostream.finished ||
		 zstream->ostream.ostream.stream_errno != 0 ||
		 zstream->ostream.error_handling_disabled);
	if (zstream->cstream != NULL) {
		ZSTD_freeCStream(zstream->cstream);
		zstream->cstream = NULL;
	}
	i_free(zstream->outbuf);
	i_zero(&zstream->output);
	if (close_parent)
		o_stream_close(zstream->ostream.parent);
}

struct ostream *
o_stream_create_zstd(struct ostream *output, int level)
{
	struct zstd_ostream *zstream;
	size_t ret;

	i_assert(level >= 1 && level <= ZSTD_maxCLevel());

	zstream = i_new(struct zstd_ostream, 1);
	zstream->ostream.sendv = o_stream_zstd_sendv;
	zstream->ostream.flush = o_stream_zstd_flush;
	zstream->ostream.iostream.close = o_stream_zstd_close;
	zstream->cstream = ZSTD_createCStream();
	if (zstream->cstream == NULL)
		i_fatal_status(FATAL_OUTOFMEM, "zstd: Out of memory");
	ret = ZSTD_initCStream(zstream->cstream, level);
	if (ZSTD_isError(ret) != 0)
		o_stream_zstd_write_error(zstream, ret);
	else {
		zstream->outbuf = i_malloc(ZSTD_CStreamOutSize());
		zstream->output.dst = zstream->outbuf;
		zstream->output.size = ZSTD_CStreamOutSize();
	}
	return o_stream_create(&zstream->ostream, output,
			       o_stream_get_fd(output));
}

#endif
