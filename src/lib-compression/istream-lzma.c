/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"

#ifdef HAVE_LZMA

#include "istream-private.h"
#include "istream-zlib.h"
#include <lzma.h>

#define CHUNK_SIZE (1024*64)

#define LZMA_MEMORY_LIMIT (1024*1024*80)

struct lzma_istream {
	struct istream_private istream;

	lzma_stream strm;
	uoff_t eof_offset;
	struct stat last_parent_statbuf;

	bool hdr_read:1;
	bool log_errors:1;
	bool marked:1;
	bool strm_closed:1;
};

static void i_stream_lzma_close(struct iostream_private *stream,
				 bool close_parent)
{
	struct lzma_istream *zstream = (struct lzma_istream *)stream;

	if (!zstream->strm_closed) {
		lzma_end(&zstream->strm);
		zstream->strm_closed = TRUE;
	}
	if (close_parent)
		i_stream_close(zstream->istream.parent);
}

static void lzma_read_error(struct lzma_istream *zstream, const char *error)
{
	io_stream_set_error(&zstream->istream.iostream,
			    "lzma.read(%s): %s at %"PRIuUOFF_T,
			    i_stream_get_name(&zstream->istream.istream), error,
			    i_stream_get_absolute_offset(&zstream->istream.istream));
	if (zstream->log_errors)
		i_error("%s", zstream->istream.iostream.error);
}

static int lzma_handle_error(struct lzma_istream *zstream, lzma_ret lzma_err)
{
	struct istream_private *stream = &zstream->istream;
	switch (lzma_err) {
	case LZMA_OK:
		break;
	case LZMA_DATA_ERROR:
	case LZMA_BUF_ERROR:
		lzma_read_error(zstream, "corrupted data");
		stream->istream.stream_errno = EINVAL;
		return -1;
	case LZMA_FORMAT_ERROR:
		lzma_read_error(zstream, "wrong magic in header (not xz file?)");
		stream->istream.stream_errno = EINVAL;
		return -1;
	case LZMA_OPTIONS_ERROR:
		lzma_read_error(zstream, "Unsupported xz options");
		stream->istream.stream_errno = EIO;
		return -1;
	case LZMA_MEM_ERROR:
		i_fatal_status(FATAL_OUTOFMEM, "lzma.read(%s): Out of memory",
			       i_stream_get_name(&stream->istream));
	case LZMA_STREAM_END:
		break;
	default:
		lzma_read_error(zstream, t_strdup_printf(
			"lzma_code() failed with %d", lzma_err));
		stream->istream.stream_errno = EIO;
		return -1;
	}
	return 0;
}

static void lzma_stream_end(struct lzma_istream *zstream)
{
	zstream->eof_offset = zstream->istream.istream.v_offset +
		(zstream->istream.pos - zstream->istream.skip);
	zstream->istream.cached_stream_size = zstream->eof_offset;
}

static ssize_t i_stream_lzma_read(struct istream_private *stream)
{
	struct lzma_istream *zstream = (struct lzma_istream *)stream;
	const unsigned char *data;
	uoff_t high_offset;
	size_t size, out_size;
	lzma_ret ret;

	high_offset = stream->istream.v_offset + (stream->pos - stream->skip);
	if (zstream->eof_offset == high_offset) {
		stream->istream.eof = TRUE;
		return -1;
	}

	if (!zstream->marked) {
		if (!i_stream_try_alloc(stream, CHUNK_SIZE, &out_size))
			return -2; /* buffer full */
	} else {
		/* try to avoid compressing, so we can quickly seek backwards */
		if (!i_stream_try_alloc_avoid_compress(stream, CHUNK_SIZE, &out_size))
			return -2; /* buffer full */
	}

	if (i_stream_read_more(stream->parent, &data, &size) < 0) {
		if (stream->parent->stream_errno != 0) {
			stream->istream.stream_errno =
				stream->parent->stream_errno;
		} else {
			i_assert(stream->parent->eof);
			ret = lzma_code(&zstream->strm, LZMA_FINISH);
			if (ret != LZMA_STREAM_END)
				if (lzma_handle_error(zstream, ret) == 0)
					stream->istream.stream_errno =
						zstream->hdr_read ? EPIPE : EINVAL;
			stream->istream.eof = TRUE;
		}
		return -1;
	}
	if (size == 0) {
		/* no more input */
		i_assert(!stream->istream.blocking);
		return 0;
	}

	zstream->strm.next_in = data;
	zstream->strm.avail_in = size;

	zstream->strm.next_out = stream->w_buffer + stream->pos;
	zstream->strm.avail_out = out_size;
	if (!zstream->hdr_read && size > LZMA_STREAM_HEADER_SIZE)
		zstream->hdr_read = TRUE;
	ret = lzma_code(&zstream->strm, LZMA_RUN);

	out_size -= zstream->strm.avail_out;
	stream->pos += out_size;

	i_stream_skip(stream->parent, size - zstream->strm.avail_in);

	if (lzma_handle_error(zstream, ret) < 0) {
		return -1;
	} else if (ret == LZMA_STREAM_END) {
		lzma_stream_end(zstream);
		if (out_size == 0) {
			stream->istream.eof = TRUE;
			return -1;
		}
	}
	if (out_size == 0) {
		/* read more input */
		return i_stream_lzma_read(stream);
	}
	return out_size;
}

static void i_stream_lzma_init(struct lzma_istream *zstream)
{
	lzma_ret ret;

	ret = lzma_stream_decoder(&zstream->strm, LZMA_MEMORY_LIMIT,
				  LZMA_CONCATENATED);
	switch (ret) {
	case LZMA_OK:
		break;
	case LZMA_MEM_ERROR:
		i_fatal_status(FATAL_OUTOFMEM, "lzma: Out of memory");
	default:
		i_fatal("lzma_stream_decoder() failed with ret=%d", ret);
	}
}

static void i_stream_lzma_reset(struct lzma_istream *zstream)
{
	struct istream_private *stream = &zstream->istream;

	i_stream_seek(stream->parent, stream->parent_start_offset);
	zstream->eof_offset = (uoff_t)-1;
	zstream->strm.next_in = NULL;
	zstream->strm.avail_in = 0;

	stream->parent_expected_offset = stream->parent_start_offset;
	stream->skip = stream->pos = 0;
	stream->istream.v_offset = 0;

	lzma_end(&zstream->strm);
	i_stream_lzma_init(zstream);
}

static void
i_stream_lzma_seek(struct istream_private *stream, uoff_t v_offset, bool mark)
{
	struct lzma_istream *zstream = (struct lzma_istream *) stream;

	if (i_stream_nonseekable_try_seek(stream, v_offset))
		return;

	/* have to seek backwards - reset state and retry */
	i_stream_lzma_reset(zstream);
	if (!i_stream_nonseekable_try_seek(stream, v_offset))
		i_unreached();

	if (mark)
		zstream->marked = TRUE;
}

static void i_stream_lzma_sync(struct istream_private *stream)
{
	struct lzma_istream *zstream = (struct lzma_istream *) stream;
	const struct stat *st;

	if (i_stream_stat(stream->parent, FALSE, &st) == 0) {
		if (memcmp(&zstream->last_parent_statbuf,
			   st, sizeof(*st)) == 0) {
			/* a compressed file doesn't change unexpectedly,
			   don't clear our caches unnecessarily */
			return;
		}
		zstream->last_parent_statbuf = *st;
	}
	i_stream_lzma_reset(zstream);
}

struct istream *i_stream_create_lzma(struct istream *input, bool log_errors)
{
	struct lzma_istream *zstream;

	zstream = i_new(struct lzma_istream, 1);
	zstream->eof_offset = (uoff_t)-1;
	zstream->log_errors = log_errors;

	i_stream_lzma_init(zstream);

	zstream->istream.iostream.close = i_stream_lzma_close;
	zstream->istream.max_buffer_size = input->real_stream->max_buffer_size;
	zstream->istream.read = i_stream_lzma_read;
	zstream->istream.seek = i_stream_lzma_seek;
	zstream->istream.sync = i_stream_lzma_sync;

	zstream->istream.istream.readable_fd = FALSE;
	zstream->istream.istream.blocking = input->blocking;
	zstream->istream.istream.seekable = input->seekable;

	return i_stream_create(&zstream->istream, input,
			       i_stream_get_fd(input), 0);
}
#endif
