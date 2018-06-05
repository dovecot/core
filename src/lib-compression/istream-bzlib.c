/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"

#ifdef HAVE_BZLIB

#include "istream-private.h"
#include "istream-zlib.h"
#include <bzlib.h>

#define CHUNK_SIZE (1024*64)

struct bzlib_istream {
	struct istream_private istream;

	bz_stream zs;
	uoff_t eof_offset;
	struct stat last_parent_statbuf;

	bool log_errors:1;
	bool marked:1;
	bool zs_closed:1;
};

static void i_stream_bzlib_close(struct iostream_private *stream,
				 bool close_parent)
{
	struct bzlib_istream *zstream = (struct bzlib_istream *)stream;

	if (!zstream->zs_closed) {
		(void)BZ2_bzDecompressEnd(&zstream->zs);
		zstream->zs_closed = TRUE;
	}
	if (close_parent)
		i_stream_close(zstream->istream.parent);
}

static void bzlib_read_error(struct bzlib_istream *zstream, const char *error)
{
	io_stream_set_error(&zstream->istream.iostream,
			    "bzlib.read(%s): %s at %"PRIuUOFF_T,
			    i_stream_get_name(&zstream->istream.istream), error,
			    i_stream_get_absolute_offset(&zstream->istream.istream));
	if (zstream->log_errors)
		i_error("%s", zstream->istream.iostream.error);
}

static ssize_t i_stream_bzlib_read(struct istream_private *stream)
{
	struct bzlib_istream *zstream = (struct bzlib_istream *)stream;
	const unsigned char *data;
	uoff_t high_offset;
	size_t size, out_size;
	int ret;

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
			bzlib_read_error(zstream, "unexpected EOF");
			stream->istream.stream_errno = EPIPE;
		}
		return -1;
	}
	if (size == 0) {
		/* no more input */
		i_assert(!stream->istream.blocking);
		return 0;
	}

	zstream->zs.next_in = (char *)data;
	zstream->zs.avail_in = size;

	zstream->zs.next_out = (char *)stream->w_buffer + stream->pos;
	zstream->zs.avail_out = out_size;
	ret = BZ2_bzDecompress(&zstream->zs);

	out_size -= zstream->zs.avail_out;
	stream->pos += out_size;

	i_stream_skip(stream->parent, size - zstream->zs.avail_in);

	switch (ret) {
	case BZ_OK:
		break;
	case BZ_PARAM_ERROR:
		i_unreached();
	case BZ_DATA_ERROR:
		bzlib_read_error(zstream, "corrupted data");
		stream->istream.stream_errno = EINVAL;
		return -1;
	case BZ_DATA_ERROR_MAGIC:
		bzlib_read_error(zstream,
			"wrong magic in header (not bz2 file?)");
		stream->istream.stream_errno = EINVAL;
		return -1;
	case BZ_MEM_ERROR:
		i_fatal_status(FATAL_OUTOFMEM, "bzlib.read(%s): Out of memory",
			       i_stream_get_name(&stream->istream));
	case BZ_STREAM_END:
		zstream->eof_offset = stream->istream.v_offset +
			(stream->pos - stream->skip);
		stream->cached_stream_size = zstream->eof_offset;
		if (out_size == 0) {
			stream->istream.eof = TRUE;
			return -1;
		}
		break;
	default:
		i_fatal("BZ2_bzDecompress() failed with %d", ret);
	}
	if (out_size == 0) {
		/* read more input */
		return i_stream_bzlib_read(stream);
	}
	return out_size;
}

static void i_stream_bzlib_init(struct bzlib_istream *zstream)
{
	int ret;

	ret = BZ2_bzDecompressInit(&zstream->zs, 0, 0);
	switch (ret) {
	case BZ_OK:
		break;
	case BZ_MEM_ERROR:
		i_fatal_status(FATAL_OUTOFMEM, "bzlib: Out of memory");
	case BZ_CONFIG_ERROR:
		i_fatal("Wrong bzlib library version (broken compilation)");
	case BZ_PARAM_ERROR:
		i_fatal("bzlib: Invalid parameters");
	default:
		i_fatal("BZ2_bzDecompressInit() failed with %d", ret);
	}
}

static void i_stream_bzlib_reset(struct bzlib_istream *zstream)
{
	struct istream_private *stream = &zstream->istream;

	i_stream_seek(stream->parent, stream->parent_start_offset);
	zstream->eof_offset = (uoff_t)-1;
	zstream->zs.next_in = NULL;
	zstream->zs.avail_in = 0;

	stream->parent_expected_offset = stream->parent_start_offset;
	stream->skip = stream->pos = 0;
	stream->istream.v_offset = 0;
	stream->high_pos = 0;

	(void)BZ2_bzDecompressEnd(&zstream->zs);
	i_stream_bzlib_init(zstream);
}

static void
i_stream_bzlib_seek(struct istream_private *stream, uoff_t v_offset, bool mark)
{
	struct bzlib_istream *zstream = (struct bzlib_istream *) stream;

	if (i_stream_nonseekable_try_seek(stream, v_offset))
		return;

	/* have to seek backwards - reset state and retry */
	i_stream_bzlib_reset(zstream);
	if (!i_stream_nonseekable_try_seek(stream, v_offset))
		i_unreached();

	if (mark)
		zstream->marked = TRUE;
}

static void i_stream_bzlib_sync(struct istream_private *stream)
{
	struct bzlib_istream *zstream = (struct bzlib_istream *) stream;
	const struct stat *st;

	if (i_stream_stat(stream->parent, FALSE, &st) < 0) {
		if (memcmp(&zstream->last_parent_statbuf,
			   st, sizeof(*st)) == 0) {
			/* a compressed file doesn't change unexpectedly,
			   don't clear our caches unnecessarily */
			return;
		}
		zstream->last_parent_statbuf = *st;
	}
	i_stream_bzlib_reset(zstream);
}

struct istream *i_stream_create_bz2(struct istream *input, bool log_errors)
{
	struct bzlib_istream *zstream;

	zstream = i_new(struct bzlib_istream, 1);
	zstream->eof_offset = (uoff_t)-1;
	zstream->log_errors = log_errors;

	i_stream_bzlib_init(zstream);

	zstream->istream.iostream.close = i_stream_bzlib_close;
	zstream->istream.max_buffer_size = input->real_stream->max_buffer_size;
	zstream->istream.read = i_stream_bzlib_read;
	zstream->istream.seek = i_stream_bzlib_seek;
	zstream->istream.sync = i_stream_bzlib_sync;

	zstream->istream.istream.readable_fd = FALSE;
	zstream->istream.istream.blocking = input->blocking;
	zstream->istream.istream.seekable = input->seekable;

	return i_stream_create(&zstream->istream, input,
			       i_stream_get_fd(input), 0);
}
#endif
