/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"

#ifdef HAVE_BZLIB

#include "istream-internal.h"
#include "istream-zlib.h"
#include <bzlib.h>

#define CHUNK_SIZE (1024*64)

struct bzlib_istream {
	struct istream_private istream;

	bz_stream zs;
	uoff_t eof_offset;
	size_t prev_size, high_pos;
	struct stat last_parent_statbuf;

	unsigned int log_errors:1;
	unsigned int marked:1;
	unsigned int zs_closed:1;
};

static void i_stream_bzlib_close(struct iostream_private *stream)
{
	struct bzlib_istream *zstream = (struct bzlib_istream *)stream;

	if (!zstream->zs_closed) {
		(void)BZ2_bzDecompressEnd(&zstream->zs);
		zstream->zs_closed = TRUE;
	}
}

static void bzlib_read_error(struct bzlib_istream *zstream, const char *error)
{
	i_error("bzlib.read(%s): %s at %"PRIuUOFF_T,
		i_stream_get_name(&zstream->istream.istream), error,
		zstream->istream.abs_start_offset +
		zstream->istream.istream.v_offset);
}

static ssize_t i_stream_bzlib_read(struct istream_private *stream)
{
	struct bzlib_istream *zstream = (struct bzlib_istream *)stream;
	const unsigned char *data;
	uoff_t high_offset;
	size_t size;
	int ret;

	high_offset = stream->istream.v_offset + (stream->pos - stream->skip);
	if (zstream->eof_offset == high_offset) {
		i_assert(zstream->high_pos == 0 ||
			 zstream->high_pos == stream->pos);
		stream->istream.eof = TRUE;
		return -1;
	}

	if (stream->pos < zstream->high_pos) {
		/* we're here because we seeked back within the read buffer. */
		ret = zstream->high_pos - stream->pos;
		stream->pos = zstream->high_pos;
		zstream->high_pos = 0;

		if (zstream->eof_offset != (uoff_t)-1) {
			high_offset = stream->istream.v_offset +
				(stream->pos - stream->skip);
			i_assert(zstream->eof_offset == high_offset);
			stream->istream.eof = TRUE;
		}
		return ret;
	}
	zstream->high_pos = 0;

	if (stream->pos + CHUNK_SIZE > stream->buffer_size) {
		/* try to keep at least CHUNK_SIZE available */
		if (!zstream->marked && stream->skip > 0) {
			/* don't try to keep anything cached if we don't
			   have a seek mark. */
			i_stream_compress(stream);
		}
		if (stream->max_buffer_size == 0 ||
		    stream->buffer_size < stream->max_buffer_size)
			i_stream_grow_buffer(stream, CHUNK_SIZE);

		if (stream->pos == stream->buffer_size) {
			if (stream->skip > 0) {
				/* lose our buffer cache */
				i_stream_compress(stream);
			}

			if (stream->pos == stream->buffer_size)
				return -2; /* buffer full */
		}
	}

	if (zstream->zs.avail_in == 0) {
		/* need to read more data. try to read a full CHUNK_SIZE */
		i_stream_skip(stream->parent, zstream->prev_size);
		if (i_stream_read_data(stream->parent, &data, &size,
				       CHUNK_SIZE-1) == -1 && size == 0) {
			if (stream->parent->stream_errno != 0) {
				stream->istream.stream_errno =
					stream->parent->stream_errno;
			} else {
				i_assert(stream->parent->eof);
				if (zstream->log_errors) {
					bzlib_read_error(zstream,
							 "unexpected EOF");
				}
				stream->istream.stream_errno = EINVAL;
			}
			return -1;
		}
		zstream->prev_size = size;
		if (size == 0) {
			/* no more input */
			i_assert(!stream->istream.blocking);
			return 0;
		}

		zstream->zs.next_in = (char *)data;
		zstream->zs.avail_in = size;
	}

	size = stream->buffer_size - stream->pos;
	zstream->zs.next_out = (char *)stream->w_buffer + stream->pos;
	zstream->zs.avail_out = size;
	ret = BZ2_bzDecompress(&zstream->zs);

	size -= zstream->zs.avail_out;
	stream->pos += size;

	switch (ret) {
	case BZ_OK:
		break;
	case BZ_PARAM_ERROR:
		i_unreached();
	case BZ_DATA_ERROR:
		if (zstream->log_errors)
			bzlib_read_error(zstream, "corrupted data");
		stream->istream.stream_errno = EINVAL;
		return -1;
	case BZ_DATA_ERROR_MAGIC:
		if (zstream->log_errors) {
			bzlib_read_error(zstream,
				"wrong magic in header (not bz2 file?)");
		}
		stream->istream.stream_errno = EINVAL;
		return -1;
	case BZ_MEM_ERROR:
		i_fatal_status(FATAL_OUTOFMEM, "bzlib.read(%s): Out of memory",
			       i_stream_get_name(&stream->istream));
	case BZ_STREAM_END:
		zstream->eof_offset = stream->istream.v_offset +
			(stream->pos - stream->skip);
		if (size == 0) {
			stream->istream.eof = TRUE;
			return -1;
		}
		break;
	default:
		i_fatal("BZ2_bzDecompress() failed with %d", ret);
	}
	if (size == 0) {
		/* read more input */
		return i_stream_bzlib_read(stream);
	}
	return size;
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
	zstream->high_pos = 0;
	zstream->prev_size = 0;

	(void)BZ2_bzDecompressEnd(&zstream->zs);
	i_stream_bzlib_init(zstream);
}

static void
i_stream_bzlib_seek(struct istream_private *stream, uoff_t v_offset, bool mark)
{
	struct bzlib_istream *zstream = (struct bzlib_istream *) stream;
	uoff_t start_offset = stream->istream.v_offset - stream->skip;

	if (v_offset < start_offset) {
		/* have to seek backwards */
		i_stream_bzlib_reset(zstream);
		start_offset = 0;
	} else if (zstream->high_pos != 0) {
		stream->pos = zstream->high_pos;
		zstream->high_pos = 0;
	}

	if (v_offset <= start_offset + stream->pos) {
		/* seeking backwards within what's already cached */
		stream->skip = v_offset - start_offset;
		stream->istream.v_offset = v_offset;
		zstream->high_pos = stream->pos;
		stream->pos = stream->skip;
	} else {
		/* read and cache forward */
		do {
			size_t avail = stream->pos - stream->skip;

			if (stream->istream.v_offset + avail >= v_offset) {
				i_stream_skip(&stream->istream,
					      v_offset -
					      stream->istream.v_offset);
				break;
			}

			i_stream_skip(&stream->istream, avail);
		} while (i_stream_read(&stream->istream) >= 0);

		if (stream->istream.v_offset != v_offset) {
			/* some failure, we've broken it */
			if (stream->istream.stream_errno != 0) {
				i_error("bzlib_istream.seek(%s) failed: %s",
					i_stream_get_name(&stream->istream),
					strerror(stream->istream.stream_errno));
				i_stream_close(&stream->istream);
			} else {
				/* unexpected EOF. allow it since we may just
				   want to check if there's anything.. */
				i_assert(stream->istream.eof);
			}
		}
	}

	if (mark)
		zstream->marked = TRUE;
}

static const struct stat *
i_stream_bzlib_stat(struct istream_private *stream, bool exact)
{
	struct bzlib_istream *zstream = (struct bzlib_istream *) stream;
	const struct stat *st;
	size_t size;

	st = i_stream_stat(stream->parent, exact);
	if (st == NULL)
		return NULL;

	/* when exact=FALSE always return the parent stat's size, even if we
	   know the exact value. this is necessary because otherwise e.g. mbox
	   code can see two different values and think that a compressed mbox
	   file keeps changing. */
	if (!exact)
		return st;

	stream->statbuf = *st;
	if (zstream->eof_offset == (uoff_t)-1) {
		uoff_t old_offset = stream->istream.v_offset;

		do {
			(void)i_stream_get_data(&stream->istream, &size);
			i_stream_skip(&stream->istream, size);
		} while (i_stream_read(&stream->istream) > 0);

		i_stream_seek(&stream->istream, old_offset);
		if (zstream->eof_offset == (uoff_t)-1)
			return NULL;
	}
	stream->statbuf.st_size = zstream->eof_offset;
	return &stream->statbuf;
}

static void i_stream_bzlib_sync(struct istream_private *stream)
{
	struct bzlib_istream *zstream = (struct bzlib_istream *) stream;
	const struct stat *st;

	st = i_stream_stat(stream->parent, FALSE);
	if (st != NULL) {
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
	zstream->istream.stat = i_stream_bzlib_stat;
	zstream->istream.sync = i_stream_bzlib_sync;

	zstream->istream.istream.readable_fd = FALSE;
	zstream->istream.istream.blocking = input->blocking;
	zstream->istream.istream.seekable = input->seekable;

	return i_stream_create(&zstream->istream, input,
			       i_stream_get_fd(input));
}
#endif
