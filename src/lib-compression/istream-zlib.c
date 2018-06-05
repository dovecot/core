/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"

#ifdef HAVE_ZLIB

#include "crc32.h"
#include "istream-private.h"
#include "istream-zlib.h"
#include <zlib.h>

#define CHUNK_SIZE (1024*64)

#define GZ_HEADER_MIN_SIZE 10
#define GZ_TRAILER_SIZE 8

#define GZ_MAGIC1	0x1f
#define GZ_MAGIC2	0x8b
#define GZ_FLAG_FHCRC	0x02
#define GZ_FLAG_FEXTRA	0x04
#define GZ_FLAG_FNAME	0x08
#define GZ_FLAG_FCOMMENT 0x10

struct zlib_istream {
	struct istream_private istream;

	z_stream zs;
	uoff_t eof_offset;
	size_t prev_size;
	uint32_t crc32;
	struct stat last_parent_statbuf;

	bool gz:1;
	bool log_errors:1;
	bool marked:1;
	bool header_read:1;
	bool trailer_read:1;
	bool zs_closed:1;
	bool starting_concated_output:1;
};

static void i_stream_zlib_init(struct zlib_istream *zstream);

static void i_stream_zlib_close(struct iostream_private *stream,
				bool close_parent)
{
	struct zlib_istream *zstream = (struct zlib_istream *)stream;

	if (!zstream->zs_closed) {
		(void)inflateEnd(&zstream->zs);
		zstream->zs_closed = TRUE;
	}
	if (close_parent)
		i_stream_close(zstream->istream.parent);
}

static void zlib_read_error(struct zlib_istream *zstream, const char *error)
{
	io_stream_set_error(&zstream->istream.iostream,
			    "zlib.read(%s): %s at %"PRIuUOFF_T,
			    i_stream_get_name(&zstream->istream.istream), error,
			    i_stream_get_absolute_offset(&zstream->istream.istream));
	if (zstream->log_errors)
		i_error("%s", zstream->istream.iostream.error);
}

static int i_stream_zlib_read_header(struct istream_private *stream)
{
	struct zlib_istream *zstream = (struct zlib_istream *)stream;
	const unsigned char *data;
	size_t size;
	unsigned int pos, fextra_size;
	int ret;

	ret = i_stream_read_bytes(stream->parent, &data, &size,
				  zstream->prev_size + 1);
	if (size == zstream->prev_size) {
		stream->istream.stream_errno = stream->parent->stream_errno;
		if (ret == -1 && stream->istream.stream_errno == 0) {
			zlib_read_error(zstream, "missing gz header");
			stream->istream.stream_errno = EINVAL;
		}
		if (ret == -2) {
			zlib_read_error(zstream, "gz header is too large");
			stream->istream.stream_errno = EINVAL;
			ret = -1;
		}
		return ret;
	}
	zstream->prev_size = size;

	if (size < GZ_HEADER_MIN_SIZE)
		return 0;
	pos = GZ_HEADER_MIN_SIZE;

	if (data[0] != GZ_MAGIC1 || data[1] != GZ_MAGIC2) {
		/* missing gzip magic header */
		zlib_read_error(zstream, "wrong magic in header (not gz file?)");
		stream->istream.stream_errno = EINVAL;
		return -1;
	}
	if ((data[3] & GZ_FLAG_FEXTRA) != 0) {
		if (pos + 2 < size)
			return 0;

		fextra_size = le16_to_cpu_unaligned(&data[pos]);
		pos += 2;
		if (pos + fextra_size < size)
			return 0;
		pos += fextra_size;
	}
	if ((data[3] & GZ_FLAG_FNAME) != 0) {
		do {
			if (pos == size)
				return 0;
		} while (data[pos++] != '\0');
	}
	if ((data[3] & GZ_FLAG_FCOMMENT) != 0) {
		do {
			if (pos == size)
				return 0;
		} while (data[pos++] != '\0');
	}
	if ((data[3] & GZ_FLAG_FHCRC) != 0) {
		if (pos + 2 < size)
			return 0;
		pos += 2;
	}
	i_stream_skip(stream->parent, pos);
	zstream->prev_size = 0;
	return 1;
}

static int i_stream_zlib_read_trailer(struct zlib_istream *zstream)
{
	struct istream_private *stream = &zstream->istream;
	const unsigned char *data;
	size_t size;
	int ret;

	ret = i_stream_read_bytes(stream->parent, &data, &size,
				  GZ_TRAILER_SIZE);
	if (size == zstream->prev_size) {
		stream->istream.stream_errno = stream->parent->stream_errno;
		if (ret == -1 && stream->istream.stream_errno == 0) {
			zlib_read_error(zstream, "missing gz trailer");
			stream->istream.stream_errno = EINVAL;
		}
		return ret;
	}
	zstream->prev_size = size;

	if (size < GZ_TRAILER_SIZE)
		return 0;

	if (le32_to_cpu_unaligned(data) != zstream->crc32) {
		zlib_read_error(zstream, "gz trailer has wrong CRC value");
		stream->istream.stream_errno = EINVAL;
		return -1;
	}
	i_stream_skip(stream->parent, GZ_TRAILER_SIZE);
	zstream->prev_size = 0;
	zstream->trailer_read = TRUE;
	return 1;
}

static ssize_t i_stream_zlib_read(struct istream_private *stream)
{
	struct zlib_istream *zstream = (struct zlib_istream *)stream;
	const unsigned char *data;
	uoff_t high_offset;
	size_t size, out_size;
	int ret;

	high_offset = stream->istream.v_offset + (stream->pos - stream->skip);
	if (zstream->eof_offset == high_offset) {
		if (!zstream->trailer_read) {
			do {
				ret = i_stream_zlib_read_trailer(zstream);
			} while (ret == 0 && stream->istream.blocking);
			if (ret <= 0)
				return ret;
		}
		if (!zstream->gz || i_stream_read_eof(stream->parent)) {
			stream->istream.eof = TRUE;
			return -1;
		}
		zstream->starting_concated_output = TRUE;
	}
	if (zstream->starting_concated_output) {
		/* make sure there actually is something in parent stream.
		   we don't want to reset the stream unless we actually see
		   some concated output. */
		ret = i_stream_read_more(stream->parent, &data, &size);
		if (ret <= 0) {
			if (ret == 0)
				return 0;
			if (stream->parent->stream_errno != 0) {
				stream->istream.stream_errno =
					stream->parent->stream_errno;
			}
			stream->istream.eof = TRUE;
			return -1;
		}

		/* gzip file with concatenated content */
		stream->cached_stream_size = (uoff_t)-1;
		zstream->eof_offset = (uoff_t)-1;
		zstream->header_read = FALSE;
		zstream->trailer_read = FALSE;
		zstream->crc32 = 0;
		zstream->starting_concated_output = FALSE;

		(void)inflateEnd(&zstream->zs);
		i_stream_zlib_init(zstream);
	}

	if (!zstream->header_read) {
		do {
			ret = i_stream_zlib_read_header(stream);
		} while (ret == 0 && stream->istream.blocking);
		if (ret <= 0)
			return ret;
		zstream->header_read = TRUE;
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
			zlib_read_error(zstream, "unexpected EOF");
			stream->istream.stream_errno = EPIPE;
		}
		return -1;
	}
	if (size == 0) {
		/* no more input */
		i_assert(!stream->istream.blocking);
		return 0;
	}

	zstream->zs.next_in = (void *)data;
	zstream->zs.avail_in = size;

	zstream->zs.next_out = stream->w_buffer + stream->pos;
	zstream->zs.avail_out = out_size;
	ret = inflate(&zstream->zs, Z_SYNC_FLUSH);

	out_size -= zstream->zs.avail_out;
	zstream->crc32 = crc32_data_more(zstream->crc32,
					 stream->w_buffer + stream->pos,
					 out_size);
	stream->pos += out_size;

	i_stream_skip(stream->parent, size - zstream->zs.avail_in);

	switch (ret) {
	case Z_OK:
		break;
	case Z_NEED_DICT:
		zlib_read_error(zstream, "can't read file without dict");
		stream->istream.stream_errno = EIO;
		return -1;
	case Z_DATA_ERROR:
		zlib_read_error(zstream, "corrupted data");
		stream->istream.stream_errno = EINVAL;
		return -1;
	case Z_MEM_ERROR:
		i_fatal_status(FATAL_OUTOFMEM, "zlib.read(%s): Out of memory",
			       i_stream_get_name(&stream->istream));
	case Z_STREAM_END:
		zstream->eof_offset = stream->istream.v_offset +
			(stream->pos - stream->skip);
		stream->cached_stream_size = zstream->eof_offset;
		zstream->zs.avail_in = 0;

		if (!zstream->trailer_read) {
			/* try to read and verify the trailer, we might not
			   be called again. */
			if (i_stream_zlib_read_trailer(zstream) < 0)
				return -1;
		}
		break;
	default:
		i_fatal("inflate() failed with %d", ret);
	}
	if (out_size == 0) {
		/* read more input */
		return i_stream_zlib_read(stream);
	}
	return out_size;
}

static void i_stream_zlib_init(struct zlib_istream *zstream)
{
	int ret;

	ret = inflateInit2(&zstream->zs, -15);
	switch (ret) {
	case Z_OK:
		break;
	case Z_MEM_ERROR:
		i_fatal_status(FATAL_OUTOFMEM, "zlib: Out of memory");
	case Z_VERSION_ERROR:
		i_fatal("Wrong zlib library version (broken compilation)");
	case Z_STREAM_ERROR:
		i_fatal("zlib: Invalid parameters");
	default:
		i_fatal("inflateInit() failed with %d", ret);
	}
	zstream->header_read = !zstream->gz;
	zstream->trailer_read = !zstream->gz;
}

static void i_stream_zlib_reset(struct zlib_istream *zstream)
{
	struct istream_private *stream = &zstream->istream;

	i_stream_seek(stream->parent, stream->parent_start_offset);
	zstream->eof_offset = (uoff_t)-1;
	zstream->crc32 = 0;

	zstream->zs.next_in = NULL;
	zstream->zs.avail_in = 0;

	stream->parent_expected_offset = stream->parent_start_offset;
	stream->skip = stream->pos = 0;
	stream->istream.v_offset = 0;
	stream->high_pos = 0;
	zstream->prev_size = 0;

	(void)inflateEnd(&zstream->zs);
	i_stream_zlib_init(zstream);
}

static void
i_stream_zlib_seek(struct istream_private *stream, uoff_t v_offset, bool mark)
{
	struct zlib_istream *zstream = (struct zlib_istream *) stream;

	if (i_stream_nonseekable_try_seek(stream, v_offset))
		return;

	/* have to seek backwards - reset state and retry */
	i_stream_zlib_reset(zstream);
	if (!i_stream_nonseekable_try_seek(stream, v_offset))
		i_unreached();

	if (mark)
		zstream->marked = TRUE;
}

static void i_stream_zlib_sync(struct istream_private *stream)
{
	struct zlib_istream *zstream = (struct zlib_istream *) stream;
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
	i_stream_zlib_reset(zstream);
}

static struct istream *
i_stream_create_zlib(struct istream *input, bool gz, bool log_errors)
{
	struct zlib_istream *zstream;

	zstream = i_new(struct zlib_istream, 1);
	zstream->eof_offset = (uoff_t)-1;
	zstream->gz = gz;
	zstream->log_errors = log_errors;

	i_stream_zlib_init(zstream);

	zstream->istream.iostream.close = i_stream_zlib_close;
	zstream->istream.max_buffer_size = input->real_stream->max_buffer_size;
	zstream->istream.read = i_stream_zlib_read;
	zstream->istream.seek = i_stream_zlib_seek;
	zstream->istream.sync = i_stream_zlib_sync;

	zstream->istream.istream.readable_fd = FALSE;
	zstream->istream.istream.blocking = input->blocking;
	zstream->istream.istream.seekable = input->seekable;

	return i_stream_create(&zstream->istream, input,
			       i_stream_get_fd(input), 0);
}

struct istream *i_stream_create_gz(struct istream *input, bool log_errors)
{
	return i_stream_create_zlib(input, TRUE, log_errors);
}

struct istream *i_stream_create_deflate(struct istream *input, bool log_errors)
{
	return i_stream_create_zlib(input, FALSE, log_errors);
}
#endif
