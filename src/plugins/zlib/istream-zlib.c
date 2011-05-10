/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"

#ifdef HAVE_ZLIB

#include "crc32.h"
#include "istream-internal.h"
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
	size_t prev_size, high_pos;
	uint32_t crc32;
	struct stat last_parent_statbuf;

	unsigned int gz:1;
	unsigned int log_errors:1;
	unsigned int marked:1;
	unsigned int header_read:1;
	unsigned int trailer_read:1;
	unsigned int zs_closed:1;
};

static void i_stream_zlib_close(struct iostream_private *stream)
{
	struct zlib_istream *zstream = (struct zlib_istream *)stream;

	if (!zstream->zs_closed) {
		(void)inflateEnd(&zstream->zs);
		zstream->zs_closed = TRUE;
	}
}

static void zlib_read_error(struct zlib_istream *zstream, const char *error)
{
	i_error("zlib.read(%s): %s at %"PRIuUOFF_T,
		i_stream_get_name(&zstream->istream.istream), error,
		zstream->istream.abs_start_offset +
		zstream->istream.istream.v_offset);
}

static int i_stream_zlib_read_header(struct istream_private *stream)
{
	struct zlib_istream *zstream = (struct zlib_istream *)stream;
	const unsigned char *data;
	size_t size;
	unsigned int pos, fextra_size;
	int ret;

	ret = i_stream_read_data(stream->parent, &data, &size,
				 zstream->prev_size);
	if (size == zstream->prev_size) {
		if (ret == -1) {
			if (zstream->log_errors)
				zlib_read_error(zstream, "missing gz header");
			stream->istream.stream_errno = EINVAL;
		}
		return ret;
	}
	zstream->prev_size = size;

	if (size < GZ_HEADER_MIN_SIZE)
		return 0;
	pos = GZ_HEADER_MIN_SIZE;

	if (data[0] != GZ_MAGIC1 || data[1] != GZ_MAGIC2) {
		/* missing gzip magic header */
		if (zstream->log_errors) {
			zlib_read_error(zstream, "wrong magic in header "
					"(not gz file?)");
		}
		stream->istream.stream_errno = EINVAL;
		return -1;
	}
	if ((data[3] & GZ_FLAG_FEXTRA) != 0) {
		if (pos + 2 < size)
			return 0;

		fextra_size = data[pos] + (data[pos+1] << 8);
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
	return 1;
}

static uint32_t data_get_uint32(const unsigned char *data)
{
	return data[0] | (data[1] << 8) | (data[2] << 16) |
		((uint32_t)data[3] << 24);
}

static int i_stream_zlib_read_trailer(struct zlib_istream *zstream)
{
	struct istream_private *stream = &zstream->istream;
	const unsigned char *data;
	size_t size;
	int ret;

	ret = i_stream_read_data(stream->parent, &data, &size,
				 GZ_TRAILER_SIZE-1);
	if (size == zstream->prev_size) {
		if (ret == -1) {
			if (zstream->log_errors)
				zlib_read_error(zstream, "missing gz trailer");
			stream->istream.stream_errno = EINVAL;
		}
		return ret;
	}
	zstream->prev_size = size;

	if (size < GZ_TRAILER_SIZE)
		return 0;

	if (data_get_uint32(data) != zstream->crc32) {
		if (zstream->log_errors) {
			zlib_read_error(zstream,
					"gz trailer has wrong CRC value");
		}
		stream->istream.stream_errno = EINVAL;
		return -1;
	}
	i_stream_skip(stream->parent, GZ_TRAILER_SIZE);
	zstream->trailer_read = TRUE;
	return 1;
}

static ssize_t i_stream_zlib_read(struct istream_private *stream)
{
	struct zlib_istream *zstream = (struct zlib_istream *)stream;
	const unsigned char *data;
	uoff_t high_offset;
	size_t size;
	int ret;

	high_offset = stream->istream.v_offset + (stream->pos - stream->skip);
	if (zstream->eof_offset == high_offset) {
		i_assert(zstream->high_pos == 0 ||
			 zstream->high_pos == stream->pos);
		if (!zstream->trailer_read) {
			do {
				ret = i_stream_zlib_read_trailer(zstream);
			} while (ret == 0 && stream->istream.blocking);
			if (ret <= 0)
				return ret;
		}
		stream->istream.eof = TRUE;
		return -1;
	}

	if (!zstream->header_read) {
		i_assert(zstream->high_pos == 0);
		do {
			ret = i_stream_zlib_read_header(stream);
		} while (ret == 0 && stream->istream.blocking);
		if (ret <= 0)
			return ret;
		zstream->header_read = TRUE;
		zstream->prev_size = 0;
	}

	if (stream->pos < zstream->high_pos) {
		/* we're here because we seeked back within the read buffer. */
		ret = zstream->high_pos - stream->pos;
		stream->pos = zstream->high_pos;
		zstream->high_pos = 0;
		if (zstream->trailer_read) {
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
					zlib_read_error(zstream,
							"unexpected EOF");
				}
				stream->istream.stream_errno = EPIPE;
			}
			return -1;
		}
		zstream->prev_size = size;
		if (size == 0) {
			/* no more input */
			i_assert(!stream->istream.blocking);
			return 0;
		}

		zstream->zs.next_in = (void *)data;
		zstream->zs.avail_in = size;
	}

	size = stream->buffer_size - stream->pos;
	zstream->zs.next_out = stream->w_buffer + stream->pos;
	zstream->zs.avail_out = size;
	ret = inflate(&zstream->zs, Z_SYNC_FLUSH);

	size -= zstream->zs.avail_out;
	zstream->crc32 = crc32_data_more(zstream->crc32,
					 stream->w_buffer + stream->pos, size);
	stream->pos += size;

	switch (ret) {
	case Z_OK:
		break;
	case Z_NEED_DICT:
		if (zstream->log_errors)
			zlib_read_error(zstream, "can't read file without dict");
		stream->istream.stream_errno = EINVAL;
		return -1;
	case Z_DATA_ERROR:
		if (zstream->log_errors)
			zlib_read_error(zstream, "corrupted data");
		stream->istream.stream_errno = EINVAL;
		return -1;
	case Z_MEM_ERROR:
		i_fatal_status(FATAL_OUTOFMEM, "zlib.read(%s): Out of memory",
			       i_stream_get_name(&stream->istream));
	case Z_STREAM_END:
		zstream->eof_offset = stream->istream.v_offset +
			(stream->pos - stream->skip);
		i_stream_skip(stream->parent,
			      zstream->prev_size - zstream->zs.avail_in);
		zstream->zs.avail_in = 0;
		zstream->prev_size = 0;

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
	if (size == 0) {
		/* read more input */
		return i_stream_zlib_read(stream);
	}
	return size;
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
	zstream->high_pos = 0;
	zstream->prev_size = 0;

	(void)inflateEnd(&zstream->zs);
	i_stream_zlib_init(zstream);
}

static void
i_stream_zlib_seek(struct istream_private *stream, uoff_t v_offset, bool mark)
{
	struct zlib_istream *zstream = (struct zlib_istream *) stream;
	uoff_t start_offset = stream->istream.v_offset - stream->skip;

	if (v_offset < start_offset) {
		/* have to seek backwards */
		i_stream_zlib_reset(zstream);
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
				i_error("zlib_istream.seek(%s) failed: %s",
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
i_stream_zlib_stat(struct istream_private *stream, bool exact)
{
	struct zlib_istream *zstream = (struct zlib_istream *) stream;
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

static void i_stream_zlib_sync(struct istream_private *stream)
{
	struct zlib_istream *zstream = (struct zlib_istream *) stream;
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
	zstream->istream.stat = i_stream_zlib_stat;
	zstream->istream.sync = i_stream_zlib_sync;

	zstream->istream.istream.readable_fd = FALSE;
	zstream->istream.istream.blocking = input->blocking;
	zstream->istream.istream.seekable = input->seekable;

	return i_stream_create(&zstream->istream, input,
			       i_stream_get_fd(input));
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
