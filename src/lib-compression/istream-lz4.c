/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"

#ifdef HAVE_LZ4

#include "buffer.h"
#include "istream-private.h"
#include "istream-zlib.h"
#include "iostream-lz4.h"
#include <lz4.h>

struct lz4_istream {
	struct istream_private istream;

	struct stat last_parent_statbuf;

	buffer_t *chunk_buf;
	uint32_t chunk_size, chunk_left, max_uncompressed_chunk_size;

	bool log_errors:1;
	bool marked:1;
	bool header_read:1;
};

static void i_stream_lz4_close(struct iostream_private *stream,
			       bool close_parent)
{
	struct lz4_istream *zstream = (struct lz4_istream *)stream;

	buffer_free(&zstream->chunk_buf);
	if (close_parent)
		i_stream_close(zstream->istream.parent);
}

static void lz4_read_error(struct lz4_istream *zstream, const char *error)
{
	io_stream_set_error(&zstream->istream.iostream,
			    "lz4.read(%s): %s at %"PRIuUOFF_T,
			    i_stream_get_name(&zstream->istream.istream), error,
			    i_stream_get_absolute_offset(&zstream->istream.istream));
	if (zstream->log_errors)
		i_error("%s", zstream->istream.iostream.error);
}

static int i_stream_lz4_read_header(struct lz4_istream *zstream)
{
	const struct iostream_lz4_header *hdr;
	const unsigned char *data;
	size_t size;
	int ret;

	ret = i_stream_read_more(zstream->istream.parent, &data, &size);
	size = I_MIN(size, sizeof(*hdr));
	buffer_append(zstream->chunk_buf, data, size);
	i_stream_skip(zstream->istream.parent, size);
	if (ret < 0) {
		if (zstream->istream.istream.stream_errno == 0) {
			lz4_read_error(zstream, "missing header (not lz4 file?)");
			zstream->istream.istream.stream_errno = EINVAL;
		} else
			zstream->istream.istream.stream_errno =
				zstream->istream.parent->stream_errno;
		return ret;
	}
	if (ret == 0 && !zstream->istream.istream.eof)
		return 0;
	if (zstream->chunk_buf->used < sizeof(*hdr))
		return 0;

	hdr = zstream->chunk_buf->data;
	if (ret == 0 || memcmp(hdr->magic, IOSTREAM_LZ4_MAGIC,
			       IOSTREAM_LZ4_MAGIC_LEN) != 0) {
		lz4_read_error(zstream, "wrong magic in header (not lz4 file?)");
		zstream->istream.istream.stream_errno = EINVAL;
		return -1;
	}
	zstream->max_uncompressed_chunk_size =
		be32_to_cpu_unaligned(hdr->max_uncompressed_chunk_size);
	buffer_set_used_size(zstream->chunk_buf, 0);
	if (zstream->max_uncompressed_chunk_size > ISTREAM_LZ4_CHUNK_SIZE) {
		lz4_read_error(zstream, t_strdup_printf(
			"lz4 max chunk size too large (%u > %u)",
			zstream->max_uncompressed_chunk_size,
			ISTREAM_LZ4_CHUNK_SIZE));
		zstream->istream.istream.stream_errno = EINVAL;
		return -1;
	}
	return 1;
}

static int i_stream_lz4_read_chunk_header(struct lz4_istream *zstream)
{
	int ret;
	size_t size;
	const unsigned char *data;
	struct istream_private *stream = &zstream->istream;

	i_assert(zstream->chunk_buf->used <= IOSTREAM_LZ4_CHUNK_PREFIX_LEN);
	ret = i_stream_read_more(stream->parent, &data, &size);
	size = I_MIN(size, IOSTREAM_LZ4_CHUNK_PREFIX_LEN - zstream->chunk_buf->used);
	buffer_append(zstream->chunk_buf, data, size);
	i_stream_skip(stream->parent, size);
	if (ret < 0) {
		stream->istream.stream_errno = stream->parent->stream_errno;
		if (stream->istream.stream_errno == 0) {
			stream->istream.eof = TRUE;
			stream->cached_stream_size =
				stream->istream.v_offset +
				stream->pos - stream->skip;
		}
		return ret;
	}
	i_assert(ret != 0 || !stream->istream.blocking);
	if (ret == 0)
		return ret;
	if (zstream->chunk_buf->used < IOSTREAM_LZ4_CHUNK_PREFIX_LEN)
		return 0;
	zstream->chunk_size = zstream->chunk_left =
		be32_to_cpu_unaligned(zstream->chunk_buf->data);
	if (zstream->chunk_size == 0 ||
	    zstream->chunk_size > ISTREAM_LZ4_CHUNK_SIZE) {
		lz4_read_error(zstream, t_strdup_printf(
			"invalid lz4 chunk size: %u", zstream->chunk_size));
		stream->istream.stream_errno = EINVAL;
		return -1;
	}
	buffer_set_used_size(zstream->chunk_buf, 0);
	return 1;
}

static ssize_t i_stream_lz4_read(struct istream_private *stream)
{
	struct lz4_istream *zstream = (struct lz4_istream *)stream;
	const unsigned char *data;
	size_t size;
	int ret;

	/* if we already have max_buffer_size amount of data, fail here */
	if (stream->pos - stream->skip >= i_stream_get_max_buffer_size(&stream->istream))
		return -2;

	if (!zstream->header_read) {
		if ((ret = i_stream_lz4_read_header(zstream)) <= 0) {
			stream->istream.eof = TRUE;
			return ret;
		}
		zstream->header_read = TRUE;
	}

	if (zstream->chunk_left == 0) {
		while ((ret = i_stream_lz4_read_chunk_header(zstream)) == 0) {
			if (ret == 0 && !stream->istream.blocking)
				return 0;
		}
		if (ret < 0)
			return ret;
	}

	/* read the whole compressed chunk into memory */
	while (zstream->chunk_left > 0 &&
	       (ret = i_stream_read_more(zstream->istream.parent, &data, &size)) > 0) {
		if (size > zstream->chunk_left)
			size = zstream->chunk_left;
		buffer_append(zstream->chunk_buf, data, size);
		i_stream_skip(zstream->istream.parent, size);
		zstream->chunk_left -= size;
	}
	if (zstream->chunk_left > 0) {
		if (ret == -1 && zstream->istream.parent->stream_errno == 0) {
			lz4_read_error(zstream, "truncated lz4 chunk");
			stream->istream.stream_errno = EPIPE;
			return -1;
		}
		zstream->istream.istream.stream_errno =
			zstream->istream.parent->stream_errno;
		i_assert(ret != 0 || !stream->istream.blocking);
		return ret;
	}
	/* if we already have max_buffer_size amount of data, fail here */
	if (stream->pos - stream->skip >= i_stream_get_max_buffer_size(&stream->istream))
		return -2;
	/* allocate enough space for the old data and the new
	   decompressed chunk. we don't know the original compressed size,
	   so just allocate the max amount of memory. */
	void *dest = i_stream_alloc(stream, zstream->max_uncompressed_chunk_size);
	ret = LZ4_decompress_safe(zstream->chunk_buf->data, dest,
				  zstream->chunk_buf->used,
				  zstream->max_uncompressed_chunk_size);
	i_assert(ret <= (int)zstream->max_uncompressed_chunk_size);
	if (ret < 0) {
		lz4_read_error(zstream, "corrupted lz4 chunk");
		stream->istream.stream_errno = EINVAL;
		return -1;
	}
	i_assert(ret > 0);
	stream->pos += ret;
	i_assert(stream->pos <= stream->buffer_size);

	/* we are going to get next chunk after this, so reset here
	   so we can reuse the chunk buf for reading next buffer prefix */
	if (zstream->chunk_left == 0)
		buffer_set_used_size(zstream->chunk_buf, 0);

	return ret;
}

static void i_stream_lz4_reset(struct lz4_istream *zstream)
{
	struct istream_private *stream = &zstream->istream;

	i_stream_seek(stream->parent, stream->parent_start_offset);
	zstream->header_read = FALSE;
	zstream->chunk_size = zstream->chunk_left = 0;

	stream->parent_expected_offset = stream->parent_start_offset;
	stream->skip = stream->pos = 0;
	stream->istream.v_offset = 0;
	buffer_set_used_size(zstream->chunk_buf, 0);
}

static void
i_stream_lz4_seek(struct istream_private *stream, uoff_t v_offset, bool mark)
{
	struct lz4_istream *zstream = (struct lz4_istream *) stream;

	if (i_stream_nonseekable_try_seek(stream, v_offset))
		return;

	/* have to seek backwards - reset state and retry */
	i_stream_lz4_reset(zstream);
	if (!i_stream_nonseekable_try_seek(stream, v_offset))
		i_unreached();

	if (mark)
		zstream->marked = TRUE;
}

static void i_stream_lz4_sync(struct istream_private *stream)
{
	struct lz4_istream *zstream = (struct lz4_istream *) stream;
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
	i_stream_lz4_reset(zstream);
}

struct istream *i_stream_create_lz4(struct istream *input, bool log_errors)
{
	struct lz4_istream *zstream;

	zstream = i_new(struct lz4_istream, 1);
	zstream->log_errors = log_errors;

	zstream->istream.iostream.close = i_stream_lz4_close;
	zstream->istream.max_buffer_size = input->real_stream->max_buffer_size;
	zstream->istream.read = i_stream_lz4_read;
	zstream->istream.seek = i_stream_lz4_seek;
	zstream->istream.sync = i_stream_lz4_sync;

	zstream->istream.istream.readable_fd = FALSE;
	zstream->istream.istream.blocking = input->blocking;
	zstream->istream.istream.seekable = input->seekable;
	zstream->chunk_buf = buffer_create_dynamic(default_pool, 1024);

	return i_stream_create(&zstream->istream, input,
			       i_stream_get_fd(input), 0);
}
#endif
