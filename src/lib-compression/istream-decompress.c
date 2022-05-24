/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream-private.h"
#include "compression.h"

struct decompress_istream {
	struct istream_private istream;
	struct istream *compressed_input;
	struct istream *decompressed_input;
	enum istream_decompress_flags flags;
};

static void copy_compressed_input_error(struct decompress_istream *zstream)
{
	struct istream_private *stream = &zstream->istream;

	stream->istream.stream_errno = zstream->compressed_input->stream_errno;
	stream->istream.eof = zstream->compressed_input->eof;
	if (zstream->compressed_input->stream_errno != 0) {
		io_stream_set_error(&stream->iostream, "%s",
			i_stream_get_error(&zstream->compressed_input->real_stream->istream));
	}
}

static void copy_decompressed_input_error(struct decompress_istream *zstream)
{
	struct istream_private *stream = &zstream->istream;

	stream->istream.stream_errno = zstream->decompressed_input->stream_errno;
	stream->istream.eof = zstream->decompressed_input->eof;
	if (zstream->decompressed_input->stream_errno != 0) {
		io_stream_set_error(&stream->iostream, "%s",
			i_stream_get_error(&zstream->decompressed_input->real_stream->istream));
	}
}

static void
i_stream_decompress_close(struct iostream_private *_stream, bool close_parent)
{
	struct istream_private *stream =
		container_of(_stream, struct istream_private, iostream);
	struct decompress_istream *zstream =
		container_of(stream, struct decompress_istream, istream);

	if (zstream->decompressed_input != NULL)
		i_stream_close(zstream->decompressed_input);
	if (close_parent)
		i_stream_close(zstream->compressed_input);
}

static void
i_stream_decompress_destroy(struct iostream_private *_stream)
{
	struct istream_private *stream =
		container_of(_stream, struct istream_private, iostream);
	struct decompress_istream *zstream =
		container_of(stream, struct decompress_istream, istream);

	i_stream_unref(&zstream->decompressed_input);
	i_stream_unref(&zstream->compressed_input);
}

static int
i_stream_decompress_not_compressed(struct decompress_istream *zstream)
{
	if ((zstream->flags & ISTREAM_DECOMPRESS_FLAG_TRY) == 0) {
		zstream->istream.istream.stream_errno = EINVAL;
		io_stream_set_error(&zstream->istream.iostream,
				    "Stream isn't compressed");
		return -1;
	} else {
		zstream->decompressed_input = zstream->compressed_input;
		i_stream_ref(zstream->decompressed_input);
		return 1;
	}
}

static int i_stream_decompress_detect(struct decompress_istream *zstream)
{
	const struct compression_handler *handler;
	ssize_t ret;

	ret = i_stream_read(zstream->compressed_input);
	handler = compression_detect_handler(zstream->compressed_input);
	if (handler == NULL) {
		switch (ret) {
		case -1:
			if (zstream->compressed_input->stream_errno != 0) {
				copy_compressed_input_error(zstream);
				return -1;
			}
			/* fall through */
		case -2:
			/* we've read a full buffer or we reached EOF -
			   the stream isn't compressed */
			return i_stream_decompress_not_compressed(zstream);
		case 0:
			return 0;
		default:
			if (!zstream->istream.istream.blocking)
				return 0;
			return i_stream_decompress_detect(zstream);
		}
	}
	if (handler->create_istream == NULL) {
		zstream->istream.istream.stream_errno = EINVAL;
		io_stream_set_error(&zstream->istream.iostream,
			"Compression handler %s not supported", handler->name);
		return -1;
	}

	zstream->decompressed_input =
		handler->create_istream(zstream->compressed_input);
	return 1;
}

static ssize_t i_stream_decompress_read(struct istream_private *stream)
{
	struct decompress_istream *zstream =
		container_of(stream, struct decompress_istream, istream);
	ssize_t ret;
	size_t pos;

	if (zstream->decompressed_input == NULL) {
		if ((ret = i_stream_decompress_detect(zstream)) <= 0)
			return ret;
	}

	i_stream_seek(zstream->decompressed_input, stream->istream.v_offset);
	stream->pos -= stream->skip;
	stream->skip = 0;

	stream->buffer = i_stream_get_data(zstream->decompressed_input, &pos);
	if (pos > stream->pos)
		ret = 0;
	else do {
		ret = i_stream_read_memarea(zstream->decompressed_input);
		copy_decompressed_input_error(zstream);
		stream->buffer = i_stream_get_data(zstream->decompressed_input,
						   &pos);
	} while (pos <= stream->pos && ret > 0);
	if (ret == -2)
		return -2;

	if (pos <= stream->pos)
		ret = ret == 0 ? 0 : -1;
	else
		ret = (ssize_t)(pos - stream->pos);
	stream->pos = pos;
	i_assert(ret != -1 || stream->istream.eof ||
		 stream->istream.stream_errno != 0);
	return ret;
}

static void i_stream_decompress_reset(struct istream_private *stream)
{
	stream->skip = stream->pos = 0;
	stream->istream.v_offset = 0;
	stream->istream.eof = FALSE;
}

static void
i_stream_decompress_seek(struct istream_private *stream,
			 uoff_t v_offset, bool mark)
{
	struct decompress_istream *zstream =
		container_of(stream, struct decompress_istream, istream);

	if (zstream->decompressed_input == NULL) {
		if (!i_stream_nonseekable_try_seek(stream, v_offset))
			i_panic("seeking backwards before detecting compression format");
	} else {
		i_stream_decompress_reset(stream);
		stream->istream.v_offset = v_offset;
		if (mark)
			i_stream_seek_mark(zstream->decompressed_input, v_offset);
		else
			i_stream_seek(zstream->decompressed_input, v_offset);
		copy_decompressed_input_error(zstream);
	}
}

static void i_stream_decompress_sync(struct istream_private *stream)
{
	struct decompress_istream *zstream =
		container_of(stream, struct decompress_istream, istream);

	i_stream_decompress_reset(stream);
	if (zstream->decompressed_input != NULL)
		i_stream_sync(zstream->decompressed_input);
}

static int i_stream_decompress_stat(struct istream_private *stream, bool exact)
{
	struct decompress_istream *zstream =
		container_of(stream, struct decompress_istream, istream);
	const struct stat *st;

	if (!exact) {
		if (i_stream_stat(zstream->compressed_input, exact, &st) < 0) {
			copy_compressed_input_error(zstream);
			return -1;
		}
		stream->statbuf = *st;
		return 0;
	}
	if (zstream->decompressed_input == NULL) {
		(void)i_stream_read(&stream->istream);
		if (zstream->decompressed_input == NULL) {
			if (stream->istream.stream_errno == 0) {
				zstream->istream.istream.stream_errno = EINVAL;
				io_stream_set_error(&zstream->istream.iostream,
					"Stream compression couldn't be detected during stat");
			}
			return -1;
		}
	}

	if (i_stream_stat(zstream->decompressed_input, exact, &st) < 0) {
		copy_decompressed_input_error(zstream);
		return -1;
	}
	i_stream_decompress_reset(stream);
	stream->statbuf = *st;
	return 0;
}

struct istream *
i_stream_create_decompress(struct istream *input,
			   enum istream_decompress_flags flags)
{
	struct decompress_istream *zstream;

	zstream = i_new(struct decompress_istream, 1);
	zstream->compressed_input = input;
	zstream->flags = flags;
	i_stream_ref(input);

	zstream->istream.iostream.close = i_stream_decompress_close;
	zstream->istream.iostream.destroy = i_stream_decompress_destroy;
	zstream->istream.max_buffer_size = input->real_stream->max_buffer_size;
	zstream->istream.read = i_stream_decompress_read;
	zstream->istream.seek = i_stream_decompress_seek;
	zstream->istream.sync = i_stream_decompress_sync;
	zstream->istream.stat = i_stream_decompress_stat;

	zstream->istream.istream.readable_fd = FALSE;
	zstream->istream.istream.blocking = input->blocking;
	zstream->istream.istream.seekable = input->seekable;

	struct istream *ret = i_stream_create(&zstream->istream, NULL,
					      i_stream_get_fd(input), 0);
	/* input isn't used as our parent istream, so need to copy the stream
	   name to preserve it. */
	i_stream_set_name(ret, i_stream_get_name(input));
	return ret;
}
