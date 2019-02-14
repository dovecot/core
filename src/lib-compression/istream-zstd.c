/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"

#ifdef HAVE_ZSTD

#include "buffer.h"
#include "istream-private.h"
#include "istream-zlib.h"
#include <zstd.h>

struct zstd_istream {
	struct istream_private istream;
	ZSTD_DStream *dstream;

	struct stat last_parent_statbuf;
	ZSTD_inBuffer input;
	size_t input_true_size;
	ZSTD_outBuffer output;
	size_t next_read;
	ssize_t buffer_size;
	bool marked : 1;
	bool log_errors : 1;
};

static void i_stream_zstd_close(struct iostream_private *stream,
				bool close_parent)
{
	struct zstd_istream *zstream = (struct zstd_istream *)stream;

	ZSTD_freeDStream(zstream->dstream);
	zstream->dstream = NULL;

	i_free(zstream->input.src);
	i_free(zstream->output.dst);
	if (close_parent)
		i_stream_close(zstream->istream.parent);
}

static size_t i_stream_zstd_decompress(struct zstd_istream *zstream)
{
	struct istream_private *stream = (struct istream_private *)zstream;
	const unsigned char *data;
	size_t size;

	if (zstream->next_read || !stream->istream.eof) {
		// move everything to back of buffer
		memmove(zstream->input.src,
			(void *)((long)zstream->input.src + zstream->input.pos),
			zstream->input.size - zstream->input.pos);
		// we have zstream->input.pos free bytes
		while (zstream->input.pos) {
			// lets fill input buffer
			if (i_stream_read_more(stream->parent, &data, &size) <
			    0) {
				if (stream->parent->stream_errno != 0) {
					stream->istream.stream_errno =
						stream->parent->stream_errno;
				}
				else {
					i_assert(stream->parent->eof);
					zstream->input.size -=
						zstream->input.pos;
					zstream->input.pos = 0;
					break;
				}
				return -1;
			}
			if (size == 0) {
				break;
			}
			if (size > zstream->input.pos) {
				size = zstream->input.pos;
			}
			memcpy((void *)((long)zstream->input.src +
					zstream->input.size -
					zstream->input.pos),
			       data, size);
			zstream->input.pos -= size;
			i_stream_skip(stream->parent, size);
		}
	}

	size_t to_read = ZSTD_decompressStream(
		zstream->dstream, &zstream->output, &zstream->input);

	if (ZSTD_isError(to_read)) {
		return to_read;
		// i_fatal("ZSTD_decompressStream():
		// %s",ZSTD_getErrorName(to_read));
	}
	zstream->next_read = to_read;
}

static ssize_t i_stream_zstd_read(struct istream_private *stream)
{
	struct zstd_istream *zstream = (struct zstd_istream *)stream;
	size_t error_code, buffer_size = 1;

	if (zstream->output.pos == 0) {
		if ((error_code = i_stream_zstd_decompress(zstream)) != 0) {
			io_stream_set_error(
				&zstream->istream.iostream,
				"zstd.read(%s): %s at %" PRIuUOFF_T,
				i_stream_get_name(&zstream->istream.istream),
				ZSTD_getErrorName(error_code),
				i_stream_get_absolute_offset(
					&zstream->istream.istream));
			if (zstream->log_errors) {
				i_error("%s", zstream->istream.iostream.error);
			}
		}
		if (zstream->output.pos == 0) {
			stream->istream.eof = TRUE;
			return -1;
		}
	}

	if (!zstream->marked) {
		if (!i_stream_try_alloc(stream, zstream->output.pos,
					&buffer_size)) {
			// TODO: return or i_fatal
			return -2;
		}
	}
	else {
		if (!i_stream_try_alloc_avoid_compress(
			    stream, zstream->output.pos, &buffer_size)) {
			return -2;
		}
	}
	// check if we need more data?
	if (zstream->output.pos < buffer_size) {
		buffer_size = zstream->output.pos;
	}
	// copy that mem
	memcpy(stream->w_buffer + stream->pos, zstream->output.dst,
	       buffer_size);
	stream->pos += buffer_size;

	zstream->output.pos -= buffer_size;
	memmove(zstream->output.dst,
		(void *)((long)zstream->output.dst + buffer_size),
		zstream->output.pos);

	return buffer_size;
}

static void i_stream_zstd_reset(struct zstd_istream *zstream)
{
	struct istream_private *stream = &zstream->istream;

	i_stream_seek(stream->parent, stream->parent_start_offset);

	stream->parent_expected_offset = stream->parent_start_offset;
	stream->skip = stream->pos = 0;
	stream->istream.v_offset = 0;

	zstream->output.pos = 0;
	zstream->input.size = zstream->input_true_size;
	zstream->input.pos = zstream->input.size;

	zstream->next_read = ZSTD_initDStream(zstream->dstream);

	if (ZSTD_isError(zstream->next_read))
		i_fatal("ZSTD_initDStream(): %s",
			ZSTD_getErrorName(zstream->next_read));
}

static void i_stream_zstd_seek(struct istream_private *stream, uoff_t v_offset,
			       bool mark)
{
	struct zstd_istream *zstream = (struct zstd_istream *)stream;

	if (i_stream_nonseekable_try_seek(stream, v_offset))
		return;

	i_stream_zstd_reset(zstream);
	if (!i_stream_nonseekable_try_seek(stream, v_offset))
		i_unreached();

	if (mark)
		zstream->marked = TRUE;
}

static void i_stream_zstd_sync(struct istream_private *stream)
{
	struct zstd_istream *zstream = (struct zstd_istream *)stream;
	const struct stat *st;

	if (i_stream_stat(stream->parent, FALSE, &st) < 0) {
		if (memcmp(&zstream->last_parent_statbuf, st, sizeof(*st)) ==
		    0) {
			return;
		}
		zstream->last_parent_statbuf = *st;
	}
	i_stream_zstd_reset(zstream);
}

struct istream *i_stream_create_zstd(struct istream *input, bool log_errors)
{
	struct zstd_istream *zstream;
	zstream = i_new(struct zstd_istream, 1);

	zstream->output.size = ZSTD_DStreamOutSize();
	zstream->output.dst = i_malloc(zstream->output.size);
	zstream->output.pos = 0;

	zstream->input.size = ZSTD_DStreamInSize();
	zstream->input.src = i_malloc(zstream->input.size);
	zstream->input.pos = zstream->input.size;
	zstream->input_true_size = zstream->input.size;

	zstream->dstream = ZSTD_createDStream();
	if (zstream->dstream == NULL)
		i_fatal("ZSTD_createDStream(): failed to create dstream.");

	zstream->next_read = ZSTD_initDStream(zstream->dstream);

	if (ZSTD_isError(zstream->next_read))
		i_fatal("ZSTD_initDStream(): %s",
			ZSTD_getErrorName(zstream->next_read));
	zstream->log_errors = log_errors;
	zstream->istream.iostream.close = i_stream_zstd_close;
	zstream->istream.max_buffer_size = input->real_stream->max_buffer_size;
	zstream->istream.read = i_stream_zstd_read;
	zstream->istream.seek = i_stream_zstd_seek;
	zstream->istream.sync = i_stream_zstd_sync;

	zstream->istream.istream.readable_fd = FALSE;
	zstream->istream.istream.blocking = input->blocking;
	zstream->istream.istream.seekable = input->seekable;

	return i_stream_create(&zstream->istream, input, i_stream_get_fd(input),
			       0);
}
#endif
