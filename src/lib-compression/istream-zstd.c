/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"

#ifdef HAVE_ZSTD

#include "buffer.h"
#include "istream-private.h"
#include "istream-zlib.h"

#include "zstd.h"
#include "zstd_errors.h"

struct zstd_istream {
	struct istream_private istream;

	ZSTD_DStream *dstream;
	ZSTD_inBuffer input;
	ZSTD_outBuffer output;

	struct stat last_parent_statbuf;

	/* ZSTD input size */
	size_t input_size;

	/* storage for frames */
	buffer_t *frame_buffer;

	/* storage for data */
	buffer_t *data_buffer;

	bool log_errors:1;
	bool marked:1;
	bool zs_closed:1;
	/* is there data remaining */
	bool remain:1;
};

static void i_stream_zstd_init(struct zstd_istream *zstream)
{
	zstream->dstream = ZSTD_createDStream();
	if (zstream->dstream == NULL)
		i_fatal_status(FATAL_OUTOFMEM, "zstd: Out of memory");
	ZSTD_initDStream(zstream->dstream);
	zstream->input_size = ZSTD_DStreamInSize();
	if (zstream->frame_buffer == NULL)
		zstream->frame_buffer = buffer_create_dynamic(default_pool, ZSTD_DStreamInSize());
	else
		buffer_set_used_size(zstream->frame_buffer, 0);
	if (zstream->data_buffer == NULL)
		zstream->data_buffer = buffer_create_dynamic(default_pool, ZSTD_DStreamOutSize());
	else
		buffer_set_used_size(zstream->data_buffer, 0);
	zstream->zs_closed = FALSE;
}

static void i_stream_zstd_deinit(struct zstd_istream *zstream, bool reuse_buffers)
{
	(void)ZSTD_freeDStream(zstream->dstream);
	zstream->dstream = NULL;
	if (!reuse_buffers) {
		buffer_free(&zstream->frame_buffer);
		buffer_free(&zstream->data_buffer);
	}
	zstream->zs_closed = TRUE;
	i_zero(&zstream->input);
}

static void i_stream_zstd_close(struct iostream_private *stream,
				bool close_parent)
{
	struct istream_private *_istream =
		container_of(stream, struct istream_private, iostream);
	struct zstd_istream *zstream =
		container_of(_istream, struct zstd_istream, istream);
	if (!zstream->zs_closed)
		i_stream_zstd_deinit(zstream, FALSE);
	buffer_free(&zstream->frame_buffer);
	if (close_parent)
		i_stream_close(zstream->istream.parent);
}

static void i_stream_zstd_error(struct zstd_istream *zstream, const char *error)
{
	io_stream_set_error(&zstream->istream.iostream,
			    "zstd.read(%s): %s at %"PRIuUOFF_T,
			    i_stream_get_name(&zstream->istream.istream), error,
			    i_stream_get_absolute_offset(&zstream->istream.istream));
	zstream->istream.istream.stream_errno = EIO;
	if (zstream->log_errors)
		i_error("%s", zstream->istream.iostream.error);
}

static void i_stream_zstd_read_error(struct zstd_istream *zstream, size_t err)
{
	const char *error = ZSTD_getErrorName(err);
	if (err == ZSTD_error_memory_allocation)
		i_fatal_status(FATAL_OUTOFMEM, "zstd.read(%s): Out of memory",
			       i_stream_get_name(&zstream->istream.istream));

	i_stream_zstd_error(zstream, error);
}

static ssize_t i_stream_zstd_read(struct istream_private *stream)
{
	struct zstd_istream *zstream =
		container_of(stream, struct zstd_istream, istream);
	const unsigned char *data;
	size_t size;
	ssize_t ret;

	if (stream->istream.eof)
		return -1;

	for (;;) {
		if (zstream->data_buffer->used > 0) {
			if (!i_stream_try_alloc(stream, stream->max_buffer_size, &size))
				return -2;
			size = I_MIN(zstream->data_buffer->used, size);
			memcpy(PTR_OFFSET(stream->w_buffer,stream->pos),
			       zstream->data_buffer->data, size);
			stream->pos += size;
			buffer_delete(zstream->data_buffer, 0, size);
			return size;
		}

		/* see if we can get more */
		if (zstream->input.pos == zstream->input.size) {
			buffer_set_used_size(zstream->frame_buffer, 0);
			/* need to read more */
			if ((ret = i_stream_read_more(stream->parent, &data, &size)) < 0) {
				stream->istream.stream_errno =
					stream->parent->stream_errno;
				stream->istream.eof = stream->parent->eof;
				if (zstream->remain &&
				    stream->istream.stream_errno == 0)
					/* truncated data */
					stream->istream.stream_errno = EPIPE;
				return ret;
			}
			if (ret == 0)
				return 0;
			buffer_append(zstream->frame_buffer, data, size);
			i_stream_skip(stream->parent, size);
			zstream->input.src = zstream->frame_buffer->data;
			zstream->input.size = zstream->frame_buffer->used;
			zstream->input.pos = 0;
		}

		i_assert(zstream->input.size > 0);
		i_assert(zstream->data_buffer->used == 0);
		zstream->output.dst = buffer_append_space_unsafe(zstream->data_buffer,
								 ZSTD_DStreamOutSize());
		zstream->output.pos = 0;
		zstream->output.size = ZSTD_DStreamOutSize();

		ret = ZSTD_decompressStream(zstream->dstream, &zstream->output,
					    &zstream->input);

		if (ZSTD_isError(ret) != 0) {
			i_stream_zstd_read_error(zstream, ret);
			return -1;
		}

		zstream->remain = ret > 0;
		buffer_set_used_size(zstream->data_buffer, zstream->output.pos);
	}
	i_unreached();
}

static void i_stream_zstd_reset(struct zstd_istream *zstream)
{
	struct istream_private *stream = &zstream->istream;

	i_stream_seek(stream->parent, stream->parent_start_offset);
	stream->parent_expected_offset = stream->parent_start_offset;
	stream->skip = stream->pos = 0;
	stream->istream.v_offset = 0;
	stream->high_pos = 0;

	i_stream_zstd_deinit(zstream, TRUE);
	i_stream_zstd_init(zstream);
}

static void
i_stream_zstd_seek(struct istream_private *stream, uoff_t v_offset, bool mark)
{
	struct zstd_istream *zstream =
		container_of(stream, struct zstd_istream, istream);

	if (i_stream_nonseekable_try_seek(stream, v_offset))
		return;

	/* have to seek backwards - reset state and retry */
	i_stream_zstd_reset(zstream);
	if (!i_stream_nonseekable_try_seek(stream, v_offset))
		i_unreached();

	if (mark)
		zstream->marked = TRUE;
}

static void i_stream_zstd_sync(struct istream_private *stream)
{
	struct zstd_istream *zstream =
		container_of(stream, struct zstd_istream, istream);
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
	i_stream_zstd_reset(zstream);
}

struct istream *
i_stream_create_zstd(struct istream *input, bool log_errors)
{
	struct zstd_istream *zstream;

	zstream = i_new(struct zstd_istream, 1);
	zstream->log_errors = log_errors;

	i_stream_zstd_init(zstream);

	zstream->istream.iostream.close = i_stream_zstd_close;
	zstream->istream.max_buffer_size = input->real_stream->max_buffer_size;
	zstream->istream.read = i_stream_zstd_read;
	zstream->istream.seek = i_stream_zstd_seek;
	zstream->istream.sync = i_stream_zstd_sync;

	zstream->istream.istream.readable_fd = FALSE;
	zstream->istream.istream.blocking = input->blocking;
	zstream->istream.istream.seekable = input->seekable;

	return i_stream_create(&zstream->istream, input,
			       i_stream_get_fd(input), 0);
}

#endif
