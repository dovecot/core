/* Copyright (C) 2003-2004 Timo Sirainen */

/* FIXME: the header wouldn't necessarily have to be read in memory. we could
   just parse it forward in _read(). */

#include "lib.h"
#include "buffer.h"
#include "message-parser.h"
#include "istream-internal.h"
#include "istream-header-filter.h"

#include <stdlib.h>

struct header_filter_istream {
	struct _istream istream;

	struct istream *input;

	buffer_t *headers;
	struct message_size header_size;
};

static void _close(struct _iostream *stream __attr_unused__)
{
}

static void _destroy(struct _iostream *stream)
{
	struct header_filter_istream *mstream =
		(struct header_filter_istream *)stream;

	i_stream_unref(mstream->input);
	buffer_free(mstream->headers);
}

static void _set_max_buffer_size(struct _iostream *stream, size_t max_size)
{
	struct header_filter_istream *mstream =
		(struct header_filter_istream *)stream;

	i_stream_set_max_buffer_size(mstream->input, max_size);
}

static void _set_blocking(struct _iostream *stream, int timeout_msecs,
			  void (*timeout_cb)(void *), void *context)
{
	struct header_filter_istream *mstream =
		(struct header_filter_istream *)stream;

	i_stream_set_blocking(mstream->input, timeout_msecs,
			      timeout_cb, context);
}

static ssize_t _read(struct _istream *stream)
{
	struct header_filter_istream *mstream =
		(struct header_filter_istream *)stream;
	ssize_t ret;
	size_t pos;

	if (stream->istream.v_offset < mstream->header_size.virtual_size) {
		/* we don't support mixing headers and body.
		   it shouldn't be needed. */
		return -2;
	}

	if (mstream->input->v_offset - mstream->header_size.physical_size !=
	    stream->istream.v_offset - mstream->header_size.virtual_size) {
		i_stream_seek(mstream->input, stream->istream.v_offset -
			      mstream->header_size.virtual_size +
			      mstream->header_size.physical_size);
	}

	stream->buffer = i_stream_get_data(mstream->input, &pos);
	if (pos <= stream->pos) {
		if (i_stream_read(mstream->input) == -2) {
			if (stream->skip == 0)
				return -2;
		}
		stream->istream.disconnected = mstream->input->disconnected;
		stream->buffer = i_stream_get_data(mstream->input, &pos);
	}

	stream->pos -= mstream->istream.skip;
	stream->skip = 0;

	ret = pos <= stream->pos ? -1 :
		(ssize_t) (pos - stream->pos);
	stream->pos = pos;
	return ret;
}

static void _seek(struct _istream *stream, uoff_t v_offset)
{
	struct header_filter_istream *mstream =
		(struct header_filter_istream *)stream;

	stream->istream.v_offset = v_offset;
	if (v_offset < mstream->header_size.virtual_size) {
		/* still in headers */
		stream->skip = v_offset;
		stream->pos = mstream->header_size.virtual_size;
		stream->buffer = buffer_get_data(mstream->headers, NULL);
	} else {
		/* body - use our real input stream */
		stream->skip = stream->pos = 0;
		stream->buffer = NULL;

		v_offset += mstream->header_size.physical_size -
			mstream->header_size.virtual_size;
		i_stream_seek(mstream->input, v_offset);
	}
}

static void read_and_hide_headers(struct istream *input,
				  const char *const *headers,
				  size_t headers_count, buffer_t *dest,
				  struct message_size *hdr_size)
{
	struct message_header_parser_ctx *hdr_ctx;
	struct message_header_line *hdr;
	uoff_t virtual_size = 0;

	hdr_ctx = message_parse_header_init(input, hdr_size, FALSE);
	while ((hdr = message_parse_header_next(hdr_ctx)) != NULL) {
		if (hdr->eoh) {
			if (dest != NULL)
				buffer_append(dest, "\r\n", 2);
			else
				virtual_size += 2;
			break;
		}

		if (bsearch(hdr->name, headers, headers_count,
			    sizeof(*headers), bsearch_strcasecmp) != NULL) {
			/* ignore */
		} else if (dest != NULL) {
			if (!hdr->continued) {
				buffer_append(dest, hdr->name, hdr->name_len);
				buffer_append(dest, ": ", 2);
			}
			buffer_append(dest, hdr->value, hdr->value_len);
			buffer_append(dest, "\r\n", 2);
		} else {
			if (!hdr->continued)
				virtual_size += hdr->name_len + 2;
			virtual_size += hdr->value_len + 2;
		}
	}
	message_parse_header_deinit(hdr_ctx);

	if (dest != NULL)
		virtual_size = buffer_get_used_size(dest);

	hdr_size->virtual_size = virtual_size;
	hdr_size->lines = 0;
}

struct istream *
i_stream_create_header_filter(pool_t pool, struct istream *input,
			      const char *const *headers, size_t headers_count)
{
	struct header_filter_istream *mstream;

	mstream = p_new(pool, struct header_filter_istream, 1);
	mstream->input = input;
	i_stream_ref(mstream->input);

	mstream->headers = buffer_create_dynamic(default_pool,
						 8192, (size_t)-1);
	read_and_hide_headers(input, headers, headers_count, mstream->headers,
			      &mstream->header_size);

	mstream->istream.buffer = buffer_get_data(mstream->headers, NULL);
	mstream->istream.pos = mstream->header_size.virtual_size;

	mstream->istream.iostream.close = _close;
	mstream->istream.iostream.destroy = _destroy;
	mstream->istream.iostream.set_max_buffer_size = _set_max_buffer_size;
	mstream->istream.iostream.set_blocking = _set_blocking;

	mstream->istream.read = _read;
	mstream->istream.seek = _seek;

	return _i_stream_create(&mstream->istream, pool, -1, 0);
}
