/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "message-parser.h"
#include "istream-internal.h"
#include "istream-header-filter.h"

#include <stdlib.h>

struct header_filter_istream {
	struct _istream istream;
	pool_t pool;

	struct istream *input;
	struct message_header_parser_ctx *hdr_ctx;

	const char **headers;
	size_t headers_count;

	header_filter_callback *callback;
	void *context;

	buffer_t *hdr_buf;
	struct message_size header_size;
	uoff_t skip_count;

	unsigned int cur_line, parsed_lines;

	unsigned int header_read:1;
	unsigned int filter:1;
	unsigned int crlf:1;
};

static void _close(struct _iostream *stream __attr_unused__)
{
}

static void _destroy(struct _iostream *stream)
{
	struct header_filter_istream *mstream =
		(struct header_filter_istream *)stream;

	if (mstream->hdr_ctx != NULL)
		message_parse_header_deinit(mstream->hdr_ctx);
	i_stream_unref(mstream->input);
	pool_unref(mstream->pool);
}

static void _set_max_buffer_size(struct _iostream *stream, size_t max_size)
{
	struct header_filter_istream *mstream =
		(struct header_filter_istream *)stream;

	i_stream_set_max_buffer_size(mstream->input, max_size);
}

static ssize_t read_header(struct header_filter_istream *mstream)
{
	struct message_header_line *hdr;
	size_t pos;
	ssize_t ret;
	int matched, hdr_ret;

	if (mstream->header_read &&
	    mstream->istream.istream.v_offset + mstream->istream.pos ==
	    mstream->header_size.virtual_size) {
		/* we don't support mixing headers and body.
		   it shouldn't be needed. */
		return -2;
	}

	if (mstream->hdr_ctx == NULL) {
		mstream->hdr_ctx =
			message_parse_header_init(mstream->input, NULL, FALSE);
	}

	buffer_copy(mstream->hdr_buf, 0,
		    mstream->hdr_buf, mstream->istream.skip, (size_t)-1);

        mstream->istream.pos -= mstream->istream.skip;
	mstream->istream.skip = 0;

	buffer_set_used_size(mstream->hdr_buf, mstream->istream.pos);

	while ((hdr_ret = message_parse_header_next(mstream->hdr_ctx,
						    &hdr)) > 0) {
		mstream->cur_line++;

		if (hdr->eoh) {
			if (mstream->crlf)
				buffer_append(mstream->hdr_buf, "\r\n", 2);
			else
				buffer_append_c(mstream->hdr_buf, '\n');
			break;
		}

		matched = bsearch(hdr->name, mstream->headers,
				  mstream->headers_count,
				  sizeof(*mstream->headers),
				  bsearch_strcasecmp) != NULL;
		if (mstream->cur_line > mstream->parsed_lines &&
		    mstream->callback != NULL) {
                        mstream->parsed_lines = mstream->cur_line;
			mstream->callback(hdr, &matched, mstream->context);
		}

		if (matched == mstream->filter) {
			/* ignore */
		} else {
			if (!hdr->continued) {
				buffer_append(mstream->hdr_buf,
					      hdr->name, hdr->name_len);
				buffer_append(mstream->hdr_buf,
					      hdr->middle, hdr->middle_len);
			}
			buffer_append(mstream->hdr_buf,
				      hdr->value, hdr->value_len);
			if (!hdr->no_newline) {
				if (mstream->crlf) {
					buffer_append(mstream->hdr_buf,
						      "\r\n", 2);
				} else
					buffer_append_c(mstream->hdr_buf, '\n');
			}

			if (mstream->skip_count >= mstream->hdr_buf->used) {
				/* we need more */
				mstream->skip_count -= mstream->hdr_buf->used;
				buffer_set_used_size(mstream->hdr_buf, 0);
			} else {
				if (mstream->skip_count > 0) {
					mstream->istream.skip =
						mstream->skip_count;
					mstream->skip_count = 0;
				}
				break;
			}
		}
	}

	mstream->istream.istream.eof = mstream->input->eof;
	mstream->istream.buffer = buffer_get_data(mstream->hdr_buf, &pos);
	ret = (ssize_t)(pos - mstream->istream.pos - mstream->istream.skip);
	mstream->istream.pos = pos;

	if (hdr_ret == 0)
		return ret;

	if (hdr == NULL) {
		/* finished */
		message_parse_header_deinit(mstream->hdr_ctx);
		mstream->hdr_ctx = NULL;

		if (!mstream->header_read && mstream->callback != NULL)
			mstream->callback(NULL, &matched, mstream->context);
		mstream->header_read = TRUE;

		mstream->header_size.physical_size = mstream->input->v_offset;
		mstream->header_size.virtual_size =
			mstream->istream.istream.v_offset + pos;
	}

	if (ret == 0) {
		i_assert(hdr == NULL);
		i_assert(mstream->istream.istream.v_offset +
			 mstream->istream.pos ==
			 mstream->header_size.virtual_size);
		return -2;
	}

	return ret;
}

static ssize_t _read(struct _istream *stream)
{
	struct header_filter_istream *mstream =
		(struct header_filter_istream *)stream;
	ssize_t ret;
	size_t pos;

	if (!mstream->header_read ||
	    stream->istream.v_offset < mstream->header_size.virtual_size) {
		ret = read_header(mstream);
		if (ret != -2 || stream->pos != stream->skip)
			return ret;
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
		stream->istream.eof = mstream->input->eof;
		stream->buffer = i_stream_get_data(mstream->input, &pos);
	}

	stream->pos -= stream->skip;
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
	stream->skip = stream->pos = 0;
	stream->buffer = NULL;

	if (mstream->hdr_ctx != NULL) {
		message_parse_header_deinit(mstream->hdr_ctx);
		mstream->hdr_ctx = NULL;
	}

	if (v_offset < mstream->header_size.virtual_size) {
		/* seek into headers. we'll have to re-parse them, use
		   skip_count to set the wanted position */
		i_stream_seek(mstream->input, 0);
		mstream->skip_count = v_offset;
		mstream->cur_line = 0;
	} else {
		/* body */
		v_offset += mstream->header_size.physical_size -
			mstream->header_size.virtual_size;
		i_stream_seek(mstream->input, v_offset);
	}
}

struct istream *
i_stream_create_header_filter(struct istream *input, int filter, int crlf,
			      const char *const *headers, size_t headers_count,
			      header_filter_callback *callback, void *context)
{
	struct header_filter_istream *mstream;
	pool_t pool;
	size_t i;

	pool = pool_alloconly_create("header filter stream", 1024);
	mstream = p_new(pool, struct header_filter_istream, 1);
	mstream->pool = pool;

	mstream->input = input;
	i_stream_ref(mstream->input);

	mstream->headers = p_new(pool, const char *, headers_count);
	for (i = 0; i < headers_count; i++) 
		mstream->headers[i] = p_strdup(pool, headers[i]);
	mstream->headers_count = headers_count;
	mstream->hdr_buf = buffer_create_dynamic(pool, 512, (size_t)-1);

	mstream->callback = callback;
	mstream->context = context;
	mstream->filter = filter;
	mstream->crlf = crlf;

	mstream->istream.iostream.close = _close;
	mstream->istream.iostream.destroy = _destroy;
	mstream->istream.iostream.set_max_buffer_size = _set_max_buffer_size;

	mstream->istream.read = _read;
	mstream->istream.seek = _seek;

	return _i_stream_create(&mstream->istream, pool, -1, 0);
}
