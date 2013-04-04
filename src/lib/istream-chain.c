/* Copyright (c) 2003-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "llist.h"
#include "istream-private.h"
#include "istream-chain.h"

struct chain_istream;

struct istream_chain_link {
	struct istream_chain_link *prev, *next;

	struct istream *stream;
	bool eof;
};

struct istream_chain {
	struct istream_chain_link *head, *tail;

	struct chain_istream *stream;
};

struct chain_istream {
	struct istream_private istream;

	size_t prev_stream_left, prev_skip;
	
	struct istream_chain chain;
};

static void ATTR_NULL(2)
i_stream_chain_append_internal(struct istream_chain *chain,
			       struct istream *stream)
{
	struct istream_chain_link *link;

	if (stream == NULL && chain->tail != NULL && chain->tail->stream == NULL)
		return;

	link = i_new(struct istream_chain_link, 1);
	link->stream = stream;
	link->eof = stream == NULL;

	if (stream != NULL)
		i_stream_ref(stream);	

	if (chain->head == NULL && stream != NULL) {
		if (chain->stream->istream.max_buffer_size == 0) {
			chain->stream->istream.max_buffer_size =
				stream->real_stream->max_buffer_size;
		} else {
			i_stream_set_max_buffer_size(stream,
				chain->stream->istream.max_buffer_size);
		}
	}
	DLLIST2_APPEND(&chain->head, &chain->tail, link);
}

void i_stream_chain_append(struct istream_chain *chain, struct istream *stream)
{
	i_stream_chain_append_internal(chain, stream);
}

void i_stream_chain_append_eof(struct istream_chain *chain)
{
	i_stream_chain_append_internal(chain, NULL);
}

static void
i_stream_chain_set_max_buffer_size(struct iostream_private *stream,
				    size_t max_size)
{
	struct chain_istream *cstream = (struct chain_istream *)stream;
	struct istream_chain_link *link = cstream->chain.head;

	cstream->istream.max_buffer_size = max_size;
	while (link != NULL) {
		if (link->stream != NULL)
			i_stream_set_max_buffer_size(link->stream, max_size);
		link = link->next;
	}
}

static void i_stream_chain_destroy(struct iostream_private *stream)
{
	struct chain_istream *cstream = (struct chain_istream *)stream;
	struct istream_chain_link *link = cstream->chain.head;

	while (link != NULL) {
		struct istream_chain_link *next = link->next;

		if (link->stream != NULL)
			i_stream_unref(&link->stream);
		i_free(link);
		link = next;
	}
	i_free(cstream->istream.w_buffer);
}

static void i_stream_chain_read_next(struct chain_istream *cstream)
{
	struct istream_chain_link *link = cstream->chain.head;
	struct istream *prev_input;
	const unsigned char *data;
	size_t data_size, size, cur_data_pos;

	i_assert(link != NULL && link->stream != NULL);
	i_assert(link->stream->eof);

	prev_input = link->stream;
	data = i_stream_get_data(prev_input, &data_size);

	DLLIST2_REMOVE(&cstream->chain.head, &cstream->chain.tail, link);
	i_free(link);

	/* a) we have more streams, b) we have EOF, c) we need to wait
	   for more streams */
	link = cstream->chain.head;
	if (link != NULL && link->stream != NULL)
		i_stream_seek(link->stream, 0);

	if (cstream->prev_stream_left > 0) {
		/* we've already buffered some of the prev_input. continue
		   appending the rest to it. */
		cur_data_pos = cstream->istream.pos -
			(cstream->istream.skip + cstream->prev_stream_left);
		i_assert(cur_data_pos <= data_size);
		data += cur_data_pos;
		data_size -= cur_data_pos;
	} else {
		cstream->istream.pos = 0;
		cstream->istream.skip = 0;
		cstream->prev_stream_left = 0;
	}

	/* we already verified that the data size is less than the
	   maximum buffer size */
	if (data_size > 0) {
		if (!i_stream_try_alloc(&cstream->istream, data_size, &size))
			i_unreached();
		i_assert(size >= data_size);
	}
	memcpy(cstream->istream.w_buffer + cstream->istream.pos,
	       data, data_size);
	cstream->istream.pos += data_size;
	cstream->prev_stream_left += data_size;

	i_stream_skip(prev_input, i_stream_get_data_size(prev_input));
	i_stream_unref(&prev_input);
}

static ssize_t i_stream_chain_read(struct istream_private *stream)
{
	struct chain_istream *cstream = (struct chain_istream *)stream;
	struct istream_chain_link *link = cstream->chain.head;
	const unsigned char *data;
	size_t size, data_size, cur_data_pos, new_pos, bytes_skipped;
	size_t new_bytes_count;
	ssize_t ret;

	if (link != NULL && link->eof) {
		stream->istream.eof = TRUE;
		return -1;
	}

	i_assert(stream->skip >= cstream->prev_skip);
	bytes_skipped = stream->skip - cstream->prev_skip;

	if (cstream->prev_stream_left == 0) {
		/* no need to worry about buffers, skip everything */
	} else if (bytes_skipped < cstream->prev_stream_left) {
		/* we're still skipping inside buffer */
		cstream->prev_stream_left -= bytes_skipped;
		bytes_skipped = 0;
	} else {
		/* done with the buffer */
		bytes_skipped -= cstream->prev_stream_left;
		cstream->prev_stream_left = 0;
	}
	stream->pos -= bytes_skipped;
	stream->skip -= bytes_skipped;
	stream->buffer += bytes_skipped;
	cstream->prev_skip = stream->skip;

	if (link == NULL) {
		i_assert(bytes_skipped == 0);
		return 0;
	}
	i_stream_skip(link->stream, bytes_skipped);

	i_assert(stream->pos >= stream->skip + cstream->prev_stream_left);
	cur_data_pos = stream->pos - (stream->skip + cstream->prev_stream_left);

	data = i_stream_get_data(link->stream, &data_size);
	if (data_size > cur_data_pos)
		ret = 0;
	else {
		/* need to read more */
		i_assert(cur_data_pos == data_size);
		ret = i_stream_read(link->stream);
		if (ret == -2 || ret == 0)
			return ret;

		if (ret == -1) {
			if (link->stream->stream_errno != 0) {
				stream->istream.stream_errno =
					link->stream->stream_errno;
				return -1;
			}
			/* EOF of this stream, go to next stream */
			i_stream_chain_read_next(cstream);
			cstream->prev_skip = stream->skip;
			return i_stream_chain_read(stream);
		}
		/* we read something */
		data = i_stream_get_data(link->stream, &data_size);
	}

	if (cstream->prev_stream_left == 0) {
		/* we can point directly to the current stream's buffers */
		stream->buffer = data;
		stream->pos -= stream->skip;
		stream->skip = 0;
		new_pos = data_size;
	} else if (data_size == cur_data_pos) {
		/* nothing new read */
		i_assert(ret == 0 || ret == -1);
		stream->buffer = stream->w_buffer;
		new_pos = stream->pos;
	} else {
		/* we still have some of the previous stream left. merge the
		   new data with it. */
		i_assert(data_size > cur_data_pos);
		new_bytes_count = data_size - cur_data_pos;
		if (!i_stream_try_alloc(stream, new_bytes_count, &size)) {
			stream->buffer = stream->w_buffer;
			return -2;
		}
		stream->buffer = stream->w_buffer;

		if (new_bytes_count > size)
			new_bytes_count = size;
		memcpy(stream->w_buffer + stream->pos,
		       data + cur_data_pos, new_bytes_count);
		new_pos = stream->pos + new_bytes_count;
	}

	ret = new_pos > stream->pos ? (ssize_t)(new_pos - stream->pos) :
		(ret == 0 ? 0 : -1);
	stream->pos = new_pos;
	cstream->prev_skip = stream->skip;
	return ret;
}

struct istream *i_stream_create_chain(struct istream_chain **chain_r)
{
	struct chain_istream *cstream;

	cstream = i_new(struct chain_istream, 1);
	cstream->chain.stream = cstream;
	cstream->istream.max_buffer_size = 256;

	cstream->istream.iostream.destroy = i_stream_chain_destroy;
	cstream->istream.iostream.set_max_buffer_size =
		i_stream_chain_set_max_buffer_size;

	cstream->istream.read = i_stream_chain_read;

	cstream->istream.istream.readable_fd = FALSE;
	cstream->istream.istream.blocking = FALSE;
	cstream->istream.istream.seekable = FALSE;

	*chain_r = &cstream->chain;
	return i_stream_create(&cstream->istream, NULL, -1);
}
