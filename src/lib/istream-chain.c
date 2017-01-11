/* Copyright (c) 2003-2017 Dovecot authors, see the included COPYING file */

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

	/* how much of the previous link's stream still exists at the
	   beginning of our buffer. skipping through this should point to
	   the beginning of the current link's stream. */
	size_t prev_stream_left;
	size_t prev_skip;
	bool have_explicit_max_buffer_size;
	
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
		struct chain_istream *cstream = (struct chain_istream *)chain->stream;

		if (cstream->have_explicit_max_buffer_size) {
			i_stream_set_max_buffer_size(stream,
				chain->stream->istream.max_buffer_size);
		} else {
			size_t max_size = i_stream_get_max_buffer_size(stream);

			if (cstream->istream.max_buffer_size < max_size)
				cstream->istream.max_buffer_size = max_size;
		}
	}
	DLLIST2_APPEND(&chain->head, &chain->tail, link);
	/* if io_add_istream() has been added to this chain stream, notify
	   the callback that we have more data available. */
	if (stream != NULL)
		i_stream_set_input_pending(stream, TRUE);
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

	cstream->have_explicit_max_buffer_size = TRUE;
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
	size_t data_size, cur_data_pos;

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
		   appending the rest to it. if it's already at EOF, there's
		   nothing more to append. */
		cur_data_pos = cstream->istream.pos -
			(cstream->istream.skip + cstream->prev_stream_left);
		i_assert(cur_data_pos <= data_size);
		data += cur_data_pos;
		data_size -= cur_data_pos;
		/* the stream has now become "previous", so its contents in
		   buffer are now part of prev_stream_left. */
		cstream->prev_stream_left += cur_data_pos;
	} else {
		cstream->istream.pos = 0;
		cstream->istream.skip = 0;
		cstream->prev_stream_left = 0;
	}

	if (data_size > 0) {
		memcpy(i_stream_alloc(&cstream->istream, data_size),
		       data, data_size);
		cstream->istream.pos += data_size;
		cstream->prev_stream_left += data_size;
	}

	i_stream_skip(prev_input, i_stream_get_data_size(prev_input));
	i_stream_unref(&prev_input);
}

static bool i_stream_chain_skip(struct chain_istream *cstream)
{
	struct istream_private *stream = &cstream->istream;
	struct istream_chain_link *link = cstream->chain.head;
	size_t bytes_skipped;

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
	if (link == NULL || link->eof) {
		i_assert(bytes_skipped == 0);
		return FALSE;
	}
	i_stream_skip(link->stream, bytes_skipped);
	return TRUE;
}

static ssize_t i_stream_chain_read(struct istream_private *stream)
{
	struct chain_istream *cstream = (struct chain_istream *)stream;
	struct istream_chain_link *link = cstream->chain.head;
	const unsigned char *data;
	size_t data_size, cur_data_pos, new_pos;
	size_t new_bytes_count;
	ssize_t ret;

	if (link != NULL && link->eof) {
		stream->istream.eof = TRUE;
		return -1;
	}

	if (!i_stream_chain_skip(cstream))
		return 0;
	i_assert(link != NULL);

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
				io_stream_set_error(&stream->iostream,
					"read(%s) failed: %s",
					i_stream_get_name(link->stream),
					i_stream_get_error(link->stream));
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
		memcpy(i_stream_alloc(stream, new_bytes_count),
		       data + cur_data_pos, new_bytes_count);
		stream->buffer = stream->w_buffer;
		new_pos = stream->pos + new_bytes_count;
	}

	ret = new_pos > stream->pos ? (ssize_t)(new_pos - stream->pos) :
		(ret == 0 ? 0 : -1);
	stream->pos = new_pos;
	cstream->prev_skip = stream->skip;
	return ret;
}

static void i_stream_chain_close(struct iostream_private *stream,
				 bool close_parent)
{
	struct chain_istream *cstream = (struct chain_istream *)stream;

	/* seek to the correct position in parent stream in case it didn't
	   end with EOF */
	(void)i_stream_chain_skip(cstream);

	if (close_parent) {
		struct istream_chain_link *link = cstream->chain.head;
		while (link != NULL) {
			i_stream_close(link->stream);
			link = link->next;
		}
	}
}

struct istream *i_stream_create_chain(struct istream_chain **chain_r)
{
	struct chain_istream *cstream;

	cstream = i_new(struct chain_istream, 1);
	cstream->chain.stream = cstream;

	cstream->istream.iostream.close = i_stream_chain_close;
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
