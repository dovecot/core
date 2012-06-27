/* Copyright (c) 2003-2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "llist.h"
#include "istream-private.h"
#include "istream-chain.h"

struct chain_istream;

struct istream_chain_link {
	struct istream_chain_link *prev, *next;

	uoff_t start_offset;
	struct istream *stream;
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

	if (stream != NULL) {
		i_stream_ref(stream);	
		link->start_offset = stream->v_offset;
	}

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
	return i_stream_chain_append_internal(chain, stream);
}

void i_stream_chain_append_eof(struct istream_chain *chain)
{
	return i_stream_chain_append_internal(chain, NULL);
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
}

static void i_stream_chain_read_next(struct chain_istream *cstream)
{
	struct istream_chain_link *link = cstream->chain.head;
	struct istream *prev_input;
	const unsigned char *data;
	size_t data_size, size;

	i_assert(link != NULL && link->stream != NULL);
	i_assert(link->stream->eof);

	prev_input = link->stream;
	data = i_stream_get_data(prev_input, &data_size);

	DLLIST2_REMOVE(&cstream->chain.head, &cstream->chain.tail, link);
	i_free(link);

	link = cstream->chain.head;
	i_assert(link == NULL || link->stream != NULL);
	if (link != NULL)
		i_stream_seek(link->stream, 0);

	/* we already verified that the data size is less than the
	   maximum buffer size */
	cstream->istream.pos = 0;
	if (data_size > 0) {
		if (!i_stream_try_alloc(&cstream->istream, data_size, &size))
			i_unreached();
		i_assert(size >= data_size);
	}

	cstream->prev_stream_left = data_size;
	memcpy(cstream->istream.w_buffer, data, data_size);
	i_stream_skip(prev_input, data_size);
	i_stream_unref(&prev_input);
	cstream->istream.skip = 0;
	cstream->istream.pos = data_size;
}

static ssize_t i_stream_chain_read(struct istream_private *stream)
{
	struct chain_istream *cstream = (struct chain_istream *)stream;
	struct istream_chain_link *link = cstream->chain.head;
	const unsigned char *data;
	size_t size, pos, cur_pos, bytes_skipped;
	ssize_t ret;
	bool last_stream;

	if (link != NULL && link->stream == NULL) {
		stream->istream.eof = TRUE;
		return -1;
	}

	i_assert(stream->skip >= cstream->prev_skip);
	bytes_skipped = stream->skip - cstream->prev_skip;

	if (cstream->prev_stream_left == 0) {
		/* no need to worry about buffers, skip everything */
		i_assert(cstream->prev_skip == 0);
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

	if (link == NULL) {
		i_assert(bytes_skipped == 0);
		return 0;
	}

	i_stream_skip(link->stream, bytes_skipped);

	cur_pos = stream->pos - stream->skip - cstream->prev_stream_left;
	data = i_stream_get_data(link->stream, &pos);
	if (pos > cur_pos)
		ret = 0;
	else {
		/* need to read more */
		i_assert(cur_pos == pos);
		ret = i_stream_read(link->stream);
		if (ret == -2 || ret == 0) {
			return ret;
		}

		if (ret == -1 && link->stream->stream_errno != 0) {
			stream->istream.stream_errno =
				link->stream->stream_errno;
			return -1;
		}

		/* we either read something or we're at EOF */
		last_stream = link->next != NULL && link->next->stream == NULL;
		if (ret == -1 && !last_stream) {
			if (stream->pos >= stream->max_buffer_size)
				return -2;

			i_stream_chain_read_next(cstream);
			cstream->prev_skip = stream->skip;
			return i_stream_chain_read(stream);
		}

		stream->istream.eof = link->stream->eof && last_stream;
		i_assert(ret != -1 || stream->istream.eof);
		data = i_stream_get_data(link->stream, &pos);
	}

	if (cstream->prev_stream_left == 0) {
		stream->buffer = data;
		stream->pos -= stream->skip;
		stream->skip = 0;
	} else if (pos == cur_pos) {
		stream->buffer = stream->w_buffer;
	} else {
		stream->buffer = stream->w_buffer;
		if (!i_stream_try_alloc(stream, pos - cur_pos, &size))
			return -2;

		if (pos > size)
			pos = size;
		memcpy(stream->w_buffer + stream->pos,
		       data + cur_pos, pos - cur_pos);
	}
	pos += stream->skip + cstream->prev_stream_left;

	ret = pos > stream->pos ? (ssize_t)(pos - stream->pos) :
		(ret == 0 ? 0 : -1);

	stream->pos = pos;
	cstream->prev_skip = stream->skip;
	return ret;
}

static const struct stat *
i_stream_chain_stat(struct istream_private *stream ATTR_UNUSED,
		    bool exact ATTR_UNUSED)
{
	i_panic("istream_chain(): stat() not supported");
	return NULL;
}

static int
i_stream_chain_get_size(struct istream_private *stream ATTR_UNUSED,
			bool exact ATTR_UNUSED, uoff_t *size_r ATTR_UNUSED)
{
	i_panic("istream_chain(): get_size() not supported");
	return -1;
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
	cstream->istream.stat = i_stream_chain_stat;
	cstream->istream.get_size = i_stream_chain_get_size;

	cstream->istream.istream.readable_fd = FALSE;
	cstream->istream.istream.blocking = FALSE;
	cstream->istream.istream.seekable = FALSE;

	*chain_r = &cstream->chain;
	return i_stream_create(&cstream->istream, NULL, -1);
}
