/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "ostream-private.h"
#include "iostream-multiplex-private.h"
#include "ostream-multiplex.h"

/* See istream-multiplex for description of the stream format. */

struct multiplex_ochannel {
	struct ostream_private ostream;
	struct multiplex_ostream *mstream;
	uint8_t cid;
	buffer_t *buf;
	uint64_t last_sent_counter;
	bool closed:1;
};

struct multiplex_ostream {
	struct ostream *parent;

	stream_flush_callback_t *old_flush_callback;
	void *old_flush_context;

	/* channel 0 is main channel */
	int cur_channel;
	size_t bufsize;
	enum ostream_multiplex_format format;
	uint64_t send_counter;
	ARRAY(struct multiplex_ochannel *) channels;

	unsigned int stream_header_bytes_left;
	buffer_t *pending_buf;

	bool pending_buf_prefix_char1:1;
	bool destroyed:1;
};

static unsigned char ostream_multiplex_header[IOSTREAM_MULTIPLEX_HEADER_SIZE] =
	"\xFF\xFF\xFF\xFF\xFF\x00\x02"
        IOSTREAM_MULTIPLEX_CHANNEL_SWITCH_PREFIX;

static struct multiplex_ochannel *
get_channel(struct multiplex_ostream *mstream, uint8_t cid)
{
	struct multiplex_ochannel *channel;
	i_assert(mstream != NULL);
	array_foreach_elem(&mstream->channels, channel) {
		if (channel != NULL && channel->cid == cid)
			return channel;
	}
	return NULL;
}

static void propagate_error(struct multiplex_ostream *mstream)
{
	struct multiplex_ochannel *channel;
	int stream_errno = mstream->parent->stream_errno;

	i_assert(stream_errno != 0);

	const char *error = o_stream_get_error(mstream->parent);
	array_foreach_elem(&mstream->channels, channel) {
		if (channel != NULL) {
			channel->ostream.ostream.stream_errno = stream_errno;
			io_stream_set_error(&channel->ostream.iostream,
					    "%s", error);
		}
	}
}

static struct multiplex_ochannel *get_next_channel(struct multiplex_ostream *mstream)
{
	struct multiplex_ochannel *oldest_channel = NULL;
	struct multiplex_ochannel *channel;
	uint64_t last_counter = mstream->send_counter;

	array_foreach_elem(&mstream->channels, channel) {
		if (channel != NULL &&
		    channel->last_sent_counter <= last_counter &&
		    channel->buf->used > 0) {
			last_counter = channel->last_sent_counter;
			oldest_channel = channel;
		}
	}
	return oldest_channel;
}

static ssize_t
o_stream_multiplex_send_packet(struct multiplex_ostream *mstream,
			       struct multiplex_ochannel *channel)
{
	/* check parent stream capacity */
	size_t tmp = o_stream_get_buffer_avail_size(mstream->parent) - 5;
	/* ensure it fits into 32 bit int */
	size_t amt = I_MIN(UINT_MAX, I_MIN(tmp, channel->buf->used));
	/* delay corking here now that we are going to send something */
	if (!o_stream_is_corked(mstream->parent))
		o_stream_cork(mstream->parent);
	uint32_t len = cpu32_to_be(amt);
	const struct const_iovec vec[] = {
		{ &channel->cid, 1 },
		{ &len, 4 },
		{ channel->buf->data, amt }
	};
	ssize_t ret;
	if ((ret = o_stream_sendv(mstream->parent, vec, N_ELEMENTS(vec))) < 0) {
		propagate_error(mstream);
		return -1;
	}
	i_assert((size_t)ret == 1 + 4 + amt);
	return amt;
}

static ssize_t
o_stream_multiplex_send_stream(struct multiplex_ostream *mstream,
			       struct multiplex_ochannel *channel)
{
	if (mstream->cur_channel != channel->cid) {
		buffer_append(mstream->pending_buf,
			      IOSTREAM_MULTIPLEX_CHANNEL_SWITCH_PREFIX,
			      IOSTREAM_MULTIPLEX_CHANNEL_SWITCH_PREFIX_LEN);
		buffer_append_c(mstream->pending_buf,
				MULTIPLEX_ISTREAM_SWITCH_TYPE_CHANNEL_ID);
		buffer_append_c(mstream->pending_buf, channel->cid);
		mstream->cur_channel = channel->cid;
	}

	const unsigned char *p, *data = channel->buf->data;
	size_t skip, size = channel->buf->used;
	size_t total_sent = 0;

	/* Handle escaping switch-prefix at the beginning of data.
	   Also if there is only a single byte left, escape that byte so the
	   stream won't end with the istream not knowing whether it's part of
	   an escape sequence or not. */
again:
	if ((size >= IOSTREAM_MULTIPLEX_CHANNEL_SWITCH_PREFIX_LEN &&
	     memcmp(data, IOSTREAM_MULTIPLEX_CHANNEL_SWITCH_PREFIX,
		    IOSTREAM_MULTIPLEX_CHANNEL_SWITCH_PREFIX_LEN) == 0) ||
	    (size == 1 &&
	     data[0] == IOSTREAM_MULTIPLEX_CHANNEL_SWITCH_PREFIX[0])) {
		/* escape prefix's first byte */
		buffer_append(mstream->pending_buf,
			      IOSTREAM_MULTIPLEX_CHANNEL_SWITCH_PREFIX,
			      IOSTREAM_MULTIPLEX_CHANNEL_SWITCH_PREFIX_LEN);
		buffer_append_c(mstream->pending_buf,
				MULTIPLEX_ISTREAM_SWITCH_TYPE_PREFIX_CHAR1);
		i_assert(!mstream->pending_buf_prefix_char1);
		mstream->pending_buf_prefix_char1 = TRUE;
		data++; size--;
		skip = 0;
	} else {
		skip = 1;
	}

	while (skip < size) {
		p = memchr(data + skip,
			   IOSTREAM_MULTIPLEX_CHANNEL_SWITCH_PREFIX[0],
			   size - skip);
		if (p == NULL) {
			skip = size;
			break;
		}
		skip = p - data;
		if (skip + 1 == size ||
		    (char)data[skip + 1] == IOSTREAM_MULTIPLEX_CHANNEL_SWITCH_PREFIX[1]) {
			/* escaping needed */
			break;
		}
		skip++;
	}

	if (!o_stream_is_corked(mstream->parent))
		o_stream_cork(mstream->parent);
	const struct const_iovec vec[] = {
		{ mstream->pending_buf->data, mstream->pending_buf->used },
		{ data, skip }
	};
	ssize_t ret;
	if ((ret = o_stream_sendv(mstream->parent, vec, N_ELEMENTS(vec))) < 0) {
		propagate_error(mstream);
		return -1;
	}

	if ((size_t)ret < mstream->pending_buf->used) {
		buffer_delete(mstream->pending_buf, 0, ret);
		return total_sent;
	}

	/* At least pending_buf was fully sent. It doesn't contain any actual
	   input data, except possibly the first character of the switch
	   prefix. */
	ret -= mstream->pending_buf->used;
	i_assert((size_t)ret <= skip);
	data += ret;
	size -= ret;
	if (mstream->pending_buf_prefix_char1) {
		mstream->pending_buf_prefix_char1 = FALSE;
		ret++;
	}
	total_sent += ret;
	buffer_set_used_size(mstream->pending_buf, 0);

	if (size > 0)
		goto again;
	i_assert(total_sent > 0);
	return total_sent;
}

static int
o_stream_multiplex_send_header(struct multiplex_ostream *mstream)
{
	size_t pos = IOSTREAM_MULTIPLEX_HEADER_SIZE -
		mstream->stream_header_bytes_left;

	ssize_t ret = o_stream_send(mstream->parent,
				    ostream_multiplex_header + pos,
				    mstream->stream_header_bytes_left);
	if (ret < 0) {
		propagate_error(mstream);
		return -1;
	}
	i_assert(ret <= mstream->stream_header_bytes_left);
	mstream->stream_header_bytes_left -= ret;
	return mstream->stream_header_bytes_left == 0 ? 1 : 0;
}

static int
o_stream_multiplex_sendv(struct multiplex_ostream *mstream)
{
	struct multiplex_ochannel *channel;
	ssize_t ret;
	int all_sent = 1;

	if (mstream->stream_header_bytes_left > 0) {
		if ((ret = o_stream_multiplex_send_header(mstream)) <= 0)
			return ret;
	}

	while((channel = get_next_channel(mstream)) != NULL) {
		if (channel->buf->used == 0)
			continue;
		if (o_stream_get_buffer_avail_size(mstream->parent) < 6) {
			all_sent = 0;
			break;
		}

		switch (mstream->format) {
		case OSTREAM_MULTIPLEX_FORMAT_PACKET:
			ret = o_stream_multiplex_send_packet(mstream, channel);
			break;
		case OSTREAM_MULTIPLEX_FORMAT_STREAM:
		case OSTREAM_MULTIPLEX_FORMAT_STREAM_CONTINUE:
			ret = o_stream_multiplex_send_stream(mstream, channel);
			break;
		}
		if (ret <= 0) {
			all_sent = ret;
			break;
		}
		buffer_delete(channel->buf, 0, ret);
		channel->last_sent_counter = ++mstream->send_counter;
	}
	if (o_stream_is_corked(mstream->parent))
		o_stream_uncork(mstream->parent);
	return all_sent;
}

static int o_stream_multiplex_flush(struct multiplex_ostream *mstream)
{
	int ret = o_stream_flush(mstream->parent);
	if (ret >= 0) {
		if ((ret = o_stream_multiplex_sendv(mstream)) <= 0)
			return ret;
	}

	/* a) Everything is flushed. See if one of the callbacks' flush
	   callbacks wants to write more data.
	   b) ostream failed. Notify the callbacks in case they need to know. */
	struct multiplex_ochannel *channel;
	bool unfinished = FALSE;
	bool failed = FALSE;
	array_foreach_elem(&mstream->channels, channel) {
		if (channel != NULL && channel->ostream.callback != NULL) {
			ret = channel->ostream.callback(channel->ostream.context);
			if (ret < 0)
				failed = TRUE;
			else if (ret == 0)
				unfinished = TRUE;
		}
	}
	return failed ? -1 :
		(unfinished ? 0 : 1);
}

static int o_stream_multiplex_ochannel_flush(struct ostream_private *stream)
{
	ssize_t ret;
	struct multiplex_ochannel *channel =
		container_of(stream, struct multiplex_ochannel, ostream);
	struct multiplex_ostream *mstream = channel->mstream;

	/* flush parent stream always, so there is room for more. */
	if ((ret = o_stream_flush(mstream->parent)) <= 0) {
		if (ret == -1)
			propagate_error(mstream);
		return ret;
	}

	/* send all channels */
	if (o_stream_multiplex_sendv(mstream) < 0)
		return -1;

	if (channel->buf->used > 0)
		return 0;
	return 1;
}

static void o_stream_multiplex_ochannel_cork(struct ostream_private *stream, bool set)
{
	if (stream->corked != set && !set) {
		/* flush */
		(void)o_stream_multiplex_ochannel_flush(stream);
	}
	stream->corked = set;
}

static ssize_t
o_stream_multiplex_ochannel_sendv(struct ostream_private *stream,
				 const struct const_iovec *iov, unsigned int iov_count)
{
	struct multiplex_ochannel *channel =
		container_of(stream, struct multiplex_ochannel, ostream);
	size_t total = 0, avail = o_stream_get_buffer_avail_size(&stream->ostream);
	size_t optimal_size = I_MIN(IO_BLOCK_SIZE, avail);

	for (unsigned int i = 0; i < iov_count; i++)
		total += iov[i].iov_len;

	if (avail < total && channel->buf->used < IO_BLOCK_SIZE) {
		/* ostream buffer size is too small for us - keep it always at
		   least at IO_BLOCK_SIZE. */
		avail = IO_BLOCK_SIZE - channel->buf->used;
	}
	if (avail < total) {
		if (o_stream_multiplex_sendv(channel->mstream) < 0)
			return -1;
		avail = o_stream_get_buffer_avail_size(&stream->ostream);
		if (avail == 0)
			return 0;
	}

	total = 0;

	for (unsigned int i = 0; i < iov_count; i++) {
		/* copy data to buffer */
		size_t tmp = avail - total;
		if (tmp == 0)
			break;
		buffer_append(channel->buf, iov[i].iov_base,
			      I_MIN(tmp, iov[i].iov_len));
		total += I_MIN(tmp, iov[i].iov_len);
	}

	stream->ostream.offset += total;

	/* will send later */
	if (stream->corked && channel->buf->used < optimal_size)
		return total;

	if (o_stream_multiplex_sendv(channel->mstream) < 0)
		return -1;
	return total;
}

static void
o_stream_multiplex_ochannel_set_flush_callback(struct ostream_private *stream,
					       stream_flush_callback_t *callback,
					       void *context)
{
	/* We have overwritten our parent's flush-callback. Don't change it. */
	stream->callback = callback;
	stream->context = context;
}

static size_t
o_stream_multiplex_ochannel_get_buffer_used_size(const struct ostream_private *stream)
{
	const struct multiplex_ochannel *channel =
		container_of(stream, const struct multiplex_ochannel, ostream);

	return channel->buf->used +
		o_stream_get_buffer_used_size(channel->mstream->parent);
}

static size_t
o_stream_multiplex_ochannel_get_buffer_avail_size(const struct ostream_private *stream)
{
	const struct multiplex_ochannel *channel =
		container_of(stream, const struct multiplex_ochannel, ostream);
	struct multiplex_ostream *mstream = channel->mstream;
	size_t max_avail = I_MIN(channel->mstream->bufsize,
				 o_stream_get_buffer_avail_size(stream->parent));
	size_t overhead_bytes;

	switch (mstream->format) {
	case OSTREAM_MULTIPLEX_FORMAT_PACKET:
		/* There is 5-byte overhead per message, so take that into
		   account */
		overhead_bytes = 5;
		break;
	case OSTREAM_MULTIPLEX_FORMAT_STREAM:
	case OSTREAM_MULTIPLEX_FORMAT_STREAM_CONTINUE:
		/* Get the maximum overhead that may be necessary for the
		   initial message. However, this doesn't include the potential
		   escaping that may be necessary. */
		overhead_bytes = mstream->stream_header_bytes_left +
			IOSTREAM_MULTIPLEX_CHANNEL_SWITCH_PREFIX_LEN + 2;
		break;
	default:
		i_unreached();
	}
	return max_avail <= (channel->buf->used + overhead_bytes) ? 0 :
		max_avail - (channel->buf->used + overhead_bytes);
	i_unreached();
}

static void
o_stream_multiplex_ochannel_close(struct iostream_private *stream, bool close_parent)
{
	struct multiplex_ochannel *arr_channel;
	struct multiplex_ochannel *channel =
		container_of(stream, struct multiplex_ochannel, ostream.iostream);

	channel->closed = TRUE;
	if (close_parent) {
		array_foreach_elem(&channel->mstream->channels, arr_channel)
			if (arr_channel != NULL && !arr_channel->closed)
				return;
		o_stream_close(channel->mstream->parent);
	}
}

static void o_stream_multiplex_try_destroy(struct multiplex_ostream *mstream)
{
	struct multiplex_ochannel *channel;
	/* can't do anything until they are all closed */
	array_foreach_elem(&mstream->channels, channel)
		if (channel != NULL)
			return;

	if (mstream->parent->real_stream->callback ==
	    (stream_flush_callback_t *)o_stream_multiplex_flush) {
		o_stream_set_flush_callback(mstream->parent,
					    *mstream->old_flush_callback,
					    mstream->old_flush_context);
	}
	o_stream_unref(&mstream->parent);
	array_free(&mstream->channels);
	buffer_free(&mstream->pending_buf);
	i_free(mstream);
}

static void o_stream_multiplex_ochannel_destroy(struct iostream_private *stream)
{
	struct multiplex_ochannel **channelp;
	struct multiplex_ochannel *channel =
		container_of(stream, struct multiplex_ochannel, ostream.iostream);
	o_stream_unref(&channel->ostream.parent);
	if (channel->buf != NULL)
		buffer_free(&channel->buf);
	/* delete the channel */
	array_foreach_modifiable(&channel->mstream->channels, channelp) {
		if (*channelp != NULL && (*channelp)->cid == channel->cid) {
			*channelp = NULL;
			break;
		}
	}
	o_stream_multiplex_try_destroy(channel->mstream);
}

static struct ostream *
o_stream_add_channel_real(struct multiplex_ostream *mstream, uint8_t cid)
{
	struct multiplex_ochannel *channel = i_new(struct multiplex_ochannel, 1);
	channel->cid = cid;
	channel->buf = buffer_create_dynamic(default_pool, 256);
	channel->mstream = mstream;
	channel->ostream.cork = o_stream_multiplex_ochannel_cork;
	channel->ostream.flush = o_stream_multiplex_ochannel_flush;
	channel->ostream.sendv = o_stream_multiplex_ochannel_sendv;
	channel->ostream.set_flush_callback =
		o_stream_multiplex_ochannel_set_flush_callback;
	channel->ostream.get_buffer_used_size =
		o_stream_multiplex_ochannel_get_buffer_used_size;
	channel->ostream.get_buffer_avail_size =
		o_stream_multiplex_ochannel_get_buffer_avail_size;
	channel->ostream.iostream.close = o_stream_multiplex_ochannel_close;
	channel->ostream.iostream.destroy = o_stream_multiplex_ochannel_destroy;
	channel->ostream.fd = o_stream_get_fd(mstream->parent);
	array_push_back(&channel->mstream->channels, &channel);

	(void)o_stream_create(&channel->ostream, mstream->parent, -1);
	/* o_stream_create() defaults the flush_callback to parent's callback.
	   Here it points to o_stream_multiplex_flush(), which just causes
	   infinite looping. */
	channel->ostream.callback = NULL;
	channel->ostream.context = NULL;
	return &channel->ostream.ostream;
}

struct ostream *o_stream_multiplex_add_channel(struct ostream *stream, uint8_t cid)
{
	struct multiplex_ochannel *chan =
		container_of(stream->real_stream, struct multiplex_ochannel,
			     ostream);
	i_assert(get_channel(chan->mstream, cid) == NULL);

	return o_stream_add_channel_real(chan->mstream, cid);
}

struct ostream *o_stream_create_multiplex(struct ostream *parent, size_t bufsize,
					  enum ostream_multiplex_format format)
{
	struct multiplex_ostream *mstream;

	mstream = i_new(struct multiplex_ostream, 1);
	mstream->parent = parent;
	mstream->format = format;
	switch (format) {
	case OSTREAM_MULTIPLEX_FORMAT_PACKET:
		break;
	case OSTREAM_MULTIPLEX_FORMAT_STREAM:
		mstream->stream_header_bytes_left =
			IOSTREAM_MULTIPLEX_HEADER_SIZE;
		break;
	case OSTREAM_MULTIPLEX_FORMAT_STREAM_CONTINUE:
		mstream->cur_channel = -1;
		break;
	}
	mstream->pending_buf = buffer_create_dynamic(default_pool, 16);
	mstream->bufsize = bufsize;
	mstream->old_flush_callback = parent->real_stream->callback;
	mstream->old_flush_context = parent->real_stream->context;
	o_stream_set_flush_callback(parent, o_stream_multiplex_flush, mstream);
	i_array_init(&mstream->channels, 8);
	o_stream_ref(parent);

	return o_stream_add_channel_real(mstream, 0);
}

uint8_t o_stream_multiplex_get_channel_id(struct ostream *stream)
{
	struct multiplex_ochannel *channel =
		container_of(stream->real_stream, struct multiplex_ochannel,
			     ostream);
	return channel->cid;
}
