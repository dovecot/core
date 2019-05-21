/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "ostream-private.h"
#include "ostream-multiplex.h"

/* all multiplex packets are [1 byte cid][4 byte length][data] */

struct multiplex_ostream;

struct multiplex_ochannel {
	struct ostream_private ostream;
	struct multiplex_ostream *mstream;
	uint8_t cid;
	buffer_t *buf;
	time_t last_sent;
	bool closed:1;
	bool corked:1;
};

struct multiplex_ostream {
	struct ostream *parent;

	/* channel 0 is main channel */
	uint8_t cur_channel;
	unsigned int remain;
	buffer_t *wbuf;
	size_t bufsize;
	ARRAY(struct multiplex_ochannel *) channels;

	bool destroyed:1;
};

static struct multiplex_ochannel *
get_channel(struct multiplex_ostream *mstream, uint8_t cid)
{
	struct multiplex_ochannel **channelp;
	i_assert(mstream != NULL);
	array_foreach_modifiable(&mstream->channels, channelp) {
		if (*channelp != NULL && (*channelp)->cid == cid)
			return *channelp;
	}
	return NULL;
}

static void propagate_error(struct multiplex_ostream *mstream, int stream_errno)
{
	struct multiplex_ochannel **channelp;
	array_foreach_modifiable(&mstream->channels, channelp)
		if (*channelp != NULL)
			(*channelp)->ostream.ostream.stream_errno = stream_errno;
}

static struct multiplex_ochannel *get_next_channel(struct multiplex_ostream *mstream)
{
	time_t oldest = ioloop_time;
	struct multiplex_ochannel *channel = NULL;
	struct multiplex_ochannel **channelp;
	array_foreach_modifiable(&mstream->channels, channelp)
		if (*channelp != NULL && (*channelp)->last_sent <= oldest &&
		    (*channelp)->buf->used > 0)
			channel = *channelp;
	return channel;
}

static ssize_t
o_stream_multiplex_sendv(struct multiplex_ostream *mstream)
{
	struct multiplex_ochannel *channel;
	ssize_t ret = 0;
	if (mstream->bufsize <= mstream->wbuf->used + 5)
		return -2;

	while((channel = get_next_channel(mstream)) != NULL) {
		if (channel->buf->used == 0)
			continue;
		size_t tmp = mstream->bufsize - mstream->wbuf->used - 5;
		/* ensure it fits into 32 bit int */
		size_t amt = I_MIN(UINT_MAX, I_MIN(tmp, channel->buf->used));
		if (tmp == 0)
			break;
		uint32_t len = cpu32_to_be(amt);
		buffer_append(mstream->wbuf, &channel->cid, 1);
		buffer_append(mstream->wbuf, &len, 4);
		buffer_append(mstream->wbuf, channel->buf->data, amt);
		buffer_delete(channel->buf, 0, amt);
		channel->last_sent = ioloop_time;
	}

	if (mstream->wbuf->used > 0) {
		ret = o_stream_send(mstream->parent, mstream->wbuf->data,
				    mstream->wbuf->used);
		if (ret < 0) {
			propagate_error(mstream, mstream->parent->stream_errno);
			return ret;
		}
		buffer_delete(mstream->wbuf, 0, ret);
	}
	return ret;
}

static int o_stream_multiplex_ochannel_flush(struct ostream_private *stream)
{
	ssize_t ret;
	struct multiplex_ochannel *channel = (struct multiplex_ochannel *)stream;
	struct multiplex_ostream *mstream = channel->mstream;

	/* flush parent stream always, so there is room for more. */
	if ((ret = o_stream_flush(mstream->parent)) <= 0) {
		if (ret == -1)
			propagate_error(mstream, mstream->parent->stream_errno);
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
	struct multiplex_ochannel *channel = (struct multiplex_ochannel*)stream;
	if (channel->corked != set && !set) {
		/* flush */
		(void)o_stream_multiplex_ochannel_flush(stream);
	}
	channel->corked = set;
}

static ssize_t
o_stream_multiplex_ochannel_sendv(struct ostream_private *stream,
				 const struct const_iovec *iov, unsigned int iov_count)
{
	struct multiplex_ochannel *channel = (struct multiplex_ochannel*)stream;
	ssize_t ret;
	size_t total = 0;
	if (channel->mstream->bufsize <= channel->buf->used)
		return -2;

	for (unsigned int i = 0; i < iov_count; i++) {
		/* copy data to buffer */
		size_t tmp = channel->mstream->bufsize - channel->buf->used;
		if (tmp == 0)
			break;
		buffer_append(channel->buf, iov[i].iov_base,
			      I_MIN(tmp, iov[i].iov_len));
		total += I_MIN(tmp, iov[i].iov_len);
	}

	stream->ostream.offset += total;

	/* will send later */
	if (channel->corked)
		return total;

	if ((ret = o_stream_multiplex_sendv(channel->mstream)) < 0)
		return ret;

	return total;
}

static size_t
o_stream_multiplex_ochannel_get_buffer_used_size(const struct ostream_private *stream)
{
	const struct multiplex_ochannel *channel =
		(const struct multiplex_ochannel*)stream;

	return channel->buf->used + channel->mstream->wbuf->used +
		o_stream_get_buffer_used_size(channel->mstream->parent);
}

static size_t
o_stream_multiplex_ochannel_get_buffer_avail_size(const struct ostream_private *stream)
{
	const struct multiplex_ochannel *channel =
		(const struct multiplex_ochannel*)stream;

	return channel->mstream->bufsize <= channel->buf->used ? 0 :
		channel->mstream->bufsize - channel->buf->used;
}

static void
o_stream_multiplex_ochannel_close(struct iostream_private *stream, bool close_parent)
{
	struct multiplex_ochannel *const *channelp;
	struct multiplex_ochannel *channel = (struct multiplex_ochannel*)stream;

	channel->closed = TRUE;
	if (close_parent) {
		array_foreach(&channel->mstream->channels, channelp)
			if (*channelp !=NULL && !(*channelp)->closed)
				return;
		o_stream_close(channel->mstream->parent);
	}
}

static void o_stream_multiplex_try_destroy(struct multiplex_ostream *mstream)
{
	struct multiplex_ochannel **channelp;
	/* can't do anything until they are all closed */
	array_foreach_modifiable(&mstream->channels, channelp)
		if (*channelp != NULL)
			return;
	o_stream_unref(&mstream->parent);
	array_free(&mstream->channels);
	buffer_free(&mstream->wbuf);
	i_free(mstream);
}

static void o_stream_multiplex_ochannel_destroy(struct iostream_private *stream)
{
	struct multiplex_ochannel **channelp;
	struct multiplex_ochannel *channel = (struct multiplex_ochannel*)stream;
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
	channel->ostream.get_buffer_used_size =
		o_stream_multiplex_ochannel_get_buffer_used_size;
	channel->ostream.get_buffer_avail_size =
		o_stream_multiplex_ochannel_get_buffer_avail_size;
	channel->ostream.iostream.close = o_stream_multiplex_ochannel_close;
	channel->ostream.iostream.destroy = o_stream_multiplex_ochannel_destroy;
	channel->ostream.fd = o_stream_get_fd(mstream->parent);
	array_push_back(&channel->mstream->channels, &channel);

	return o_stream_create(&channel->ostream, mstream->parent,
			       mstream->bufsize);
}

struct ostream *o_stream_multiplex_add_channel(struct ostream *stream, uint8_t cid)
{
	struct multiplex_ochannel *chan =
		(struct multiplex_ochannel *)stream->real_stream;
	i_assert(get_channel(chan->mstream, cid) == NULL);

	return o_stream_add_channel_real(chan->mstream, cid);
}

struct ostream *o_stream_create_multiplex(struct ostream *parent, size_t bufsize)
{
	struct multiplex_ostream *mstream;

	mstream = i_new(struct multiplex_ostream, 1);
	mstream->parent = parent;
	mstream->bufsize = bufsize;
	mstream->wbuf = buffer_create_dynamic(default_pool, 256);
	i_array_init(&mstream->channels, 8);
	o_stream_ref(parent);

	return o_stream_add_channel_real(mstream, 0);
}

uint8_t o_stream_multiplex_get_channel_id(struct ostream *stream)
{
	struct multiplex_ochannel *channel =
		(struct multiplex_ochannel *)stream->real_stream;
	return channel->cid;
}
