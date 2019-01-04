/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "istream-private.h"
#include "istream-multiplex.h"

/* all multiplex packets are [1 byte cid][4 byte length][data] */

struct multiplex_istream;

struct multiplex_ichannel {
	struct istream_private istream;
	struct multiplex_istream *mstream;
	uint8_t cid;
	size_t pending_pos;
	bool closed:1;
};

struct multiplex_istream {
	struct istream *parent;

	/* channel 0 is main channel */
	uint8_t cur_channel;
	unsigned int remain;
	size_t bufsize;
	ARRAY(struct multiplex_ichannel *) channels;

	bool blocking:1;
};

static ssize_t i_stream_multiplex_ichannel_read(struct istream_private *stream);

static struct multiplex_ichannel *
get_channel(struct multiplex_istream *mstream, uint8_t cid)
{
	struct multiplex_ichannel **channelp;
	i_assert(mstream != NULL);
	array_foreach_modifiable(&mstream->channels, channelp) {
		if (*channelp != NULL && (*channelp)->cid == cid)
			return *channelp;
	}
	return NULL;
}

static void propagate_error(struct multiplex_istream *mstream, int stream_errno)
{
	struct multiplex_ichannel **channelp;
	array_foreach_modifiable(&mstream->channels, channelp)
		if (*channelp != NULL)
			(*channelp)->istream.istream.stream_errno = stream_errno;
}

static void propagate_eof(struct multiplex_istream *mstream)
{
	struct multiplex_ichannel **channelp;
	array_foreach_modifiable(&mstream->channels, channelp) {
		if (*channelp == NULL)
			continue;

		(*channelp)->istream.istream.eof = TRUE;
		if (mstream->remain > 0) {
			(*channelp)->istream.istream.stream_errno = EPIPE;
			io_stream_set_error(&(*channelp)->istream.iostream,
				"Unexpected EOF - %u bytes remaining in packet",
				mstream->remain);
		}
	}
}

static ssize_t
i_stream_multiplex_read(struct multiplex_istream *mstream,
			struct multiplex_ichannel *req_channel)
{
	const unsigned char *data;
	size_t len = 0, used, wanted, avail;
	ssize_t ret, got = 0;

	if (mstream->parent == NULL) {
		req_channel->istream.istream.eof = TRUE;
		return -1;
	}

	(void)i_stream_get_data(mstream->parent, &len);

	if (len == 0 && mstream->parent->closed) {
		req_channel->istream.istream.eof = TRUE;
		return -1;
	}

	if (((mstream->remain > 0 && len == 0) ||
	     (mstream->remain == 0 && len < 5)) &&
	    (ret = i_stream_read_memarea(mstream->parent)) <= 0) {
		propagate_error(mstream, mstream->parent->stream_errno);
		if (mstream->parent->eof)
			propagate_eof(mstream);
		return ret;
	}

	for(;;) {
		data = i_stream_get_data(mstream->parent, &len);
		if (len == 0) {
			if (got == 0 && mstream->blocking) {
				/* can't return 0 with blocking istreams,
				   so try again from the beginning. */
				return i_stream_multiplex_read(mstream, req_channel);
			}
			break;
		}

		if (mstream->remain > 0) {
			struct multiplex_ichannel *channel =
				get_channel(mstream, mstream->cur_channel);
			wanted = I_MIN(len, mstream->remain);
			/* is it open? */
			if (channel != NULL && !channel->closed) {
				struct istream_private *stream = &channel->istream;
				stream->pos += channel->pending_pos;
				bool alloc_ret = i_stream_try_alloc(stream, wanted, &avail);
				stream->pos -= channel->pending_pos;
				if (!alloc_ret) {
					i_stream_set_input_pending(&stream->istream, TRUE);
					if (channel->cid != req_channel->cid)
						return 0;
					if (got > 0)
						break;
					return -2;
				}

				used = I_MIN(wanted, avail);

				/* dump into buffer */
				if (channel->cid != req_channel->cid) {
					i_assert(stream->pos + channel->pending_pos + used <= stream->buffer_size);
					memcpy(stream->w_buffer + stream->pos + channel->pending_pos,
					       data, used);
					channel->pending_pos += used;
					i_stream_set_input_pending(&stream->istream, TRUE);
				} else {
					i_assert(stream->pos + used <= stream->buffer_size);
					memcpy(stream->w_buffer + stream->pos, data, used);
					stream->pos += used;
					got += used;
				}
			} else {
				used = wanted;
			}
			mstream->remain -= used;
			i_stream_skip(mstream->parent, used);
			/* see if there is more to read */
			continue;
		}
		if (mstream->remain == 0) {
			/* need more data */
			if (len < 5) {
				ret = i_stream_multiplex_ichannel_read(&req_channel->istream);
				if (ret > 0)
					got += ret;
				break;
			}
			/* channel ID */
			mstream->cur_channel = data[0];
			/* data length */
			mstream->remain = be32_to_cpu_unaligned(data+1);
			i_stream_skip(mstream->parent, 5);
		}
	}

	propagate_error(mstream, mstream->parent->stream_errno);
	if (mstream->parent->eof)
		propagate_eof(mstream);

	return got;
}

static ssize_t i_stream_multiplex_ichannel_read(struct istream_private *stream)
{
	struct multiplex_ichannel *channel = (struct multiplex_ichannel*)stream;
	/* if previous multiplex read dumped data for us
	   actually serve it here. */
	if (channel->pending_pos > 0) {
		ssize_t ret = channel->pending_pos;
		stream->pos += channel->pending_pos;
		channel->pending_pos = 0;
		return ret;
	}
	return i_stream_multiplex_read(channel->mstream, channel);
}

static void
i_stream_multiplex_ichannel_switch_ioloop_to(struct istream_private *stream,
					     struct ioloop *ioloop)
{
	struct multiplex_ichannel *channel = (struct multiplex_ichannel*)stream;

	i_stream_switch_ioloop_to(channel->mstream->parent, ioloop);
}

static void
i_stream_multiplex_ichannel_close(struct iostream_private *stream, bool close_parent)
{
	struct multiplex_ichannel *const *channelp;
	struct multiplex_ichannel *channel = (struct multiplex_ichannel*)stream;
	channel->closed = TRUE;
	if (close_parent) {
		array_foreach(&channel->mstream->channels, channelp)
			if (*channelp != NULL && !(*channelp)->closed)
				return;
		i_stream_close(channel->mstream->parent);
	}
}

static void i_stream_multiplex_try_destroy(struct multiplex_istream *mstream)
{
	struct multiplex_ichannel **channelp;
	/* can't do anything until they are all closed */
	array_foreach_modifiable(&mstream->channels, channelp)
		if (*channelp != NULL)
			return;
	i_stream_unref(&mstream->parent);
	array_free(&mstream->channels);
	i_free(mstream);
}

static void i_stream_multiplex_ichannel_destroy(struct iostream_private *stream)
{
	struct multiplex_ichannel **channelp;
	struct multiplex_ichannel *channel = (struct multiplex_ichannel*)stream;
	i_stream_multiplex_ichannel_close(stream, TRUE);
	i_stream_free_buffer(&channel->istream);
	array_foreach_modifiable(&channel->mstream->channels, channelp) {
		if (*channelp == channel) {
			*channelp = NULL;
			break;
		}
	}
	i_stream_multiplex_try_destroy(channel->mstream);
}

static struct istream *
i_stream_add_channel_real(struct multiplex_istream *mstream, uint8_t cid)
{
	struct multiplex_ichannel *channel = i_new(struct multiplex_ichannel, 1);
	channel->cid = cid;
	channel->mstream = mstream;
	channel->istream.read = i_stream_multiplex_ichannel_read;
	channel->istream.switch_ioloop_to = i_stream_multiplex_ichannel_switch_ioloop_to;
	channel->istream.iostream.close = i_stream_multiplex_ichannel_close;
	channel->istream.iostream.destroy = i_stream_multiplex_ichannel_destroy;
	channel->istream.max_buffer_size = mstream->bufsize;
	channel->istream.istream.blocking = mstream->blocking;
	if (cid == 0)
		channel->istream.fd = i_stream_get_fd(mstream->parent);
	else
		channel->istream.fd = -1;
	array_push_back(&channel->mstream->channels, &channel);

	return i_stream_create(&channel->istream, NULL, channel->istream.fd, 0);
}

struct istream *i_stream_multiplex_add_channel(struct istream *stream, uint8_t cid)
{
	struct multiplex_ichannel *chan =
		(struct multiplex_ichannel *)stream->real_stream;
	i_assert(get_channel(chan->mstream, cid) == NULL);

	return i_stream_add_channel_real(chan->mstream, cid);
}

struct istream *i_stream_create_multiplex(struct istream *parent, size_t bufsize)
{
	struct multiplex_istream *mstream;

	mstream = i_new(struct multiplex_istream, 1);
	mstream->parent = parent;
	mstream->bufsize = bufsize;
	mstream->blocking = parent->blocking;
	i_array_init(&mstream->channels, 8);
	i_stream_ref(parent);

	return i_stream_add_channel_real(mstream, 0);
}

uint8_t i_stream_multiplex_get_channel_id(struct istream *stream)
{
	struct multiplex_ichannel *channel =
		(struct multiplex_ichannel *)stream->real_stream;
	return channel->cid;
}
