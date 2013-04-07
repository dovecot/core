/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ostream-private.h"
#include "ostream-metawrap.h"

struct metawrap_ostream {
	struct ostream_private ostream;
	void (*write_callback)(void *);
	void *context;
};

static void o_stream_metawrap_call_callback(struct metawrap_ostream *mstream)
{
	void (*write_callback)(void *) = mstream->write_callback;

	if (write_callback != NULL) {
		mstream->write_callback = NULL;
		write_callback(mstream->context);
	}
}

static ssize_t
o_stream_metawrap_sendv(struct ostream_private *stream,
			const struct const_iovec *iov, unsigned int iov_count)
{
	struct metawrap_ostream *mstream = (struct metawrap_ostream *)stream;
	ssize_t ret;

	o_stream_metawrap_call_callback(mstream);
	if ((ret = o_stream_sendv(stream->parent, iov, iov_count)) < 0)
		o_stream_copy_error_from_parent(stream);
	return ret;
}

static off_t
o_stream_metawrap_send_istream(struct ostream_private *_outstream,
			       struct istream *instream)
{
	struct metawrap_ostream *outstream =
		(struct metawrap_ostream *)_outstream;
	off_t ret;

	o_stream_metawrap_call_callback(outstream);
	if ((ret = o_stream_send_istream(_outstream->parent, instream)) < 0)
		o_stream_copy_error_from_parent(_outstream);
	return ret;
}

struct ostream *
o_stream_create_metawrap(struct ostream *output,
			 void (*write_callback)(void *), void *context)
{
	struct metawrap_ostream *mstream;

	mstream = i_new(struct metawrap_ostream, 1);
	mstream->ostream.sendv = o_stream_metawrap_sendv;
	mstream->ostream.send_istream = o_stream_metawrap_send_istream;
	mstream->write_callback = write_callback;
	mstream->context = context;

	return o_stream_create(&mstream->ostream, output,
			       o_stream_get_fd(output));
}
