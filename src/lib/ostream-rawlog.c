/* Copyright (c) 2011-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "iostream-rawlog-private.h"
#include "ostream-private.h"
#include "ostream-rawlog.h"

struct rawlog_ostream {
	struct ostream_private ostream;
	struct rawlog_iostream riostream;
};

static void o_stream_rawlog_close(struct iostream_private *stream,
				  bool close_parent)
{
	struct rawlog_ostream *rstream = (struct rawlog_ostream *)stream;

	(void)o_stream_flush(rstream->ostream.parent);
	iostream_rawlog_close(&rstream->riostream);

	if (close_parent)
		o_stream_close(rstream->ostream.parent);
}

static ssize_t
o_stream_rawlog_sendv(struct ostream_private *stream,
		      const struct const_iovec *iov, unsigned int iov_count)
{
	struct rawlog_ostream *rstream = (struct rawlog_ostream *)stream;
	unsigned int i;
	ssize_t ret, bytes;

	if ((ret = o_stream_sendv(stream->parent, iov, iov_count)) < 0) {
		o_stream_copy_error_from_parent(stream);
		return -1;
	}
	bytes = ret;
	for (i = 0; i < iov_count && bytes > 0; i++) {
		if (iov[i].iov_len < (size_t)bytes) {
			iostream_rawlog_write(&rstream->riostream,
					      iov[i].iov_base, iov[i].iov_len);
			bytes -= iov[i].iov_len;
		} else {
			iostream_rawlog_write(&rstream->riostream,
					      iov[i].iov_base, bytes);
			break;
		}
	}

	stream->ostream.offset += ret;
	return ret;
}

struct ostream *
o_stream_create_rawlog(struct ostream *output, const char *rawlog_path,
		       int rawlog_fd, enum iostream_rawlog_flags flags)
{
	struct rawlog_ostream *rstream;

	i_assert(rawlog_path != NULL);
	i_assert(rawlog_fd != -1);

	rstream = i_new(struct rawlog_ostream, 1);
	rstream->ostream.sendv = o_stream_rawlog_sendv;
	rstream->ostream.iostream.close = o_stream_rawlog_close;

	rstream->riostream.rawlog_path = i_strdup(rawlog_path);
	rstream->riostream.rawlog_fd = rawlog_fd;
	iostream_rawlog_init(&rstream->riostream, flags, FALSE);

	return o_stream_create(&rstream->ostream, output, -1);
}
