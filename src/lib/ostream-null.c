/* Copyright (c) 2016-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ostream-private.h"
#include "ostream-null.h"

static ssize_t
o_stream_null_sendv(struct ostream_private *stream,
		    const struct const_iovec *iov, unsigned int iov_count)
{
	unsigned int i;
	size_t ret = 0;

	for (i = 0; i < iov_count; i++)
		ret += iov[i].iov_len;
	stream->ostream.offset += ret;
	return ret;
}

struct ostream *o_stream_create_null(void)
{
	struct ostream_private *stream;
	struct ostream *output;

	stream = i_new(struct ostream_private, 1);
	stream->ostream.blocking = TRUE;
	stream->sendv = o_stream_null_sendv;

	output = o_stream_create(stream, NULL, -1);
	o_stream_set_no_error_handling(output, TRUE);
	o_stream_set_name(output, "(/dev/null)");
	return output;
}
