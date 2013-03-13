/* Copyright (c) 2010-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "ostream-private.h"
#include "ostream-cmp.h"

struct cmp_ostream {
	struct ostream_private ostream;

	struct istream *input;
	bool equals;
};

static void o_stream_cmp_close(struct iostream_private *stream,
			       bool close_parent)
{
	struct cmp_ostream *cstream = (struct cmp_ostream *)stream;

	if (cstream->input == NULL)
		return;

	i_stream_unref(&cstream->input);
	(void)o_stream_flush(&cstream->ostream.ostream);
	if (close_parent)
		o_stream_close(cstream->ostream.parent);
}

bool stream_cmp_block(struct istream *input,
		      const unsigned char *data, size_t size)
{
	const unsigned char *indata;
	size_t insize, max;

	while (size > 0) {
		(void)i_stream_read_data(input, &indata, &insize, size-1);
		max = I_MIN(insize, size);
		if (insize == 0 || memcmp(data, indata, max) != 0)
			return FALSE;
		data += max;
		size -= max;
		i_stream_skip(input, max);
	}
	return TRUE;
}

static ssize_t
o_stream_cmp_sendv(struct ostream_private *stream,
		   const struct const_iovec *iov, unsigned int iov_count)
{
	struct cmp_ostream *cstream = (struct cmp_ostream *)stream;
	unsigned int i;
	ssize_t ret;

	if (cstream->equals) {
		for (i = 0; i < iov_count; i++) {
			if (!stream_cmp_block(cstream->input, iov[i].iov_base,
					      iov[i].iov_len)) {
				cstream->equals = FALSE;
				break;
			}
		}
	}

	if ((ret = o_stream_sendv(stream->parent, iov, iov_count)) < 0) {
		o_stream_copy_error_from_parent(stream);
		return -1;
	}

	stream->ostream.offset += ret;
	return ret;
}

struct ostream *
o_stream_create_cmp(struct ostream *output, struct istream *input)
{
	struct cmp_ostream *cstream;

	cstream = i_new(struct cmp_ostream, 1);
	cstream->ostream.sendv = o_stream_cmp_sendv;
	cstream->ostream.iostream.close = o_stream_cmp_close;
	cstream->input = input;
	cstream->equals = TRUE;
	i_stream_ref(input);

	return o_stream_create(&cstream->ostream, output,
			       o_stream_get_fd(output));
}

bool o_stream_cmp_equals(struct ostream *_output)
{
	struct cmp_ostream *cstream =
		(struct cmp_ostream *)_output->real_stream;

	return cstream->equals;
}
