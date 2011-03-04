/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "ostream-internal.h"
#include "ostream-cmp.h"

struct cmp_ostream {
	struct ostream_private ostream;

	struct istream *input;
	struct ostream *output;
	bool equals;
};

static void cstream_copy_error(struct cmp_ostream *cstream)
{
	struct ostream *src = cstream->output;
	struct ostream *dest = &cstream->ostream.ostream;

	dest->stream_errno = src->stream_errno;
	dest->last_failed_errno = src->last_failed_errno;
	dest->overflow = src->overflow;
}

static void o_stream_cmp_close(struct iostream_private *stream)
{
	struct cmp_ostream *cstream = (struct cmp_ostream *)stream;

	if (cstream->output == NULL)
		return;

	i_stream_unref(&cstream->input);
	o_stream_flush(&cstream->ostream.ostream);
	o_stream_unref(&cstream->output);
}

static int o_stream_cmp_flush(struct ostream_private *stream)
{
	struct cmp_ostream *cstream = (struct cmp_ostream *)stream;
	int ret;

	ret = o_stream_flush(cstream->output);
	if (ret < 0)
		cstream_copy_error(cstream);
	return ret;
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

	if ((ret = o_stream_sendv(cstream->output, iov, iov_count)) < 0) {
		cstream_copy_error(cstream);
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
	cstream->ostream.flush = o_stream_cmp_flush;
	cstream->ostream.iostream.close = o_stream_cmp_close;
	cstream->input = input;
	cstream->output = output;
	cstream->equals = TRUE;
	i_stream_ref(input);
	o_stream_ref(output);

	return o_stream_create(&cstream->ostream);
}

bool o_stream_cmp_equals(struct ostream *_output)
{
	struct cmp_ostream *cstream =
		(struct cmp_ostream *)_output->real_stream;

	return cstream->equals;
}
