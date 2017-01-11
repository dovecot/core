/* Copyright (c) 2016-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "ostream.h"
#include "ostream-private.h"
#include "ostream-escaped.h"

struct escaped_ostream {
	struct ostream_private ostream;
	ostream_escaped_escape_formatter_t format;

	string_t *buf;
	bool flushed;
};

static ssize_t
o_stream_escaped_send_outbuf(struct escaped_ostream *estream)
{
	ssize_t ret;

	if (estream->flushed)
		return 1; /* nothing to send */
	ret = o_stream_send(estream->ostream.parent, str_data(estream->buf), str_len(estream->buf));
	if (ret < 0) {
		o_stream_copy_error_from_parent(&estream->ostream);
		return -1;
	}
	if ((size_t)ret != str_len(estream->buf)) {
		/* move data */
		str_delete(estream->buf, 0, ret);
		return 0;
	}
	str_truncate(estream->buf, 0);
	estream->flushed = TRUE;
	return 1;
}

static ssize_t
o_stream_escaped_send_chunk(struct escaped_ostream *estream,
			    const unsigned char *data, size_t len)
{
	size_t i, max_buffer_size;
	ssize_t ret;

	max_buffer_size = I_MIN(o_stream_get_max_buffer_size(estream->ostream.parent),
				estream->ostream.max_buffer_size);
	if (max_buffer_size > IO_BLOCK_SIZE) {
		/* avoid using up too much memory in case of large buffers */
		max_buffer_size = IO_BLOCK_SIZE;
	}

	for (i = 0; i < len; i++) {
		if (str_len(estream->buf) + 2 > max_buffer_size) { /* escaping takes at least two bytes */
			ret = o_stream_escaped_send_outbuf(estream);
			if (ret < 0) {
				estream->ostream.ostream.offset += i;
				return ret;
			}
			if (ret == 0)
				break;
		}
		estream->format(estream->buf, data[i]);
		estream->flushed = FALSE;
	}
	estream->ostream.ostream.offset += i;
	return i;
}

static ssize_t
o_stream_escaped_sendv(struct ostream_private *stream,
		       const struct const_iovec *iov, unsigned int iov_count)
{
	struct escaped_ostream *estream = (struct escaped_ostream *)stream;
	unsigned int iov_cur;
	ssize_t ret, bytes = 0;

	for (iov_cur = 0; iov_cur < iov_count; iov_cur++) {
		ret = o_stream_escaped_send_chunk(estream,
				iov[iov_cur].iov_base, iov[iov_cur].iov_len);
		if (ret < 0)
			return ret;
		bytes += ret;
		if ((size_t)ret != iov[iov_cur].iov_len)
			break;
	}
	if (o_stream_escaped_send_outbuf(estream) < 0)
		return -1;
	return bytes;
}

static int
o_stream_escaped_flush(struct ostream_private *stream)
{
	struct escaped_ostream *estream = (struct escaped_ostream *)stream;
	int ret;

	if ((ret = o_stream_escaped_send_outbuf(estream)) <= 0)
		return ret;
	if ((ret = o_stream_flush(stream->parent)) < 0)
		o_stream_copy_error_from_parent(stream);
	return ret;
}

static void o_stream_escaped_destroy(struct iostream_private *stream)
{
	struct escaped_ostream *estream = (struct escaped_ostream *)stream;

	str_free(&estream->buf);
	o_stream_unref(&estream->ostream.parent);
}

void ostream_escaped_hex_format(string_t *dest, unsigned char chr)
{
	str_printfa(dest, "%02x", chr);
}

struct ostream *
o_stream_create_escaped(struct ostream *output,
			ostream_escaped_escape_formatter_t format)
{
	struct escaped_ostream *estream;

	estream = i_new(struct escaped_ostream, 1);
	estream->ostream.sendv = o_stream_escaped_sendv;
	estream->ostream.flush = o_stream_escaped_flush;
	estream->ostream.max_buffer_size = o_stream_get_max_buffer_size(output);
	estream->ostream.iostream.destroy = o_stream_escaped_destroy;
	estream->buf = str_new(default_pool, 512);
	estream->format = format;
	estream->flushed = FALSE;

	return o_stream_create(&estream->ostream, output, o_stream_get_fd(output));
}
