/* Copyright (c) 2004 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "istream.h"
#include "ostream-internal.h"
#include "ostream-crlf.h"

#define IOVBUF_COUNT 64

struct crlf_ostream {
	struct _ostream ostream;

        struct ostream *output;
	int last_cr;
};

static void _close(struct _iostream *stream)
{
	struct crlf_ostream *cstream = (struct crlf_ostream *)stream;

	o_stream_close(cstream->output);
}

static void _destroy(struct _iostream *stream)
{
	struct crlf_ostream *cstream = (struct crlf_ostream *)stream;

	o_stream_ref(cstream->output);
}

static void _set_max_buffer_size(struct _iostream *stream, size_t max_size)
{
	struct crlf_ostream *cstream = (struct crlf_ostream *)stream;

	o_stream_set_max_buffer_size(cstream->output, max_size);
}

static void _cork(struct _ostream *stream, int set)
{
	struct crlf_ostream *cstream = (struct crlf_ostream *)stream;

	if (set)
		o_stream_cork(cstream->output);
	else
		o_stream_uncork(cstream->output);
}

static int _flush(struct _ostream *stream)
{
	struct crlf_ostream *cstream = (struct crlf_ostream *)stream;

	return o_stream_flush(cstream->output);
}

static size_t _get_used_size(struct _ostream *stream)
{
	struct crlf_ostream *cstream = (struct crlf_ostream *)stream;

	return o_stream_get_buffer_used_size(cstream->output);
}

static int _seek(struct _ostream *stream, uoff_t offset)
{
	struct crlf_ostream *cstream = (struct crlf_ostream *)stream;

	cstream->last_cr = FALSE;
	return o_stream_seek(cstream->output, offset);
}

static ssize_t sendv_crlf(struct crlf_ostream *cstream,
			  const struct const_iovec *iov, size_t iov_count)
{
	ssize_t ret;
	size_t pos;

	ret = o_stream_sendv(cstream->output, iov, iov_count);
	if (ret > 0) {
		pos = (size_t)ret - 1;
		while (pos >= iov->iov_len) {
			pos -= iov->iov_len;
			iov++;
		}

		cstream->last_cr = *((const char *)iov->iov_base + pos) == '\r';
	}
	return ret;
}

static ssize_t
_sendv_crlf(struct _ostream *stream, const struct const_iovec *iov,
	    size_t iov_count)
{
	static const struct const_iovec cr_iov = { "\r", 1 };
	struct crlf_ostream *cstream = (struct crlf_ostream *)stream;
	buffer_t *buf;
	const unsigned char *data;
	struct const_iovec new_iov;
	size_t vec, i, len, start, new_iov_count = 0, new_iov_size = 0;
	ssize_t ret;
	int last_cr;

	last_cr = cstream->last_cr;

	t_push();
	buf = buffer_create_dynamic(unsafe_data_stack_pool,
				    sizeof(struct const_iovec *) * IOVBUF_COUNT,
				    (size_t)-1);
	for (vec = 0; vec < iov_count; vec++) {
		data = iov[vec].iov_base;
		len = iov[vec].iov_len;

		for (i = start = 0;; i++) {
			if (i != len) {
				if (data[i] != '\n')
					continue;

				if (i > 0) {
					if (data[i-1] == '\r')
						continue;
				} else {
					if (last_cr)
						continue;
				}

				/* need to insert CR */
			}

			if (i != start) {
				new_iov.iov_base = data + start;
				new_iov.iov_len = i - start;

				buffer_append(buf, &new_iov, sizeof(new_iov));
				new_iov_count++;
				new_iov_size += new_iov.iov_len;
			}
			start = i;

			if (i != len) {
				buffer_append(buf, &cr_iov, sizeof(cr_iov));
				new_iov_count++;
				new_iov_size++;
			}

			if (new_iov_count >= IOVBUF_COUNT-1) {
				ret = sendv_crlf(cstream, buf->data,
						 new_iov_count);
				if (ret != (ssize_t)new_iov_size) {
					t_pop();
					return ret;
				}

				buffer_set_used_size(buf, 0);
				new_iov_count = 0;
				new_iov_size = 0;
			}

			if (i == len)
				break;
		}

		if (len != 0)
			last_cr = data[len-1] == '\r';
	}

	ret = sendv_crlf(cstream, buf->data, new_iov_count);
	t_pop();
	return ret;
}

static ssize_t
_sendv_lf(struct _ostream *stream, const struct const_iovec *iov,
	  size_t iov_count)
{
	struct crlf_ostream *cstream = (struct crlf_ostream *)stream;
	buffer_t *buf;
	const unsigned char *data;
	struct const_iovec new_iov;
	size_t vec, i, len, start, new_iov_count = 0, new_iov_size = 0;
	ssize_t ret;

	t_push();
	buf = buffer_create_dynamic(unsafe_data_stack_pool,
				    sizeof(struct const_iovec *) * IOVBUF_COUNT,
				    (size_t)-1);
	for (vec = 0; vec < iov_count; vec++) {
		data = iov[vec].iov_base;
		len = iov[vec].iov_len;

		for (i = start = 0;; i++) {
			if (i != len && data[i] != '\r')
				continue;

			if (i != start) {
				new_iov.iov_base = data + start;
				new_iov.iov_len = i - start;

				buffer_append(buf, &new_iov, sizeof(new_iov));
				new_iov_count++;
				new_iov_size += new_iov.iov_len;
			}
			start = i+1;

			if (new_iov_count == IOVBUF_COUNT) {
				ret = o_stream_sendv(cstream->output,
						     buf->data, new_iov_count);
				if (ret != (ssize_t)new_iov_size) {
					t_pop();
					return ret;
				}

				buffer_set_used_size(buf, 0);
				new_iov_count = 0;
				new_iov_size = 0;
			}

			if (i == len)
				break;
		}
	}

	ret = o_stream_sendv(cstream->output, buf->data, new_iov_count);
	t_pop();
	return ret;
}

static off_t
_send_istream(struct _ostream *outstream, struct istream *instream)
{
	struct const_iovec iov;
	size_t sent = 0;
	ssize_t ret;

	while ((ret = i_stream_read(instream)) != -1) {
		if (ret == 0)
			return sent;

		iov.iov_base = i_stream_get_data(instream, &iov.iov_len);
		ret = o_stream_sendv(&outstream->ostream, &iov, 1);
		if (ret <= 0)
			return ret < 0 && sent == 0 ? -1 : (ssize_t)sent;

		i_stream_skip(instream, ret);
		sent += ret;

		if ((size_t)ret != iov.iov_len)
			return sent;
	}

	return sent == 0 ? -1 : (ssize_t)sent;
}

static struct crlf_ostream *
o_stream_create_common(pool_t pool, struct ostream *output)
{
	struct crlf_ostream *cstream;

	cstream = p_new(pool, struct crlf_ostream, 1);
	cstream->output = output;
	o_stream_ref(output);

	cstream->ostream.iostream.close = _close;
	cstream->ostream.iostream.destroy = _destroy;
	cstream->ostream.iostream.set_max_buffer_size = _set_max_buffer_size;

	cstream->ostream.cork = _cork;
	cstream->ostream.flush = _flush;
	cstream->ostream.get_used_size = _get_used_size;
	cstream->ostream.seek = _seek;
	cstream->ostream.send_istream = _send_istream;
	return cstream;
}

struct ostream *o_stream_create_crlf(pool_t pool, struct ostream *output)
{
	struct crlf_ostream *cstream;

	cstream = o_stream_create_common(pool, output);
	cstream->ostream.sendv = _sendv_crlf;
	return _o_stream_create(&cstream->ostream, pool);
}

struct ostream *o_stream_create_lf(pool_t pool, struct ostream *output)
{
	struct crlf_ostream *cstream;

	cstream = o_stream_create_common(pool, output);
	cstream->ostream.sendv = _sendv_lf;
	return _o_stream_create(&cstream->ostream, pool);
}
