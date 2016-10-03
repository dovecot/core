/* Copyright (c) 2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "ostream-private.h"
#include "test-common.h"

struct test_ostream {
	struct ostream_private ostream;
	buffer_t *internal_buf;
	buffer_t *output_buf;
	size_t max_output_size;
	struct timeout *to;
	bool flush_pending;
};

static void o_stream_test_destroy(struct iostream_private *stream)
{
	struct test_ostream *tstream = (struct test_ostream *)stream;

	if (tstream->to != NULL)
		timeout_remove(&tstream->to);
	if (tstream->internal_buf != NULL)
		buffer_free(&tstream->internal_buf);
}

static int o_stream_test_flush(struct ostream_private *stream)
{
	struct test_ostream *tstream = (struct test_ostream *)stream;

	if (tstream->internal_buf == NULL || tstream->internal_buf->used == 0)
		return 1;
	if (tstream->output_buf->used >= tstream->max_output_size)
		return 0;

	size_t left = tstream->max_output_size - tstream->output_buf->used;
	size_t n = I_MIN(left, tstream->internal_buf->used);
	buffer_append(tstream->output_buf, tstream->internal_buf->data, n);
	buffer_delete(tstream->internal_buf, 0, n);
	return tstream->internal_buf->used == 0 ? 1 : 0;
}

static ssize_t
o_stream_test_sendv(struct ostream_private *stream,
		    const struct const_iovec *iov, unsigned int iov_count)
{
	struct test_ostream *tstream = (struct test_ostream *)stream;
	struct const_iovec cur_iov = { NULL, 0 };
	size_t left, n;
	ssize_t ret = 0;
	unsigned int i;

	/* first we need to try to flush the internal buffer */
	if ((ret = o_stream_test_flush(stream)) <= 0)
		return ret;

	/* append to output_buf until max_output_size is reached */
	ret = 0;
	for (i = 0; i < iov_count; i++) {
		left = tstream->max_output_size < tstream->output_buf->used ? 0 :
			tstream->max_output_size - tstream->output_buf->used;
		n = I_MIN(left, iov[i].iov_len);
		buffer_append(tstream->output_buf, iov[i].iov_base, n);
		stream->ostream.offset += n;
		ret += n;
		if (n != iov[i].iov_len) {
			cur_iov.iov_base = CONST_PTR_OFFSET(iov[i].iov_base, n);
			cur_iov.iov_len = iov[i].iov_len - n;
			break;
		}
	}
	/* if we've internal_buf, append to it until max_buffer_size is
	   reached */
	if (i == iov_count || tstream->internal_buf == NULL)
		return ret;
	do {
		left = tstream->ostream.max_buffer_size -
			tstream->internal_buf->used;
		n = I_MIN(left, cur_iov.iov_len);
		buffer_append(tstream->internal_buf, cur_iov.iov_base, n);
		stream->ostream.offset += n;
		ret += n;
		if (n != cur_iov.iov_len)
			break;
		if (++i < iov_count)
			cur_iov = iov[i];
	} while (i < iov_count);

	tstream->flush_pending = TRUE;
	return ret;
}

static void test_ostream_send_more(struct test_ostream *tstream)
{
	struct ostream *ostream = &tstream->ostream.ostream;
	int ret;

	o_stream_ref(ostream);
	tstream->flush_pending = FALSE;
	if (tstream->ostream.callback != NULL)
		ret = tstream->ostream.callback(tstream->ostream.context);
	else
		ret = o_stream_test_flush(&tstream->ostream);
	if (ret == 0 || (tstream->internal_buf != NULL &&
			 tstream->internal_buf->used > 0))
		tstream->flush_pending = TRUE;
	if (!tstream->flush_pending ||
	    tstream->output_buf->used >= tstream->max_output_size)
		timeout_remove(&tstream->to);
	o_stream_unref(&ostream);
}

static void test_ostream_set_send_more_timeout(struct test_ostream *tstream)
{
	if (tstream->to == NULL && tstream->flush_pending &&
	    tstream->output_buf->used < tstream->max_output_size)
		tstream->to = timeout_add_short(0, test_ostream_send_more, tstream);
}

static void
o_stream_test_flush_pending(struct ostream_private *stream, bool set)
{
	struct test_ostream *tstream = (struct test_ostream *)stream;

	if (tstream->internal_buf != NULL && tstream->internal_buf->used > 0) {
		/* we have internal data, won't reset flush_pending */
		i_assert(tstream->flush_pending);
	} else {
		tstream->flush_pending = set;
	}
	if (set)
		test_ostream_set_send_more_timeout(tstream);
}

static size_t
o_stream_test_get_used_size(const struct ostream_private *stream)
{
	struct test_ostream *tstream = (struct test_ostream *)stream;

	return tstream->internal_buf == NULL ? 0 :
		tstream->internal_buf->used;
}

struct ostream *test_ostream_create(buffer_t *output)
{
	struct test_ostream *tstream;
	struct ostream *ostream;

	tstream = i_new(struct test_ostream, 1);
	tstream->ostream.max_buffer_size = (size_t)-1;
	tstream->ostream.iostream.destroy = o_stream_test_destroy;
	tstream->ostream.sendv = o_stream_test_sendv;
	tstream->ostream.flush = o_stream_test_flush;
	tstream->ostream.flush_pending = o_stream_test_flush_pending;
	tstream->ostream.get_used_size = o_stream_test_get_used_size;
	tstream->ostream.ostream.blocking = TRUE;

	tstream->output_buf = output;
	tstream->max_output_size = (size_t)-1;
	ostream = o_stream_create(&tstream->ostream, NULL, -1);
	o_stream_set_name(ostream, "(test-ostream)");
	return ostream;
}

struct ostream *test_ostream_create_nonblocking(buffer_t *output,
						size_t max_internal_buffer_size)
{
	struct test_ostream *tstream;

	tstream = (struct test_ostream *)test_ostream_create(output)->real_stream;
	tstream->internal_buf = buffer_create_dynamic(default_pool, 128);
	tstream->ostream.ostream.blocking = FALSE;
	tstream->ostream.max_buffer_size = max_internal_buffer_size;
	return &tstream->ostream.ostream;
}

static struct test_ostream *test_ostream_find(struct ostream *output)
{
	struct ostream *out;

	for (out = output; out != NULL; out = out->real_stream->parent) {
		if (out->real_stream->sendv == o_stream_test_sendv)
			return (struct test_ostream *)out->real_stream;
	}
	i_panic("%s isn't test-ostream", o_stream_get_name(output));
}

void test_ostream_set_max_output_size(struct ostream *output, size_t max_size)
{
	struct test_ostream *tstream = test_ostream_find(output);

	tstream->max_output_size = max_size;
	test_ostream_set_send_more_timeout(tstream);
}
