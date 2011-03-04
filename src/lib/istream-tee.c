/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream-internal.h"
#include "istream-tee.h"

struct tee_istream {
	struct istream *input;
	struct tee_child_istream *children;

	uoff_t max_read_offset;
};

struct tee_child_istream {
	struct istream_private istream;

	struct tee_istream *tee;
	struct tee_child_istream *next;

	unsigned int last_read_waiting:1;
};

static void tee_streams_update_buffer(struct tee_istream *tee)
{
	struct tee_child_istream *tstream = tee->children;
	const unsigned char *data;
	size_t size, old_used;

	data = i_stream_get_data(tee->input, &size);
	for (; tstream != NULL; tstream = tstream->next) {
		if (tstream->istream.istream.closed) {
			tstream->istream.skip = tstream->istream.pos = 0;
			continue;
		}
		old_used = tstream->istream.pos - tstream->istream.skip;

		tstream->istream.buffer = data;
		tstream->istream.skip = tstream->istream.istream.v_offset -
			tee->input->v_offset;
		i_assert(tstream->istream.skip + old_used <= size);
		tstream->istream.pos = tstream->istream.skip + old_used;

		tstream->istream.parent_expected_offset =
			tee->input->v_offset;
		tstream->istream.access_counter =
			tee->input->real_stream->access_counter;
	}
}

static void tee_streams_skip(struct tee_istream *tee)
{
	struct tee_child_istream *tstream = tee->children;
	size_t min_skip;

	min_skip = (size_t)-1;
	for (; tstream != NULL; tstream = tstream->next) {
		if (tstream->istream.skip < min_skip &&
		    !tstream->istream.istream.closed)
			min_skip = tstream->istream.skip;
	}

	if (min_skip > 0 && min_skip != (size_t)-1) {
		i_stream_skip(tee->input, min_skip);
		tee_streams_update_buffer(tee);
	}
}

static void i_stream_tee_close(struct iostream_private *stream)
{
	struct tee_child_istream *tstream = (struct tee_child_istream *)stream;

	tee_streams_skip(tstream->tee);
}

static void i_stream_tee_destroy(struct iostream_private *stream)
{
	struct tee_child_istream *tstream = (struct tee_child_istream *)stream;
	struct tee_istream *tee = tstream->tee;
	struct tee_child_istream **p;

	if (tstream->istream.istream.v_offset > tee->max_read_offset)
		tee->max_read_offset = tstream->istream.istream.v_offset;

	for (p = &tee->children; *p != NULL; p = &(*p)->next) {
		if (*p == tstream) {
			*p = tstream->next;
			break;
		}
	}

	if (tee->children == NULL) {
		/* last child. the tee is now destroyed */
		i_assert(tee->input->v_offset <= tee->max_read_offset);
		i_stream_skip(tee->input,
			      tee->max_read_offset - tee->input->v_offset);

		i_stream_unref(&tee->input);
		i_free(tee);
	} else {
		tee_streams_skip(tstream->tee);
	}
}

static void
i_stream_tee_set_max_buffer_size(struct iostream_private *stream,
				 size_t max_size)
{
	struct tee_child_istream *tstream = (struct tee_child_istream *)stream;

	tstream->istream.max_buffer_size = max_size;
	i_stream_set_max_buffer_size(tstream->tee->input, max_size);
}

static ssize_t i_stream_tee_read(struct istream_private *stream)
{
	struct tee_child_istream *tstream = (struct tee_child_istream *)stream;
	struct istream *input = tstream->tee->input;
	const unsigned char *data;
	size_t size;
	uoff_t last_high_offset;
	ssize_t ret;

	tstream->last_read_waiting = FALSE;
	if (stream->buffer == NULL) {
		/* initial read */
		tee_streams_update_buffer(tstream->tee);
	}
	data = i_stream_get_data(input, &size);

	/* last_high_offset contains how far we have read this child tee stream
	   so far. input->v_offset + size contains how much is available in
	   the parent stream without having to read more. */
	last_high_offset = stream->istream.v_offset +
		(stream->pos - stream->skip);
	if (stream->pos == size) {
		/* we've read everything, need to read more */
		i_assert(last_high_offset == input->v_offset + size);
		tee_streams_skip(tstream->tee);
		ret = i_stream_read(input);
		if (ret <= 0) {
			(void)i_stream_get_data(input, &size);
			if (ret == -2 && stream->skip != 0) {
				/* someone else is holding the data,
				   wait for it */
				tstream->last_read_waiting = TRUE;
				return 0;
			}
			stream->istream.stream_errno = input->stream_errno;
			stream->istream.eof = input->eof;
			return ret;
		}
		tee_streams_update_buffer(tstream->tee);
		data = i_stream_get_data(input, &size);
	} else {
		/* there's still some data available from parent */
		i_assert(last_high_offset < input->v_offset + size);
		i_assert(stream->pos < size);
		stream->buffer = data;
	}

	i_assert(stream->buffer == data);
	ret = size - stream->pos;
	i_assert(ret > 0);
	stream->pos = size;
	return ret;
}

static const struct stat *
i_stream_tee_stat(struct istream_private *stream, bool exact)
{
	struct tee_child_istream *tstream = (struct tee_child_istream *)stream;

	return i_stream_stat(tstream->tee->input, exact);
}

static void i_stream_tee_sync(struct istream_private *stream)
{
	struct tee_child_istream *tstream = (struct tee_child_istream *)stream;
	size_t size;

	tee_streams_skip(tstream->tee);
	(void)i_stream_get_data(tstream->tee->input, &size);
	if (size != 0) {
		i_panic("tee-istream: i_stream_sync() called "
			"with data still buffered");
	}
	i_stream_sync(tstream->tee->input);
}

struct tee_istream *tee_i_stream_create(struct istream *input)
{
	struct tee_istream *tee;

	tee = i_new(struct tee_istream, 1);
	if (input->v_offset == 0) {
		i_stream_ref(input);
		tee->input = input;
	} else {
		tee->input = i_stream_create_limit(input, (uoff_t)-1);
	}
	return tee;
}

struct istream *tee_i_stream_create_child(struct tee_istream *tee)
{
	struct tee_child_istream *tstream;
	struct istream *ret, *input = tee->input;

	tstream = i_new(struct tee_child_istream, 1);
	tstream->tee = tee;

	tstream->istream.max_buffer_size = input->real_stream->max_buffer_size;
	tstream->istream.iostream.close = i_stream_tee_close;
	tstream->istream.iostream.destroy = i_stream_tee_destroy;
	tstream->istream.iostream.set_max_buffer_size =
		i_stream_tee_set_max_buffer_size;

	tstream->istream.read = i_stream_tee_read;
	tstream->istream.stat = i_stream_tee_stat;
	tstream->istream.sync = i_stream_tee_sync;

	tstream->next = tee->children;
	tee->children = tstream;

	ret = i_stream_create(&tstream->istream, input, i_stream_get_fd(input));
	/* we keep the reference in tee stream, no need for extra references */
	i_stream_unref(&input);
	return ret;
}

bool tee_i_stream_child_is_waiting(struct istream *input)
{
	struct tee_child_istream *tstream =
		(struct tee_child_istream *)input->real_stream;

	return tstream->last_read_waiting;
}
