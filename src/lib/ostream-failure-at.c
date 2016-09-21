/* Copyright (c) 2015-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "ostream-private.h"
#include "ostream-failure-at.h"

struct failure_at_ostream {
	struct ostream_private ostream;
	char *error_string;
	uoff_t failure_offset;
	bool failed;
};

static void o_stream_failure_at_destroy(struct iostream_private *stream)
{
	struct failure_at_ostream *fstream =
		(struct failure_at_ostream *)stream;

	i_free(fstream->error_string);
	o_stream_unref(&fstream->ostream.parent);
}

static ssize_t
o_stream_failure_at_sendv(struct ostream_private *stream,
			  const struct const_iovec *iov, unsigned int iov_count)
{
	struct failure_at_ostream *fstream =
		(struct failure_at_ostream *)stream;
	unsigned int i;
	struct const_iovec *iov_dup;
	unsigned int iov_dup_count;
	uoff_t bytes_until_failure, blocking_bytes_count = 0;
	ssize_t ret;

	if (stream->ostream.blocking) {
		/* blocking ostream must return either a full success or a
		   failure. if the current write would go past failure_offset,
		   return a failure now before writing anything. */
		for (i = 0; i < iov_count; i++)
			blocking_bytes_count += iov[i].iov_len;
		if (blocking_bytes_count > 0) {
			/* if we're exactly at the failure offset after this
			   write, fail it only on the next write. */
			blocking_bytes_count--;
		}
	}

	if (fstream->failure_offset <= stream->ostream.offset + blocking_bytes_count) {
		io_stream_set_error(&stream->iostream, "%s",
				    fstream->error_string);
		stream->ostream.stream_errno = errno = EIO;
		fstream->failed = TRUE;
		return -1;
	}
	bytes_until_failure = fstream->failure_offset - stream->ostream.offset;

	iov_dup = i_new(struct const_iovec, iov_count);
	iov_dup_count = iov_count;
	for (i = 0; i < iov_count; i++) {
		iov_dup[i] = iov[i];
		if (iov_dup[i].iov_len >= bytes_until_failure) {
			iov_dup[i].iov_len = bytes_until_failure;
			iov_dup_count = i+1;
			break;
		}
	}
	ret = o_stream_sendv(stream->parent, iov_dup, iov_dup_count);
	i_free(iov_dup);

	if (ret < 0) {
		o_stream_copy_error_from_parent(stream);
		return -1;
	}
	stream->ostream.offset += ret;
	return ret;
}

static int
o_stream_failure_at_flush(struct ostream_private *stream)
{
	struct failure_at_ostream *fstream =
		(struct failure_at_ostream *)stream;

	if (fstream->failed) {
		io_stream_set_error(&stream->iostream, "%s",
				    fstream->error_string);
		stream->ostream.stream_errno = errno = EIO;
		return -1;
	}
	return o_stream_flush(stream->parent);
}

struct ostream *
o_stream_create_failure_at(struct ostream *output, uoff_t failure_offset,
			   const char *error_string)
{
	struct failure_at_ostream *fstream;

	fstream = i_new(struct failure_at_ostream, 1);
	fstream->ostream.sendv = o_stream_failure_at_sendv;
	fstream->ostream.flush = o_stream_failure_at_flush;
	fstream->ostream.iostream.destroy = o_stream_failure_at_destroy;
	fstream->failure_offset = failure_offset;
	fstream->error_string = i_strdup(error_string);
	return o_stream_create(&fstream->ostream, output,
			       o_stream_get_fd(output));
}

struct ostream *
o_stream_create_failure_at_flush(struct ostream *output, const char *error_string)
{
	struct failure_at_ostream *fstream;

	fstream = i_new(struct failure_at_ostream, 1);
	fstream->ostream.flush = o_stream_failure_at_flush;
	fstream->ostream.iostream.destroy = o_stream_failure_at_destroy;
	fstream->error_string = i_strdup(error_string);
	fstream->failed = TRUE;
	return o_stream_create(&fstream->ostream, output,
			       o_stream_get_fd(output));
}
