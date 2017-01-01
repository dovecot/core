/* Copyright (c) 2015-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream-private.h"
#include "istream-failure-at.h"

struct failure_at_istream {
	struct istream_private istream;
	char *error_string;
	uoff_t failure_offset;
};

static void i_stream_failure_at_destroy(struct iostream_private *stream)
{
	struct failure_at_istream *fstream =
		(struct failure_at_istream *)stream;

	i_free(fstream->error_string);
}

static ssize_t
i_stream_failure_at_read(struct istream_private *stream)
{
	struct failure_at_istream *fstream = (struct failure_at_istream *)stream;
	uoff_t new_offset;
	ssize_t ret;

	i_stream_seek(stream->parent, stream->parent_start_offset +
		      stream->istream.v_offset);

	ret = i_stream_read_copy_from_parent(&stream->istream);
	new_offset = stream->istream.v_offset + (stream->pos - stream->skip);
	if (ret >= 0 && new_offset >= fstream->failure_offset) {
		if (stream->istream.v_offset >= fstream->failure_offset) {
			/* we already passed the wanted failure offset,
			   return error immediately. */
			stream->pos = stream->skip;
			stream->istream.stream_errno = errno = EIO;
			io_stream_set_error(&stream->iostream, "%s",
					    fstream->error_string);
			ret = -1;
		} else {
			/* return data up to the wanted failure offset and
			   on the next read() call return failure */
			size_t new_pos = fstream->failure_offset -
				stream->istream.v_offset + stream->skip;
			i_assert(new_pos >= stream->skip &&
				 stream->pos >= new_pos);
			ret -= stream->pos - new_pos;
			stream->pos = new_pos;
		}
	} else if (ret < 0 && stream->istream.stream_errno == 0 &&
		   fstream->failure_offset == (uoff_t)-1) {
		/* failure at EOF */
		stream->istream.stream_errno = errno = EIO;
		io_stream_set_error(&stream->iostream, "%s",
				    fstream->error_string);
	}
	return ret;
}

struct istream *
i_stream_create_failure_at(struct istream *input, uoff_t failure_offset,
			   const char *error_string)
{
	struct failure_at_istream *fstream;

	fstream = i_new(struct failure_at_istream, 1);
	fstream->istream.max_buffer_size = input->real_stream->max_buffer_size;
	fstream->istream.stream_size_passthrough = TRUE;

	fstream->istream.read = i_stream_failure_at_read;
	fstream->istream.iostream.destroy = i_stream_failure_at_destroy;

	fstream->istream.istream.readable_fd = input->readable_fd;
	fstream->istream.istream.blocking = input->blocking;
	fstream->istream.istream.seekable = input->seekable;

	fstream->error_string = i_strdup(error_string);
	fstream->failure_offset = failure_offset;
	return i_stream_create(&fstream->istream, input,
			       i_stream_get_fd(input));
}

struct istream *
i_stream_create_failure_at_eof(struct istream *input, const char *error_string)
{
	return i_stream_create_failure_at(input, (uoff_t)-1, error_string);
}
