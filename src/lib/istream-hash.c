/* Copyright (c) 2013-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hash-method.h"
#include "istream-private.h"
#include "istream-hash.h"

struct hash_istream {
	struct istream_private istream;

	const struct hash_method *method;
	void *hash_context;
	uoff_t high_offset;
};

static ssize_t
i_stream_hash_read(struct istream_private *stream)
{
	struct hash_istream *hstream = (struct hash_istream *)stream;
	const unsigned char *data;
	size_t size;
	uoff_t skip;
	ssize_t ret;

	i_stream_seek(stream->parent, stream->parent_start_offset +
		      stream->istream.v_offset);

	ret = i_stream_read_copy_from_parent(&stream->istream);
	if (ret > 0 && hstream->hash_context != NULL) {
		data = i_stream_get_data(&stream->istream, &size);
		i_assert((size_t)ret <= size);

		i_assert(stream->istream.v_offset <= hstream->high_offset);
		skip = hstream->high_offset - stream->istream.v_offset;
		if (skip < (size_t)size) {
			hstream->high_offset += (size-skip);
			hstream->method->loop(hstream->hash_context,
					      data+skip, size-skip);
		}
	} else if (ret < 0) {
		/* we finished hashing it. don't access it anymore, because
		   the memory pointed by the hash may be freed before the
		   istream itself */
		hstream->hash_context = NULL;
	}
	return ret;
}

static void
i_stream_hash_seek(struct istream_private *stream,
		   uoff_t v_offset, bool mark ATTR_UNUSED)
{
	struct hash_istream *hstream = (struct hash_istream *)stream;

	if (hstream->hash_context != NULL) {
		io_stream_set_error(&stream->iostream,
			"Seeking not supported before hashing is finished");
		stream->istream.stream_errno = ESPIPE;
	}
	stream->istream.v_offset = v_offset;
	stream->skip = stream->pos = 0;
}

struct istream *
i_stream_create_hash(struct istream *input, const struct hash_method *method,
		     void *hash_context)
{
	struct hash_istream *hstream;

	hstream = i_new(struct hash_istream, 1);
	hstream->istream.max_buffer_size = input->real_stream->max_buffer_size;
	hstream->istream.stream_size_passthrough = TRUE;

	hstream->istream.read = i_stream_hash_read;
	hstream->istream.seek = i_stream_hash_seek;

	hstream->istream.istream.readable_fd = input->readable_fd;
	hstream->istream.istream.blocking = input->blocking;
	hstream->istream.istream.seekable = input->seekable;

	hstream->method = method;
	hstream->hash_context = hash_context;
	return i_stream_create(&hstream->istream, input,
			       i_stream_get_fd(input));
}
