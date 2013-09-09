/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hash-method.h"
#include "istream-private.h"
#include "istream-hash.h"

struct hash_istream {
	struct istream_private istream;

	const struct hash_method *method;
	void *hash_context;
};

static ssize_t
i_stream_hash_read(struct istream_private *stream)
{
	struct hash_istream *hstream = (struct hash_istream *)stream;
	const unsigned char *data;
	size_t size;
	ssize_t ret;

	i_stream_seek(stream->parent, stream->parent_start_offset +
		      stream->istream.v_offset);

	ret = i_stream_read_copy_from_parent(&stream->istream);
	if (ret > 0 && hstream->hash_context != NULL) {
		data = i_stream_get_data(&stream->istream, &size);
		i_assert((size_t)ret <= size);
		hstream->method->loop(hstream->hash_context,
				      data+(size-ret), ret);
	} else if (ret < 0) {
		/* we finished hashing it. don't access it anymore, because
		   the memory pointed by the hash may be freed before the
		   istream itself */
		hstream->hash_context = NULL;
	}
	return ret;
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

	hstream->istream.istream.blocking = input->blocking;
	hstream->istream.istream.seekable = FALSE;

	hstream->method = method;
	hstream->hash_context = hash_context;
	return i_stream_create(&hstream->istream, input,
			       i_stream_get_fd(input));
}
