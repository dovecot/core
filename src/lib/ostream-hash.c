/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hash-method.h"
#include "ostream-private.h"
#include "ostream-hash.h"

struct hash_ostream {
	struct ostream_private ostream;
	const struct hash_method *method;
	void *hash_context;
};

static ssize_t
o_stream_hash_sendv(struct ostream_private *stream,
		    const struct const_iovec *iov, unsigned int iov_count)
{
	struct hash_ostream *hstream = (struct hash_ostream *)stream;
	unsigned int i;
	size_t bytes_left, block_len;
	ssize_t ret;

	if ((ret = o_stream_sendv(stream->parent, iov, iov_count)) < 0) {
		o_stream_copy_error_from_parent(stream);
		return -1;
	}
	if (ret > 0) {
		bytes_left = ret;
		for (i = 0; i < iov_count && bytes_left > 0; i++) {
			block_len = iov[i].iov_len <= bytes_left ?
				iov[i].iov_len : bytes_left;
			hstream->method->loop(hstream->hash_context,
					      iov[i].iov_base, block_len);
			bytes_left -= block_len;
		}
	}

	stream->ostream.offset += ret;
	return ret;
}

struct ostream *
o_stream_create_hash(struct ostream *output, const struct hash_method *method,
		     void *hash_context)
{
	struct hash_ostream *hstream;

	hstream = i_new(struct hash_ostream, 1);
	hstream->ostream.sendv = o_stream_hash_sendv;
	hstream->method = method;
	hstream->hash_context = hash_context;

	return o_stream_create(&hstream->ostream, output,
			       o_stream_get_fd(output));
}
