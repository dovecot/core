#ifndef OSTREAM_INTERNAL_H
#define OSTREAM_INTERNAL_H

#include "ostream.h"
#include "iostream-internal.h"

struct ostream_private {
/* inheritance: */
	struct iostream_private iostream;

/* methods: */
	void (*cork)(struct ostream_private *stream, bool set);
	int (*flush)(struct ostream_private *stream);
	void (*flush_pending)(struct ostream_private *stream, bool set);
	size_t (*get_used_size)(const struct ostream_private *stream);
	int (*seek)(struct ostream_private *stream, uoff_t offset);
	ssize_t (*sendv)(struct ostream_private *stream,
			 const struct const_iovec *iov,
			 unsigned int iov_count);
	off_t (*send_istream)(struct ostream_private *outstream,
			      struct istream *instream);

/* data: */
	struct ostream ostream;

	stream_flush_callback_t *callback;
	void *context;
};

struct ostream *o_stream_create(struct ostream_private *_stream);

#endif
