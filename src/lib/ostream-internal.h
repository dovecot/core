#ifndef __OSTREAM_INTERNAL_H
#define __OSTREAM_INTERNAL_H

#include "ostream.h"
#include "iostream-internal.h"

struct _ostream {
/* inheritance: */
	struct _iostream iostream;

/* methods: */
	void (*cork)(struct _ostream *stream, bool set);
	int (*flush)(struct _ostream *stream);
	void (*flush_pending)(struct _ostream *stream, bool set);
	size_t (*get_used_size)(struct _ostream *stream);
	int (*seek)(struct _ostream *stream, uoff_t offset);
	ssize_t (*sendv)(struct _ostream *stream, const struct const_iovec *iov,
			 unsigned int iov_count);
	off_t (*send_istream)(struct _ostream *outstream,
			      struct istream *instream);

/* data: */
	struct ostream ostream;

	stream_flush_callback_t *callback;
	void *context;
};

struct ostream *_o_stream_create(struct _ostream *_stream);

#endif
