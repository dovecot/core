#ifndef OSTREAM_PRIVATE_H
#define OSTREAM_PRIVATE_H

#include "ostream.h"
#include "iostream-private.h"

struct ostream_private {
/* inheritance: */
	struct iostream_private iostream;

/* methods: */
	void (*cork)(struct ostream_private *stream, bool set);
	int (*flush)(struct ostream_private *stream);
	void (*set_flush_callback)(struct ostream_private *stream,
				   stream_flush_callback_t *callback,
				   void *context);
	void (*flush_pending)(struct ostream_private *stream, bool set);
	size_t (*get_used_size)(const struct ostream_private *stream);
	int (*seek)(struct ostream_private *stream, uoff_t offset);
	ssize_t (*sendv)(struct ostream_private *stream,
			 const struct const_iovec *iov,
			 unsigned int iov_count);
	int (*write_at)(struct ostream_private *stream,
			const void *data, size_t size, uoff_t offset);
	off_t (*send_istream)(struct ostream_private *outstream,
			      struct istream *instream);
	void (*switch_ioloop)(struct ostream_private *stream);

/* data: */
	struct ostream ostream;
	size_t max_buffer_size;

	struct ostream *parent; /* for filter streams */

	int fd;
	stream_flush_callback_t *callback;
	void *context;

	unsigned int corked:1;
	unsigned int last_errors_not_checked:1;
	unsigned int error_handling_disabled:1;
};

struct ostream *
o_stream_create(struct ostream_private *_stream, struct ostream *parent, int fd)
	ATTR_NULL(2);

off_t io_stream_copy(struct ostream *outstream, struct istream *instream,
		     size_t block_size);

void o_stream_copy_error_from_parent(struct ostream_private *_stream);

#endif
