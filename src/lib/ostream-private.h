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
	enum ostream_send_istream_result
		(*send_istream)(struct ostream_private *outstream,
				struct istream *instream);
	void (*switch_ioloop_to)(struct ostream_private *stream,
				 struct ioloop *ioloop);

/* data: */
	struct ostream ostream;
	size_t max_buffer_size;

	struct ostream *parent; /* for filter streams */

	int fd;
	struct timeval last_write_timeval;

	stream_flush_callback_t *callback;
	void *context;

	bool corked:1;
	bool finished:1;
	bool closing:1;
	bool last_errors_not_checked:1;
	bool error_handling_disabled:1;
	bool noverflow:1;
	bool finish_also_parent:1;
	bool finish_via_child:1;
};

struct ostream *
o_stream_create(struct ostream_private *_stream, struct ostream *parent, int fd)
	ATTR_NULL(2);

enum ostream_send_istream_result
io_stream_copy(struct ostream *outstream, struct istream *instream);

void o_stream_copy_error_from_parent(struct ostream_private *_stream);
/* This should be called before sending data to parent stream. It makes sure
   that the parent stream's output buffer doesn't become too large.
   Returns 1 if more data can be safely added, 0 if not, -1 if error. */
int o_stream_flush_parent_if_needed(struct ostream_private *_stream);

/* Call this in flush() handler to flush the parent stream. It will call
   either o_stream_flush() or o_stream_finish() depending on whether this
   stream is already finished. If the parent fails, its error will be also
   copied to this stream. */
int o_stream_flush_parent(struct ostream_private *_stream);

#endif
