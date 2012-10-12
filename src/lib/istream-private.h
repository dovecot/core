#ifndef ISTREAM_PRIVATE_H
#define ISTREAM_PRIVATE_H

#include "istream.h"
#include "iostream-private.h"

#define I_STREAM_MIN_SIZE IO_BLOCK_SIZE

struct istream_private {
/* inheritance: */
	struct iostream_private iostream;

/* methods: */
	ssize_t (*read)(struct istream_private *stream);
	void (*seek)(struct istream_private *stream,
		     uoff_t v_offset, bool mark);
	void (*sync)(struct istream_private *stream);
	int (*stat)(struct istream_private *stream, bool exact);
	int (*get_size)(struct istream_private *stream, bool exact, uoff_t *size_r);

/* data: */
	struct istream istream;

	int fd;
	uoff_t abs_start_offset;
	struct stat statbuf;

	const unsigned char *buffer;
	unsigned char *w_buffer; /* may be NULL */

	size_t buffer_size, max_buffer_size, init_buffer_size;
	size_t skip, pos, try_alloc_limit;

	struct istream *parent; /* for filter streams */
	uoff_t parent_start_offset;

	/* parent stream's expected offset is kept here. i_stream_read()
	   always seeks parent stream to here before calling read(). */
	uoff_t parent_expected_offset;

	/* increased every time the stream is changed (e.g. seek, read).
	   this way streams can check if their parent streams have been
	   accessed behind them. */
	unsigned int access_counter;

	string_t *line_str; /* for i_stream_next_line() if w_buffer == NULL */
	unsigned int line_crlf:1;
	unsigned int return_nolf_line:1;
	unsigned int stream_size_passthrough:1; /* stream is parent's size */
};

struct istream * ATTR_NOWARN_UNUSED_RESULT
i_stream_create(struct istream_private *stream, struct istream *parent, int fd)
	ATTR_NULL(2);

void i_stream_compress(struct istream_private *stream);
void i_stream_grow_buffer(struct istream_private *stream, size_t bytes);
bool ATTR_NOWARN_UNUSED_RESULT
i_stream_try_alloc(struct istream_private *stream,
		   size_t wanted_size, size_t *size_r);
void *i_stream_alloc(struct istream_private *stream, size_t size);
ssize_t i_stream_read_copy_from_parent(struct istream *istream);
void i_stream_default_seek_nonseekable(struct istream_private *stream,
				       uoff_t v_offset, bool mark);

#endif
