#ifndef ISTREAM_INTERNAL_H
#define ISTREAM_INTERNAL_H

#include "istream.h"
#include "iostream-internal.h"

#define I_STREAM_MIN_SIZE 4096

struct istream_private {
/* inheritance: */
	struct iostream_private iostream;

/* methods: */
	ssize_t (*read)(struct istream_private *stream);
	void (*seek)(struct istream_private *stream,
		     uoff_t v_offset, bool mark);
	void (*sync)(struct istream_private *stream);
	const struct stat *(*stat)(struct istream_private *stream, bool exact);

/* data: */
	struct istream istream;

	int fd;
	uoff_t abs_start_offset;
	struct stat statbuf;

	const unsigned char *buffer;
	unsigned char *w_buffer; /* may be NULL */

	size_t buffer_size, max_buffer_size;
	size_t skip, pos;

	struct istream *parent; /* for filter streams */
	uoff_t parent_start_offset;

	string_t *line_str; /* for i_stream_next_line() if w_buffer == NULL */
};

struct istream *
i_stream_create(struct istream_private *stream, struct istream *parent, int fd);

void i_stream_compress(struct istream_private *stream);
void i_stream_grow_buffer(struct istream_private *stream, size_t bytes);
bool i_stream_get_buffer_space(struct istream_private *stream,
			       size_t wanted_size, size_t *size_r);

#endif
