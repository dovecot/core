#ifndef __ISTREAM_INTERNAL_H
#define __ISTREAM_INTERNAL_H

#include "istream.h"
#include "iostream-internal.h"

#define I_STREAM_MIN_SIZE 4096

struct _istream {
/* inheritance: */
	struct _iostream iostream;

/* methods: */
	ssize_t (*read)(struct _istream *stream);
	void (*seek)(struct _istream *stream, uoff_t v_offset, bool mark);
	void (*sync)(struct _istream *stream);
	const struct stat *(*stat)(struct _istream *stream, bool exact);

/* data: */
	struct istream istream;

	int fd;
	uoff_t abs_start_offset;
	struct stat statbuf;

	const unsigned char *buffer;
	unsigned char *w_buffer; /* may be NULL */

	size_t buffer_size, max_buffer_size;
	size_t skip, pos;

	string_t *line_str; /* for i_stream_next_line() if w_buffer == NULL */
};

struct istream *_i_stream_create(struct _istream *_buf, pool_t pool, int fd,
				 uoff_t abs_start_offset);

void _i_stream_compress(struct _istream *stream);
void _i_stream_grow_buffer(struct _istream *stream, size_t bytes);

#endif
