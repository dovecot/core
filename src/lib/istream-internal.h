#ifndef __ISTREAM_INTERNAL_H
#define __ISTREAM_INTERNAL_H

#include "istream.h"
#include "iostream-internal.h"

struct _istream {
/* inheritance: */
	struct _iostream iostream;

/* methods: */
	ssize_t (*read)(struct _istream *stream);
	void (*seek)(struct _istream *stream, uoff_t v_offset);
	uoff_t (*get_size)(struct _istream *stream);

/* data: */
	struct istream istream;

	int fd;
	const unsigned char *buffer;
	unsigned char *w_buffer; /* may be NULL */
	size_t buffer_size;
	uoff_t abs_start_offset;

	size_t skip, pos;
};

struct istream *_i_stream_create(struct _istream *_buf, pool_t pool, int fd,
				 uoff_t abs_start_offset);

#endif
