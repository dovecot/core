#ifndef __ISTREAM_INTERNAL_H
#define __ISTREAM_INTERNAL_H

#include "istream.h"
#include "iostream-internal.h"

typedef struct __IStream _IStream;

struct __IStream {
/* inheritance: */
	_IOStream iostream;

/* methods: */
	ssize_t (*read)(_IStream *stream);
	void (*skip_count)(_IStream *stream, uoff_t count);
	void (*seek)(_IStream *stream, uoff_t v_offset);

/* data: */
	IStream istream;

	int fd;
	const unsigned char *buffer;
	unsigned char *w_buffer; /* may be NULL */
	size_t buffer_size;

	size_t skip, pos, cr_lookup_pos;
};

IStream *_i_stream_create(_IStream *_buf, Pool pool, int fd,
			  uoff_t start_offset, uoff_t v_size);

#endif
