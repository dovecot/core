#ifndef __IBUFFER_INTERNAL_H
#define __IBUFFER_INTERNAL_H

#include "ibuffer.h"
#include "iobuffer-internal.h"

typedef struct __IBuffer _IBuffer;

struct __IBuffer {
/* inheritance: */
	_IOBuffer iobuf;

/* methods: */
	ssize_t (*read)(_IBuffer *buf);
	void (*skip_count)(_IBuffer *buf, uoff_t count);
	void (*seek)(_IBuffer *buf, uoff_t v_offset);

/* data: */
	IBuffer ibuffer;

	int fd;
	const unsigned char *buffer;
	unsigned char *w_buffer; /* may be NULL */
	size_t buffer_size;

	size_t skip, pos, cr_lookup_pos;
};

IBuffer *_i_buffer_create(_IBuffer *_buf, Pool pool, int fd,
			  uoff_t start_offset, uoff_t v_size);

#endif
