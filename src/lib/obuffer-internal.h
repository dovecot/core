#ifndef __OBUFFER_INTERNAL_H
#define __OBUFFER_INTERNAL_H

#include "obuffer.h"
#include "iobuffer-internal.h"

typedef struct __OBuffer _OBuffer;

struct __OBuffer {
/* inheritance: */
	_IOBuffer iobuf;

/* methods: */
	void (*cork)(_OBuffer *buf);
	int (*flush)(_OBuffer *buf);
	int (*have_space)(_OBuffer *buf, size_t size);
	int (*seek)(_OBuffer *buf, uoff_t offset);
	ssize_t (*send)(_OBuffer *buf, const void *data, size_t size);
	off_t (*send_ibuffer)(_OBuffer *outbuf, IBuffer *inbuf);

/* data: */
	OBuffer obuffer;
};

OBuffer *_o_buffer_create(_OBuffer *_buf, Pool pool);

#endif
