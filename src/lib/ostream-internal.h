#ifndef __OSTREAM_INTERNAL_H
#define __OSTREAM_INTERNAL_H

#include "ostream.h"
#include "iostream-internal.h"

typedef struct __OStream _OStream;

struct __OStream {
/* inheritance: */
	_IOStream iostream;

/* methods: */
	void (*cork)(_OStream *stream);
	int (*flush)(_OStream *stream);
	int (*have_space)(_OStream *stream, size_t size);
	int (*seek)(_OStream *stream, uoff_t offset);
	ssize_t (*send)(_OStream *stream, const void *data, size_t size);
	off_t (*send_istream)(_OStream *outstream, IStream *instream);

/* data: */
	OStream ostream;
};

OStream *_o_stream_create(_OStream *_stream, Pool pool);

#endif
