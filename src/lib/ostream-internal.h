#ifndef __OSTREAM_INTERNAL_H
#define __OSTREAM_INTERNAL_H

#include "ostream.h"
#include "iostream-internal.h"

struct _ostream {
/* inheritance: */
	struct _iostream iostream;

/* methods: */
	void (*cork)(struct _ostream *stream);
	int (*flush)(struct _ostream *stream);
	int (*have_space)(struct _ostream *stream, size_t size);
	int (*seek)(struct _ostream *stream, uoff_t offset);
	ssize_t (*send)(struct _ostream *stream, const void *data, size_t size);
	off_t (*send_istream)(struct _ostream *outstream,
			      struct istream *instream);

/* data: */
	struct ostream ostream;
};

struct ostream *_o_stream_create(struct _ostream *_stream, pool_t pool);

#endif
