#ifndef __IOSTREAM_INTERNAL_H
#define __IOSTREAM_INTERNAL_H

/* This file is private to IStream and OStream implementation */

typedef struct _IOStream _IOStream;

struct _IOStream {
	Pool pool;
	int refcount;

	void (*close)(_IOStream *stream);
	void (*destroy)(_IOStream *stream);
	void (*set_max_buffer_size)(_IOStream *stream, size_t max_size);
	void (*set_blocking)(_IOStream *stream, int timeout_msecs,
			     void (*timeout_func)(void *), void *context);
};

void _io_stream_init(Pool pool, _IOStream *stream);
void _io_stream_ref(_IOStream *stream);
void _io_stream_unref(_IOStream *stream);
void _io_stream_close(_IOStream *stream);
void _io_stream_set_max_buffer_size(_IOStream *stream, size_t max_size);
void _io_stream_set_blocking(_IOStream *stream, int timeout_msecs,
			     void (*timeout_func)(void *), void *context);

#define GET_TIMEOUT_TIME(fstream) \
        ((fstream)->timeout_msecs == 0 ? 0 : \
	 time(NULL) + ((fstream)->timeout_msecs / 1000))
#define STREAM_IS_BLOCKING(fstream) \
	((fstream)->timeout_msecs != 0)

#endif
