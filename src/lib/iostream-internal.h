#ifndef __IOSTREAM_INTERNAL_H
#define __IOSTREAM_INTERNAL_H

/* This file is private to IStream and OStream implementation */

struct _iostream {
	pool_t pool;
	int refcount;

	void (*close)(struct _iostream *stream);
	void (*destroy)(struct _iostream *stream);
	void (*set_max_buffer_size)(struct _iostream *stream, size_t max_size);
	void (*set_blocking)(struct _iostream *stream, int timeout_msecs,
			     void (*timeout_func)(void *), void *context);
};

void _io_stream_init(pool_t pool, struct _iostream *stream);
void _io_stream_ref(struct _iostream *stream);
void _io_stream_unref(struct _iostream *stream);
void _io_stream_close(struct _iostream *stream);
void _io_stream_set_max_buffer_size(struct _iostream *stream, size_t max_size);
void _io_stream_set_blocking(struct _iostream *stream, int timeout_msecs,
			     void (*timeout_func)(void *), void *context);

#define GET_TIMEOUT_TIME(fstream) \
        ((fstream)->timeout_msecs == 0 ? 0 : \
	 time(NULL) + ((fstream)->timeout_msecs / 1000))
#define STREAM_IS_BLOCKING(fstream) \
	((fstream)->timeout_msecs != 0)

#endif
