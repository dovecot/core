#ifndef IOSTREAM_INTERNAL_H
#define IOSTREAM_INTERNAL_H

/* This file is private to input stream and output stream implementations */

struct _iostream {
	int refcount;

	void (*close)(struct _iostream *stream);
	void (*destroy)(struct _iostream *stream);
	void (*set_max_buffer_size)(struct _iostream *stream, size_t max_size);
};

void _io_stream_init(struct _iostream *stream);
void _io_stream_ref(struct _iostream *stream);
void _io_stream_unref(struct _iostream *stream);
void _io_stream_close(struct _iostream *stream);
void _io_stream_set_max_buffer_size(struct _iostream *stream, size_t max_size);

#endif
