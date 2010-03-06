#ifndef IOSTREAM_INTERNAL_H
#define IOSTREAM_INTERNAL_H

/* This file is private to input stream and output stream implementations */

struct iostream_private {
	int refcount;
	char *name;

	void (*close)(struct iostream_private *stream);
	void (*destroy)(struct iostream_private *stream);
	void (*set_max_buffer_size)(struct iostream_private *stream,
				    size_t max_size);

	void (*destroy_callback)(void *context);
	void *destroy_context;
};

void io_stream_init(struct iostream_private *stream);
void io_stream_ref(struct iostream_private *stream);
void io_stream_unref(struct iostream_private *stream);
void io_stream_close(struct iostream_private *stream);
void io_stream_set_max_buffer_size(struct iostream_private *stream,
				   size_t max_size);

#endif
