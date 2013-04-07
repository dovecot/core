#ifndef IOSTREAM_PRIVATE_H
#define IOSTREAM_PRIVATE_H

/* This file is private to input stream and output stream implementations */

struct iostream_destroy_callback {
	void (*callback)(void *context);
	void *context;
};

struct iostream_private {
	int refcount;
	char *name;

	void (*close)(struct iostream_private *streami, bool close_parent);
	void (*destroy)(struct iostream_private *stream);
	void (*set_max_buffer_size)(struct iostream_private *stream,
				    size_t max_size);

	ARRAY(struct iostream_destroy_callback) destroy_callbacks;
};

void io_stream_init(struct iostream_private *stream);
void io_stream_ref(struct iostream_private *stream);
void io_stream_unref(struct iostream_private *stream);
void io_stream_close(struct iostream_private *stream, bool close_parent);
void io_stream_set_max_buffer_size(struct iostream_private *stream,
				   size_t max_size);

#endif
