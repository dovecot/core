#ifndef IOSTREAM_PRIVATE_H
#define IOSTREAM_PRIVATE_H

#include "iostream.h"

/* This file is private to input stream and output stream implementations */

struct iostream_destroy_callback {
	void (*callback)(void *context);
	void *context;
};

struct iostream_private {
	int refcount;
	char *name;
	char *error;

	void (*close)(struct iostream_private *streami, bool close_parent);
	void (*destroy)(struct iostream_private *stream);
	void (*set_max_buffer_size)(struct iostream_private *stream,
				    size_t max_size);

	ARRAY(struct iostream_destroy_callback) destroy_callbacks;
};

void io_stream_init(struct iostream_private *stream);
void io_stream_ref(struct iostream_private *stream);
bool io_stream_unref(struct iostream_private *stream);
void io_stream_free(struct iostream_private *stream);
void io_stream_close(struct iostream_private *stream, bool close_parent);
void io_stream_set_max_buffer_size(struct iostream_private *stream,
				   size_t max_size);
void io_stream_add_destroy_callback(struct iostream_private *stream,
				    void (*callback)(void *), void *context);
void io_stream_remove_destroy_callback(struct iostream_private *stream,
				       void (*callback)(void *));
/* Set a specific error for the stream. This shouldn't be used for regular
   syscall errors where stream's errno is enough, since it's used by default.
   The stream errno must always be set even if the error string is also set.
   Setting this error replaces the previously set error. */
void io_stream_set_error(struct iostream_private *stream,
			 const char *fmt, ...) ATTR_FORMAT(2, 3);
void io_stream_set_verror(struct iostream_private *stream,
			  const char *fmt, va_list args) ATTR_FORMAT(2, 0);

#endif
