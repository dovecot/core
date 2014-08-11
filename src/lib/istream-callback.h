#ifndef ISTREAM_CALLBACK_H
#define ISTREAM_CALLBACK_H

/* istream-callback can be used to implement an istream that returns data
   by calling the specified callback. The callback needs to do:

   a) Add data to buffer unless the buffer size is already too large
   (the callback can decide by itself what is too large). Return TRUE
   regardless of whether any data was added.

   b) Return FALSE when it's finished adding data or when it reaches an error.
   On error i_stream_callback_set_error() must be called before returning.

   i_stream_add_destroy_callback() can be also added to do any cleanups that
   the callback may need to do.
*/
typedef bool istream_callback_read_t(buffer_t *buf, void *context);

struct istream *
i_stream_create_callback(istream_callback_read_t *callback, void *context);
#define i_stream_create_callback(callback, context) \
	i_stream_create_callback(1 ? (istream_callback_read_t *)callback : \
		CALLBACK_TYPECHECK(callback, bool (*)(buffer_t *buf, typeof(context))), \
		context)

/* Append data to the istream externally. Typically this is used to add a
   header to the stream before the callbacks are called. */
void i_stream_callback_append(struct istream *input,
			      const void *data, size_t size);
void i_stream_callback_append_str(struct istream *input, const char *str);

/* Returns the istream-callback's internal buffer. This buffer can be used to
   append data to the stream. */
buffer_t *i_stream_callback_get_buffer(struct istream *input);

void i_stream_callback_set_error(struct istream *input, int stream_errno,
				 const char *error);

#endif
