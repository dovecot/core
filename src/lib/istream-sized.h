#ifndef ISTREAM_SIZED_H
#define ISTREAM_SIZED_H

struct istream_sized_error_data {
	/* Stream's current v_offset */
	uoff_t v_offset;
	/* How many more bytes are being added within this read() */
	size_t new_bytes;
	/* What's the original wanted size. */
	uoff_t wanted_size;
	/* TRUE if we're at EOF now */
	bool eof;
};

typedef const char *
istream_sized_callback_t(const struct istream_sized_error_data *data,
			 void *context);

/* Assume that input stream is exactly the given size. If the stream is too
   small, fail with stream_errno=EPIPE. If stream is too large, fail with
   stream_errno=EINVAL. */
struct istream *i_stream_create_sized(struct istream *input, uoff_t size);
struct istream *i_stream_create_sized_range(struct istream *input,
					    uoff_t offset, uoff_t size);
/* Like i_stream_create_sized*(), but allow input stream's size to be larger. */
struct istream *i_stream_create_min_sized(struct istream *input, uoff_t min_size);
struct istream *i_stream_create_min_sized_range(struct istream *input,
						uoff_t offset, uoff_t min_size);
/* Same as i_stream_create_sized(), but set the error message via the
   callback. */
struct istream *
i_stream_create_sized_with_callback(struct istream *input, uoff_t size,
				    istream_sized_callback_t *error_callback,
				    void *context);
#define i_stream_create_sized_with_callback(input, size, error_callback, context) \
	i_stream_create_sized_with_callback(input, size - \
		CALLBACK_TYPECHECK(error_callback, \
			const char *(*)(const struct istream_sized_error_data *, typeof(context))), \
		(istream_sized_callback_t *)error_callback, context)

#endif
