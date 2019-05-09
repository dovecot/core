#ifndef ISTREAM_HEADER_FILTER_H
#define ISTREAM_HEADER_FILTER_H

struct header_filter_istream;

enum header_filter_flags {
	/* Include only specified headers in output.*/
	HEADER_FILTER_INCLUDE		= 0x01,
	/* Exclude specified headers from output. */
	HEADER_FILTER_EXCLUDE		= 0x02,

	/* Use LF linefeeds instead of CRLF. */
	HEADER_FILTER_NO_CR		= 0x04,
	/* Return EOF at the beginning of message body. */
	HEADER_FILTER_HIDE_BODY		= 0x08,
	/* If the empty "end of headers" line doesn't exist, add it. */
	HEADER_FILTER_ADD_MISSING_EOH	= 0x10,
	/* If body doesn't end with [CR]LF, add it/them. */
	HEADER_FILTER_END_BODY_WITH_LF	= 0x20,
	/* Preserve the original LF or CRLF. */
	HEADER_FILTER_CRLF_PRESERVE	= 0x40
};

struct message_header_line;

typedef void header_filter_callback(struct header_filter_istream *input,
				    struct message_header_line *hdr,
				    bool *matched, void *context);

extern header_filter_callback *null_header_filter_callback;

/* NOTE: headers list must be sorted. */
struct istream *
i_stream_create_header_filter(struct istream *input,
			      enum header_filter_flags flags,
			      const char *const *headers,
			      unsigned int headers_count,
			      header_filter_callback *callback, void *context)
	ATTR_NULL(6);
#define i_stream_create_header_filter(input, flags, headers, headers_count, \
				        callback, context) \
	  i_stream_create_header_filter(input, flags, headers, headers_count - \
		CALLBACK_TYPECHECK(callback, void (*)( \
			struct header_filter_istream *, \
			struct message_header_line *, bool *, typeof(context))), \
		(header_filter_callback *)callback, context)

/* Add more data to headers. Should called from the filter callback. */
void i_stream_header_filter_add(struct header_filter_istream *input,
				const void *data, size_t size);

#endif
