#ifndef ISTREAM_HEADER_FILTER_H
#define ISTREAM_HEADER_FILTER_H

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
	HEADER_FILTER_END_BODY_WITH_LF	= 0x20
};

struct message_header_line;

typedef void header_filter_callback(struct message_header_line *hdr,
				    bool *matched, void *context);

extern header_filter_callback *null_header_filter_callback;

/* NOTE: headers list must be sorted. */
struct istream *
i_stream_create_header_filter(struct istream *input,
			      enum header_filter_flags flags,
			      const char *const *headers,
			      unsigned int headers_count,
			      header_filter_callback *callback, void *context);
#ifdef CONTEXT_TYPE_SAFETY
#  define i_stream_create_header_filter(input, flags, headers, headers_count, \
				        callback, context) \
	({(void)(1 ? 0 : callback((struct message_header_line *)0, \
				  (bool *)0, context)); \
	  i_stream_create_header_filter(input, flags, headers, headers_count, \
			(header_filter_callback *)callback, context); })
#else
#  define i_stream_create_header_filter(input, flags, headers, headers_count, \
				        callback, context) \
	  i_stream_create_header_filter(input, flags, headers, headers_count, \
			(header_filter_callback *)callback, context)
#endif

#endif
