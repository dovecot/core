#ifndef __ISTREAM_HEADER_FILTER_H
#define __ISTREAM_HEADER_FILTER_H

enum header_filter_flags {
	/* Include only specified headers in output.*/
	HEADER_FILTER_INCLUDE	= 0x01,
	/* Exclude specified headers from output. */
	HEADER_FILTER_EXCLUDE	= 0x02,

	/* Use LF linefeeds instead of CRLF. */
	HEADER_FILTER_NO_CR	= 0x04,
	/* Return EOF at the beginning of message body. */
	HEADER_FILTER_HIDE_BODY	= 0x08
};

struct message_header_line;

typedef void header_filter_callback(struct message_header_line *hdr,
				    bool *matched, void *context);

/* NOTE: headers list must be sorted. */
struct istream *
i_stream_create_header_filter(struct istream *input,
			      enum header_filter_flags flags,
			      const char *const *headers,
			      unsigned int headers_count,
			      header_filter_callback *callback, void *context);

#endif
