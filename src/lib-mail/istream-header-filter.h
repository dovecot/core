#ifndef __ISTREAM_HEADER_FILTER_H
#define __ISTREAM_HEADER_FILTER_H

/* NOTE: NULL-terminated headers list must be sorted. */
struct istream *
i_stream_create_header_filter(pool_t pool, struct istream *input,
			      const char *const *headers, size_t headers_count);

#endif
