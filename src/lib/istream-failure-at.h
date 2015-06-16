#ifndef ISTREAM_FAILURE_AT_H
#define ISTREAM_FAILURE_AT_H

struct istream *
i_stream_create_failure_at(struct istream *input, uoff_t failure_offset,
			   const char *error_string);
struct istream *
i_stream_create_failure_at_eof(struct istream *input, const char *error_string);

#endif
