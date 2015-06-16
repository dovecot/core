#ifndef OSTREAM_FAILURE_AT_H
#define OSTREAM_FAILURE_AT_H

struct ostream *
o_stream_create_failure_at(struct ostream *output, uoff_t failure_offset,
			   const char *error_string);
struct ostream *
o_stream_create_failure_at_flush(struct ostream *output, const char *error_string);

#endif
