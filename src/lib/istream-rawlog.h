#ifndef ISTREAM_RAWLOG_H
#define ISTREAM_RAWLOG_H

#include "iostream-rawlog.h"

struct istream *
i_stream_create_rawlog(struct istream *input, const char *rawlog_path,
		       int rawlog_fd, enum iostream_rawlog_flags flags);
struct istream *
i_stream_create_rawlog_from_stream(struct istream *input,
				   struct ostream *rawlog_output,
				   enum iostream_rawlog_flags flags);

#endif
