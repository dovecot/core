#ifndef OSTREAM_RAWLOG_H
#define OSTREAM_RAWLOG_H

#include "iostream-rawlog.h"

struct ostream *
o_stream_create_rawlog(struct ostream *output, const char *rawlog_path,
		       int rawlog_fd, enum iostream_rawlog_flags flags);
struct ostream *
o_stream_create_rawlog_from_stream(struct ostream *output,
				   struct ostream *rawlog_output,
				   enum iostream_rawlog_flags flags);

#endif
