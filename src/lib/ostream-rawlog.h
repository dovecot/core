#ifndef OSTREAM_RAWLOG_H
#define OSTREAM_RAWLOG_H

struct ostream *
o_stream_create_rawlog(struct ostream *output, const char *rawlog_path,
		       int rawlog_fd, enum iostream_rawlog_flags flags);

#endif
