#ifndef ISTREAM_RAWLOG_H
#define ISTREAM_RAWLOG_H

struct istream *
i_stream_create_rawlog(struct istream *input, const char *rawlog_path,
		       int rawlog_fd, enum iostream_rawlog_flags flags);

#endif
