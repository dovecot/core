#ifndef OSTREAM_RAWLOG_H
#define OSTREAM_RAWLOG_H

struct ostream *
o_stream_create_rawlog(struct ostream *output, const char *rawlog_path,
		       int rawlog_fd, bool autoclose_fd);

#endif
