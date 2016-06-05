#ifndef ISTREAM_FILE_PRIVATE_H
#define ISTREAM_FILE_PRIVATE_H

#include "istream-private.h"

struct file_istream {
	struct istream_private istream;

	uoff_t skip_left;

	bool file:1;
	bool autoclose_fd:1;
	bool seen_eof:1;
};

struct istream *
i_stream_create_file_common(struct file_istream *fstream,
			    int fd, const char *path,
			    size_t max_buffer_size, bool autoclose_fd);
ssize_t i_stream_file_read(struct istream_private *stream);
void i_stream_file_close(struct iostream_private *stream, bool close_parent);

#endif
