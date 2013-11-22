#ifndef ISTREAM_MAIL_FILTER_H
#define ISTREAM_MAIL_FILTER_H

struct istream *
i_stream_create_ext_filter(struct istream *input, const char *socket_path,
			   const char *args);

#endif
