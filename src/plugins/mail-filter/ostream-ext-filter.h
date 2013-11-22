#ifndef OSTREAM_MAIL_FILTER_H
#define OSTREAM_MAIL_FILTER_H

struct ostream *
o_stream_create_ext_filter(struct ostream *output, const char *socket_path,
			   const char *args);

#endif
