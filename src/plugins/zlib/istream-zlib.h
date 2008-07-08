#ifndef ISTREAM_ZLIB_H
#define ISTREAM_ZLIB_H

struct istream *i_stream_create_zlib(int fd);
struct istream *i_stream_create_bzlib(int fd);

#endif
