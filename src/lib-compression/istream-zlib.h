#ifndef ISTREAM_ZLIB_H
#define ISTREAM_ZLIB_H

struct istream *i_stream_create_gz(struct istream *input, bool log_errors);
struct istream *i_stream_create_deflate(struct istream *input, bool log_errors);
struct istream *i_stream_create_bz2(struct istream *input, bool log_errors);
struct istream *i_stream_create_lzma(struct istream *input, bool log_errors);
struct istream *i_stream_create_lz4(struct istream *input, bool log_errors);
struct istream *i_stream_create_zstd(struct istream *input, bool log_errors);

#endif
