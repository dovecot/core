#ifndef OSTREAM_ZLIB_H
#define OSTREAM_ZLIB_H

struct ostream *o_stream_create_gz(struct ostream *output, int level);
struct ostream *o_stream_create_deflate(struct ostream *output, int level);
struct ostream *o_stream_create_bz2(struct ostream *output, int level);
struct ostream *o_stream_create_lzma(struct ostream *output, int level);
struct ostream *o_stream_create_lz4(struct ostream *output, int level);
struct ostream *o_stream_create_zstd(struct ostream *output, int level);

#endif
