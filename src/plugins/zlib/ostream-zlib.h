#ifndef OSTREAM_ZLIB_H
#define OSTREAM_ZLIB_H

struct ostream *o_stream_create_gz(struct ostream *output, int level);
struct ostream *o_stream_create_deflate(struct ostream *output, int level);
struct ostream *o_stream_create_bz2(struct ostream *output, int level);

#endif
