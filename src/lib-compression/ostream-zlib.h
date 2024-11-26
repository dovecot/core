#ifndef OSTREAM_ZLIB_H
#define OSTREAM_ZLIB_H

struct ostream *o_stream_create_gz_auto(struct ostream *output, struct event *event);
struct ostream *o_stream_create_deflate_auto(struct ostream *output, struct event *event);
struct ostream *o_stream_create_bz2_auto(struct ostream *output, struct event *event);
struct ostream *o_stream_create_lz4_auto(struct ostream *output, struct event *event);
struct ostream *o_stream_create_zstd_auto(struct ostream *output, struct event *event);

#endif
