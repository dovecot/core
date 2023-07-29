#ifndef OSTREAM_ZLIB_H
#define OSTREAM_ZLIB_H

struct ostream *o_stream_create_gz(struct ostream *output, int level);
struct ostream *o_stream_create_deflate(struct ostream *output, int level);
struct ostream *o_stream_create_bz2(struct ostream *output, int level);
struct ostream *o_stream_create_lz4(struct ostream *output, int level);
struct ostream *o_stream_create_zstd(struct ostream *output, int level);

struct ostream *o_stream_create_gz_auto(struct ostream *output, struct event *event);
struct ostream *o_stream_create_deflate_auto(struct ostream *output, struct event *event);

int compression_get_min_level_gz(void);
int compression_get_default_level_gz(void);
int compression_get_max_level_gz(void);

int compression_get_min_level_bz2(void);
int compression_get_default_level_bz2(void);
int compression_get_max_level_bz2(void);

int compression_get_min_level_lz4(void);
int compression_get_default_level_lz4(void);
int compression_get_max_level_lz4(void);

int compression_get_min_level_zstd(void);
int compression_get_default_level_zstd(void);
int compression_get_max_level_zstd(void);

#endif
