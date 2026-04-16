#ifndef OSTREAM_ZLIB_H
#define OSTREAM_ZLIB_H

struct ostream *o_stream_create_gz_auto(struct ostream *output, struct event *event);
struct ostream *o_stream_create_deflate_auto(struct ostream *output, struct event *event);
struct ostream *o_stream_create_deflate(struct ostream *output, int level);
struct ostream *o_stream_create_bz2_auto(struct ostream *output, struct event *event);
struct ostream *o_stream_create_lz4_auto(struct ostream *output, struct event *event);
struct ostream *o_stream_create_zstd_auto(struct ostream *output, struct event *event);

/* Reset the deflate compression dictionary so that subsequent compressed
   output cannot reference data from before this call.  Pass any ostream in
   the chain (e.g. a rawlog wrapper); the function locates the deflate stream
   internally.  Safe to call when compression is not active – it is a no-op
   in that case. */
void o_stream_deflate_reset_dict(struct ostream *output);

#endif
