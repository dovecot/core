#ifndef OSTREAM_MULTIPLEX
#define OSTREAM_MULTIPLEX 1

struct ostream *o_stream_create_multiplex(struct ostream *parent, size_t bufsize);
struct ostream *o_stream_multiplex_add_channel(struct ostream *stream, uint8_t cid);
uint8_t o_stream_multiplex_get_channel_id(struct ostream *stream);

#endif
