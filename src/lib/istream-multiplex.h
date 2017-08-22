#ifndef ISTREAM_MULTIPLEX
#define ISTREAM_MULTIPLEX 1

struct istream *i_stream_create_multiplex(struct istream *parent, size_t bufsize);
struct istream *i_stream_multiplex_add_channel(struct istream *stream, uint8_t cid);
uint8_t i_stream_multiplex_get_channel_id(struct istream *stream);

#endif
