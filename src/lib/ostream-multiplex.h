#ifndef OSTREAM_MULTIPLEX
#define OSTREAM_MULTIPLEX 1

enum ostream_multiplex_format {
	OSTREAM_MULTIPLEX_FORMAT_PACKET,
	/* Start a new multiplex ostream */
	OSTREAM_MULTIPLEX_FORMAT_STREAM,
	/* Continue an existing multiplex ostream. No header is sent. */
	OSTREAM_MULTIPLEX_FORMAT_STREAM_CONTINUE,
};

struct ostream *o_stream_create_multiplex(struct ostream *parent, size_t bufsize,
					  enum ostream_multiplex_format format);
struct ostream *o_stream_multiplex_add_channel(struct ostream *stream, uint8_t cid);
uint8_t o_stream_multiplex_get_channel_id(struct ostream *stream);

#endif
