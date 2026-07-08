#ifndef OSTREAM_MULTIPLEX
#define OSTREAM_MULTIPLEX 1

enum ostream_multiplex_format {
	/* DEPRECATED: The original packet-based framing
	   (<channel-id><32bit length><data>). It can't stream to a parent
	   with max_buffer_size==0 and requires the parent to buffer a whole
	   packet, so it doesn't work with senders that stream directly to the
	   socket (e.g. imap-fetch). New code should use
	   OSTREAM_MULTIPLEX_FORMAT_STREAM. Kept only for backwards
	   compatibility with peers that don't yet understand the stream
	   format, and is being phased out. */
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
