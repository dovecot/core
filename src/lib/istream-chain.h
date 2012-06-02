#ifndef ISTREAM_CHAIN_H
#define ISTREAM_CHAIN_H

struct istream_chain;

/* Flexibly couple input streams into a single chain stream. Input streams can
   be added after creation of the chain stream, and the chain stream will not
   signal EOF until all streams are read to EOF and the last stream added was
   NULL. Streams that were finished to EOF are unreferenced. The chain stream
   is obviously not seekable and it has no determinable size. The chain_r
   argument returns a pointer to the chain object. */
struct istream *i_stream_create_chain(struct istream_chain **chain_r);

/* Append an input stream to the chain. A NULL stream marks the end of the chain
   and only then reads from the chain stream can return EOF. */
void i_stream_chain_append(struct istream_chain *chain, struct istream *stream);

#endif
