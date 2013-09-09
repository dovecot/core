#ifndef ISTREAM_HASH_H
#define ISTREAM_HASH_H

struct hash_method;

/* hash_context must be allocated and initialized by caller. This istream will
   simply call method->loop() for all the data going through the istream. */
struct istream *
i_stream_create_hash(struct istream *input, const struct hash_method *method,
		     void *hash_context);

#endif
