#ifndef OSTREAM_HASH_H
#define OSTREAM_HASH_H

/* hash_context must be allocated and initialized by caller. This ostream will
   simply call method->loop() for all the data going through the ostream. */
struct ostream *
o_stream_create_hash(struct ostream *output, const struct hash_method *method,
		     void *hash_context);

#endif
