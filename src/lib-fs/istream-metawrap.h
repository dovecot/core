#ifndef ISTREAM_METAWRAP_H
#define ISTREAM_METAWRAP_H

typedef void
metawrap_callback_t(const char *key, const char *value, void *context);

/* Input stream is in format "key:value\nkey2:value2\n...\n\ncontents.
   The given callback is called for each key/value metadata pair, and the
   returned stream will skip over the metadata and return only the contents. */
struct istream *
i_stream_create_metawrap(struct istream *input,
			 metawrap_callback_t *callback, void *context);

#endif
