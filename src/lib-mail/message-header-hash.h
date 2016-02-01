#ifndef MESSAGE_HEADER_HASH_H
#define MESSAGE_HEADER_HASH_H

struct hash_method;

void message_header_hash_more(const struct hash_method *method, void *context,
			      unsigned int version,
			      const unsigned char *data, size_t size);

#endif
