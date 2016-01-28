#ifndef MESSAGE_HEADER_HASH_H
#define MESSAGE_HEADER_HASH_H

struct md5_context;

void message_header_hash_more(struct md5_context *md5_ctx,
			      unsigned int version,
			      const unsigned char *data, size_t size);

#endif
