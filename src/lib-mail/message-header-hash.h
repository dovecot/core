#ifndef MESSAGE_HEADER_HASH_H
#define MESSAGE_HEADER_HASH_H

struct hash_method;

struct message_header_hash_context {
	bool prev_was_questionmark;
};

/* Initialize ctx with zeros. */
void message_header_hash_more(struct message_header_hash_context *ctx,
			      const struct hash_method *method, void *context,
			      unsigned int version,
			      const unsigned char *data, size_t size);

#endif
