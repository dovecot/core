#ifndef __MESSAGE_PART_SERIALIZE_H
#define __MESSAGE_PART_SERIALIZE_H

struct message_part;
struct message_size;

/* Serialize message part. */
void message_part_serialize(struct message_part *part, buffer_t *dest);

/* Generate struct message_part from serialized data. Returns NULL and sets
   error if any problems are detected. If cache header size is unreliable
   (eg. with mbox), you can give a new header size which will be used. */
struct message_part *
message_part_deserialize(pool_t pool, const void *data, size_t size,
			 const struct message_size *new_hdr_size,
			 const char **error_r);

#endif
