#ifndef MESSAGE_PART_SERIALIZE_H
#define MESSAGE_PART_SERIALIZE_H

struct message_part;
struct message_size;

/* Serialize message part. */
void message_part_serialize(struct message_part *part, buffer_t *dest);

/* Generate struct message_part from serialized data. Returns NULL and sets
   error if any problems are detected. */
struct message_part *
message_part_deserialize(pool_t pool, const void *data, size_t size,
			 const char **error_r);

#endif
