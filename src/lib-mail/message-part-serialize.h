#ifndef __MESSAGE_PART_SERIALIZE_H
#define __MESSAGE_PART_SERIALIZE_H

/* Serialize message part. */
void message_part_serialize(MessagePart *part, Buffer *dest);

/* Generate MessagePart from serialized data. */
MessagePart *message_part_deserialize(Pool pool, const void *data, size_t size);

/* Update header size in serialized MessagePart. */
int message_part_serialize_update_header(void *data, size_t size,
					 MessageSize *hdr_size);

/* Get message size from serialized MessagePart data. */
int message_part_deserialize_size(const void *data, size_t size,
				  MessageSize *hdr_size,
				  MessageSize *body_size);

#endif
