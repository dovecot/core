#ifndef __MESSAGE_PART_SERIALIZE_H
#define __MESSAGE_PART_SERIALIZE_H

/* Serialize message part, allocating memory from temporary pool.
   size is updated to contain the size of returned data. */
const void *message_part_serialize(MessagePart *part, unsigned int *size);

/* Generate MessagePart from serialized data. */
MessagePart *message_part_deserialize(Pool pool, const void *data,
				      unsigned int size);

/* Update header size in serialized MessagePart. */
int message_part_serialize_update_header(void *data, unsigned int size,
					 MessageSize *hdr_size);

/* Get message size from serialized MessagePart data. */
int message_part_deserialize_size(const void *data, unsigned int size,
				  MessageSize *hdr_size,
				  MessageSize *body_size);

#endif
