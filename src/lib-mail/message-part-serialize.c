/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "message-parser.h"
#include "message-part-serialize.h"

/*
   Serialized a series of SerializedMessageParts:

   root part
     root's first children
       children's first children
       ...
     root's next children
     ...
*/

/* struct is 8 byte aligned */
typedef struct {
	uoff_t physical_pos;
  
	uoff_t header_physical_size;
	uoff_t header_virtual_size;
  
	uoff_t body_physical_size;
	uoff_t body_virtual_size;

	unsigned int header_lines;
	unsigned int body_lines;

	unsigned int children_count;
	unsigned int flags;
} SerializedMessagePart;

static void message_part_serialize_part(MessagePart *part,
					unsigned int *children_count,
					SerializedMessagePart **spart_base,
					unsigned int *pos, unsigned int *size)
{
	SerializedMessagePart *spart;
	unsigned int buf_size;

	while (part != NULL) {
		/* make sure we have space */
		if (*pos == *size) {
			*size *= 2;
			buf_size = sizeof(SerializedMessagePart) * (*size);

			*spart_base = t_buffer_reget(*spart_base, buf_size);
		}

		/* create serialized part */
		spart = (*spart_base) + (*pos);
		memset(spart, 0, sizeof(SerializedMessagePart));

		spart->physical_pos = part->physical_pos;

		spart->header_physical_size = part->header_size.physical_size;
		spart->header_virtual_size = part->header_size.virtual_size;
		spart->header_lines = part->header_size.lines;

		spart->body_physical_size = part->body_size.physical_size;
		spart->body_virtual_size = part->body_size.virtual_size;
		spart->body_lines = part->body_size.lines;

		spart->children_count = 0;
		spart->flags = part->flags;

		if (children_count != NULL)
			(*children_count)++;
		(*pos)++;

		if (part->children != NULL) {
			message_part_serialize_part(part->children,
						    &spart->children_count,
						    spart_base, pos, size);
		}
		part = part->next;
	}
}

const void *message_part_serialize(MessagePart *part, unsigned int *size)
{
        SerializedMessagePart *spart_base;
	unsigned int pos, buf_size;

	buf_size = 32;
	spart_base = t_buffer_get(sizeof(SerializedMessagePart) * buf_size);

	pos = 0;
	message_part_serialize_part(part, NULL, &spart_base, &pos, &buf_size);

	*size = sizeof(SerializedMessagePart) * pos;
	t_buffer_alloc(*size);
	return spart_base;
}

static MessagePart *
message_part_deserialize_part(Pool pool, MessagePart *parent,
			      const SerializedMessagePart **spart_pos,
			      unsigned int *count, unsigned int child_count)
{
        const SerializedMessagePart *spart;
	MessagePart *part, *first_part, **next_part;
	unsigned int i;

	first_part = NULL;
	next_part = NULL;
	for (i = 0; i < child_count && *count > 0; i++) {
		spart = *spart_pos;
		(*spart_pos)++;
		(*count)--;

		part = p_new(pool, MessagePart, 1);
		part->physical_pos = spart->physical_pos;

		part->header_size.physical_size = spart->header_physical_size;
		part->header_size.virtual_size = spart->header_virtual_size;
		part->header_size.lines = spart->header_lines;

		part->body_size.physical_size = spart->body_physical_size;
		part->body_size.virtual_size = spart->body_virtual_size;
		part->body_size.lines = spart->body_lines;

		part->flags = spart->flags;

		part->parent = parent;
		part->children = message_part_deserialize_part(pool, part,
							spart_pos, count,
							spart->children_count);

		if (first_part == NULL)
			first_part = part;
		if (next_part != NULL)
			*next_part = part;
		next_part = &part->next;
	}

	return first_part;
}

MessagePart *message_part_deserialize(Pool pool, const void *data,
				      unsigned int size)
{
        const SerializedMessagePart *spart;
	unsigned int count;

	/* make sure it looks valid */
	if (size == 0 || (size % sizeof(SerializedMessagePart)) != 0)
		return NULL;

	spart = data;
	count = size / sizeof(SerializedMessagePart);
	return message_part_deserialize_part(pool, NULL, &spart, &count, count);
}
