/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
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

void message_part_serialize(MessagePart *part, Buffer *dest)
{
	SerializedMessagePart *spart;

	while (part != NULL) {
		/* create serialized part */
		spart = buffer_append_space(dest,
					    sizeof(SerializedMessagePart));
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

		if (part->children != NULL)
			message_part_serialize(part, dest);
		part = part->next;
	}
}

static MessagePart *
message_part_deserialize_part(Pool pool, MessagePart *parent,
			      const SerializedMessagePart **spart_pos,
			      size_t *count, unsigned int child_count)
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
				      size_t size)
{
        const SerializedMessagePart *spart;
	size_t count;

	/* make sure it looks valid */
	if (size < sizeof(SerializedMessagePart))
		return NULL;

	spart = data;
	count = size / sizeof(SerializedMessagePart);
	if (count > UINT_MAX)
		return NULL;

	return message_part_deserialize_part(pool, NULL, &spart, &count,
					     (unsigned int)count);
}

int message_part_serialize_update_header(void *data, size_t size,
					 MessageSize *hdr_size)
{
	SerializedMessagePart *spart = data;
	uoff_t first_pos;
	off_t pos_diff;
	size_t i, count;

	/* make sure it looks valid */
	if (size < sizeof(SerializedMessagePart))
		return FALSE;

	if (hdr_size->physical_size >= OFF_T_MAX ||
	    spart->physical_pos >= OFF_T_MAX ||
	    spart->header_physical_size >= OFF_T_MAX)
		return FALSE;

	first_pos = spart->physical_pos;
	pos_diff = (off_t)hdr_size->physical_size - spart->header_physical_size;

	spart->header_physical_size = hdr_size->physical_size;
	spart->header_virtual_size = hdr_size->virtual_size;
	spart->header_lines = hdr_size->lines;

	if (pos_diff != 0) {
		/* have to update all positions, but skip the first one */
		count = (size / sizeof(SerializedMessagePart))-1;
		spart++;

		for (i = 0; i < count; i++, spart++) {
			if (spart->physical_pos < first_pos ||
			    spart->physical_pos >= OFF_T_MAX) {
				/* invalid offset, might cause overflow */
				return FALSE;
			}
			spart->physical_pos += pos_diff;
		}
	}
	return TRUE;
}

int message_part_deserialize_size(const void *data, size_t size,
				  MessageSize *hdr_size,
				  MessageSize *body_size)
{
        const SerializedMessagePart *spart = data;

	/* make sure it looks valid */
	if (size < sizeof(SerializedMessagePart))
		return FALSE;

	hdr_size->physical_size = spart->header_physical_size;
	hdr_size->virtual_size = spart->header_virtual_size;
	hdr_size->lines = spart->header_lines;

	body_size->physical_size = spart->body_physical_size;
	body_size->virtual_size = spart->body_virtual_size;
	body_size->lines = spart->body_lines;

	return TRUE;
}
