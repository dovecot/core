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
struct serialized_message_part {
	uoff_t physical_pos;
  
	uoff_t header_physical_size;
	uoff_t header_virtual_size;
  
	uoff_t body_physical_size;
	uoff_t body_virtual_size;

	unsigned int header_lines;
	unsigned int body_lines;

	unsigned int children_count;
	unsigned int flags;
};

struct deserialize_context {
	pool_t pool;

	const struct serialized_message_part *spart;
	unsigned int sparts_left;

	uoff_t pos;
	const char *error;
};

static unsigned int
_message_part_serialize(struct message_part *part, buffer_t *dest)
{
	struct serialized_message_part *spart;
	unsigned int count = 0;

	while (part != NULL) {
		/* create serialized part */
		spart = buffer_append_space(dest, sizeof(*spart));
		memset(spart, 0, sizeof(*spart));

		spart->physical_pos = part->physical_pos;

		spart->header_physical_size = part->header_size.physical_size;
		spart->header_virtual_size = part->header_size.virtual_size;
		spart->header_lines = part->header_size.lines;

		spart->body_physical_size = part->body_size.physical_size;
		spart->body_virtual_size = part->body_size.virtual_size;
		spart->body_lines = part->body_size.lines;

		spart->flags = part->flags;

		if (part->children != NULL) {
			spart->children_count =
				_message_part_serialize(part->children, dest);
		}

		count++;
		part = part->next;
	}

	return count;
}

void message_part_serialize(struct message_part *part, buffer_t *dest)
{
	_message_part_serialize(part, dest);
}

static int message_part_deserialize_part(struct deserialize_context *ctx,
					 struct message_part *parent,
					 unsigned int child_count,
                                         struct message_part **part_r)
{
        const struct serialized_message_part *spart;
	struct message_part *part, *first_part, **next_part;
	uoff_t pos;

	first_part = NULL;
	next_part = NULL;
	while (child_count > 0) {
		child_count--;
		if (ctx->sparts_left == 0) {
			ctx->error = "Not enough data for all parts";
			return FALSE;
		}

		spart = ctx->spart;
		ctx->spart++;
		ctx->sparts_left--;

		part = p_new(ctx->pool, struct message_part, 1);
		part->physical_pos = spart->physical_pos;

		if (part->physical_pos < ctx->pos) {
			ctx->error = "physical_pos less than expected";
			return FALSE;
		}

		part->header_size.physical_size = spart->header_physical_size;
		part->header_size.virtual_size = spart->header_virtual_size;
		part->header_size.lines = spart->header_lines;

		if (spart->header_virtual_size < spart->header_physical_size) {
			ctx->error = "header_virtual_size too small";
			return FALSE;
		}

		part->body_size.physical_size = spart->body_physical_size;
		part->body_size.virtual_size = spart->body_virtual_size;
		part->body_size.lines = spart->body_lines;

		if (spart->body_virtual_size < spart->body_physical_size) {
			ctx->error = "body_virtual_size too small";
			return FALSE;
		}

		part->flags = spart->flags;
		part->parent = parent;

		/* our children must be after our physical_pos and the last
		   child must be within our size. */
		ctx->pos = part->physical_pos;
		pos = part->physical_pos + spart->header_physical_size +
			spart->body_physical_size;

		if (!message_part_deserialize_part(ctx, part,
						   spart->children_count,
						   &part->children))
			return FALSE;

		if (ctx->pos > pos) {
			ctx->error = "child part location exceeds our size";
			return FALSE;
		}
		ctx->pos = pos; /* save it for above check for parent */

		if (part->flags & MESSAGE_PART_FLAG_MESSAGE_RFC822) {
			/* Only one child is possible */
			if (part->children == NULL) {
				ctx->error =
					"message/rfc822 part has no children";
				return FALSE;
			}
			if (part->children->next != NULL) {
				ctx->error = "message/rfc822 part "
					"has multiple children";
				return FALSE;
			}
		}

		if (first_part == NULL)
			first_part = part;
		if (next_part != NULL)
			*next_part = part;
		next_part = &part->next;
	}

	*part_r = first_part;
	return TRUE;
}

static int check_size(size_t size, const char **error)
{
	if (size < sizeof(struct serialized_message_part)) {
		*error = "Not enough data for root";
		return FALSE;
	}

	if ((size % sizeof(struct serialized_message_part)) != 0) {
		*error = "Incorrect data size";
		return FALSE;
	}

	if (size / sizeof(struct serialized_message_part) > UINT_MAX) {
		*error = "Insane amount of data";
		return FALSE;
	}

	return TRUE;
}

struct message_part *message_part_deserialize(pool_t pool, const void *data,
					      size_t size, const char **error)
{
	struct deserialize_context ctx;
        struct message_part *part;

	if (!check_size(size, error))
		return NULL;

	memset(&ctx, 0, sizeof(ctx));
	ctx.pool = pool;
	ctx.spart = data;
	ctx.sparts_left =
		(unsigned int) (size / sizeof(struct serialized_message_part));

	if (!message_part_deserialize_part(&ctx, NULL, 1, &part)) {
		*error = ctx.error;
		return NULL;
	}

	if (ctx.sparts_left > 0) {
		*error = "Too much data";
		return NULL;
	}

	return part;
}

int message_part_serialize_update_header(void *data, size_t size,
					 struct message_size *hdr_size,
					 const char **error)
{
	struct serialized_message_part *spart = data;
	uoff_t first_pos;
	off_t pos_diff;
	size_t i, count;
	unsigned int children;

	if (!check_size(size, error))
		return FALSE;

	if (hdr_size->physical_size >= OFF_T_MAX ||
	    spart->physical_pos >= OFF_T_MAX ||
	    spart->header_physical_size >= OFF_T_MAX) {
		*error = "Invalid data";
		return FALSE;
	}

	first_pos = spart->physical_pos;
	pos_diff = (off_t)hdr_size->physical_size - spart->header_physical_size;

	spart->header_physical_size = hdr_size->physical_size;
	spart->header_virtual_size = hdr_size->virtual_size;
	spart->header_lines = hdr_size->lines;

	if (pos_diff != 0) {
		/* have to update all positions, but skip the first one */
		children = spart->children_count;
		count = (size / sizeof(struct serialized_message_part))-1;
		spart++;

		for (i = 0; i < count; i++, spart++) {
			if (spart->physical_pos < first_pos ||
			    spart->physical_pos >= OFF_T_MAX) {
				/* invalid offset, might cause overflow */
				*error = "Invalid offset";
				return FALSE;
			}

			children += spart->children_count;
			spart->physical_pos += pos_diff;
		}

		if (children != count) {
			*error = t_strdup_printf("Size mismatch %u vs %u",
						 children, count);
			return FALSE;
		}
	}

	return TRUE;
}

int message_part_deserialize_size(const void *data, size_t size,
				  struct message_size *hdr_size,
				  struct message_size *body_size)
{
        const struct serialized_message_part *spart = data;

	/* make sure it looks valid */
	if (size < sizeof(struct serialized_message_part))
		return FALSE;

	hdr_size->physical_size = spart->header_physical_size;
	hdr_size->virtual_size = spart->header_virtual_size;
	hdr_size->lines = spart->header_lines;

	body_size->physical_size = spart->body_physical_size;
	body_size->virtual_size = spart->body_virtual_size;
	body_size->lines = spart->body_lines;

	return TRUE;
}
