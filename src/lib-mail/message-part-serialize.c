/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "buffer.h"
#include "message-parser.h"
#include "message-part-serialize.h"

/*
   root part
     root's first children
       children's first children
       ...
     root's next children
     ...

   part
     unsigned int flags
     (not root part)
       uoff_t physical_pos
     uoff_t header_physical_size
     uoff_t header_virtual_size
     uoff_t body_physical_size
     uoff_t body_virtual_size
     (flags & (MESSAGE_PART_FLAG_TEXT | MESSAGE_PART_FLAG_MESSAGE_RFC822))
       unsigned int body_lines
     (flags & (MESSAGE_PART_FLAG_MULTIPART | MESSAGE_PART_FLAG_MESSAGE_RFC822))
       unsigned int children_count

*/

struct deserialize_context {
	pool_t pool;
	const unsigned char *data, *end;

	uoff_t pos;
	const char *error;
};

static void part_serialize(struct message_part *part, buffer_t *dest,
			   uoff_t *pos, unsigned int *children_count_r)
{
	unsigned int count, children_count;
	size_t children_offset;
	uoff_t part_pos, child_pos;
	bool root = part->parent == NULL;

	count = 0;
	while (part != NULL) {
		/* The tree must be internally consistent so its serialized
		   form always passes message_part_deserialize(). The input is
		   freshly parsed in-memory data, not read from disk, so an
		   inconsistency is a parser/programming bug: assert instead of
		   writing a tree that would later fail to deserialize or crash
		   the from-parts walk. The root's physical_pos isn't
		   serialized, so it's treated as 0. */
		part_pos = root ? 0 : part->physical_pos;
		i_assert(part_pos >= *pos);

		/* create serialized part */
		buffer_append(dest, &part->flags, sizeof(part->flags));
		if (root)
			root = FALSE;
		else {
			buffer_append(dest, &part->physical_pos,
				      sizeof(part->physical_pos));
		}
		buffer_append(dest, &part->header_size.physical_size,
			      sizeof(part->header_size.physical_size));
		buffer_append(dest, &part->header_size.virtual_size,
			      sizeof(part->header_size.virtual_size));
		buffer_append(dest, &part->body_size.physical_size,
			      sizeof(part->body_size.physical_size));
		buffer_append(dest, &part->body_size.virtual_size,
			      sizeof(part->body_size.virtual_size));

		if ((part->flags & (MESSAGE_PART_FLAG_TEXT |
				    MESSAGE_PART_FLAG_MESSAGE_RFC822)) != 0) {
			buffer_append(dest, &part->body_size.lines,
				      sizeof(part->body_size.lines));
		}

		if ((part->flags & (MESSAGE_PART_FLAG_MULTIPART |
				    MESSAGE_PART_FLAG_MESSAGE_RFC822)) != 0) {
			children_offset = dest->used;
			children_count = 0;
			buffer_append(dest, &children_count,
				      sizeof(children_count));

			if (part->children != NULL) {
				child_pos = part_pos +
					part->header_size.physical_size;
				part_serialize(part->children, dest,
					       &child_pos, &children_count);

				buffer_write(dest, children_offset,
					     &children_count,
					     sizeof(children_count));
				/* children must fit within our body */
				i_assert(child_pos <= part_pos +
					 part->header_size.physical_size +
					 part->body_size.physical_size);
			}
		} else {
			i_assert(part->children == NULL);
		}

		*pos = part_pos + part->header_size.physical_size +
			part->body_size.physical_size;

		count++;
		part = part->next;
	}

	*children_count_r = count;
}

void message_part_serialize(struct message_part *part, buffer_t *dest)
{
	unsigned int children_count;
	uoff_t pos = 0;

	part_serialize(part, dest, &pos, &children_count);
}

static bool read_next(struct deserialize_context *ctx,
		      void *buffer, size_t buffer_size)
{
	if (ctx->data + buffer_size > ctx->end) {
		ctx->error = "Not enough data";
		return FALSE;
	}

	memcpy(buffer, ctx->data, buffer_size);
	ctx->data += buffer_size;
	return TRUE;
}

static bool ATTR_NULL(2)
message_part_deserialize_part(struct deserialize_context *ctx,
			      struct message_part *parent,
			      unsigned int siblings,
			      struct message_part **part_r)
{
	struct message_part *p, *part, *first_part, **next_part;
	unsigned int children_count;
	uoff_t pos;
	bool root = parent == NULL;

	first_part = NULL;
	next_part = NULL;
	while (siblings > 0) {
		siblings--;

		part = p_new(ctx->pool, struct message_part, 1);
		part->parent = parent;
		for (p = parent; p != NULL; p = p->parent)
			p->children_count++;

		if (!read_next(ctx, &part->flags, sizeof(part->flags)))
			return FALSE;

		if (root)
			root = FALSE;
		else {
			if (!read_next(ctx, &part->physical_pos,
				       sizeof(part->physical_pos)))
				return FALSE;
		}

		if (part->physical_pos < ctx->pos) {
			ctx->error = "physical_pos less than expected";
			return FALSE;
		}

		if (!read_next(ctx, &part->header_size.physical_size,
			       sizeof(part->header_size.physical_size)))
			return FALSE;

		if (!read_next(ctx, &part->header_size.virtual_size,
			       sizeof(part->header_size.virtual_size)))
			return FALSE;

		if (part->header_size.virtual_size <
		    part->header_size.physical_size) {
			ctx->error = "header_size.virtual_size too small";
			return FALSE;
		}

		if (!read_next(ctx, &part->body_size.physical_size,
			       sizeof(part->body_size.physical_size)))
			return FALSE;

		if (!read_next(ctx, &part->body_size.virtual_size,
			       sizeof(part->body_size.virtual_size)))
			return FALSE;

		if ((part->flags & (MESSAGE_PART_FLAG_TEXT |
				    MESSAGE_PART_FLAG_MESSAGE_RFC822)) != 0) {
			if (!read_next(ctx, &part->body_size.lines,
				       sizeof(part->body_size.lines)))
				return FALSE;
		}

		if (part->body_size.virtual_size <
		    part->body_size.physical_size) {
			ctx->error = "body_size.virtual_size too small";
			return FALSE;
		}

		if ((part->flags & (MESSAGE_PART_FLAG_MULTIPART |
				    MESSAGE_PART_FLAG_MESSAGE_RFC822)) != 0) {
			if (!read_next(ctx, &children_count,
				       sizeof(children_count)))
				return FALSE;
		} else {
                        children_count = 0;
		}

		if ((part->flags & MESSAGE_PART_FLAG_MESSAGE_RFC822) != 0) {
			/* Only one child is possible */
			if (children_count == 0) {
				ctx->error =
					"message/rfc822 part has no children";
				return FALSE;
			}
			if (children_count != 1) {
				ctx->error = "message/rfc822 part "
					"has multiple children";
				return FALSE;
			}
		}

		if (children_count > 0) {
			/* our children must be after our physical_pos+header
			   and the last child must be within our size. */
			ctx->pos = part->physical_pos +
				part->header_size.physical_size;
			pos = ctx->pos + part->body_size.physical_size;

			if (!message_part_deserialize_part(ctx, part,
							   children_count,
							   &part->children))
				return FALSE;

			if (ctx->pos > pos) {
				ctx->error =
					"child part location exceeds our size";
				return FALSE;
			}
			ctx->pos = pos; /* save it for above check for parent */
		} else {
			/* leaf part: advance past its body so the next sibling
			   can't be recorded overlapping it. Without this a
			   cached tree with overlapping leaf siblings would be
			   accepted and later crash the from-parts walk. */
			ctx->pos = part->physical_pos +
				part->header_size.physical_size +
				part->body_size.physical_size;
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

struct message_part *
message_part_deserialize(pool_t pool, const void *data, size_t size,
			 const char **error_r)
{
	struct deserialize_context ctx;
        struct message_part *part;

	i_zero(&ctx);
	ctx.pool = pool;
	ctx.data = data;
	ctx.end = ctx.data + size;

	if (!message_part_deserialize_part(&ctx, NULL, 1, &part)) {
		*error_r = ctx.error;
		return NULL;
	}

	if (ctx.data != ctx.end) {
		*error_r = "Too much data";
		return NULL;
	}

	return part;
}
