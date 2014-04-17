/* Copyright (c) 2014 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "message-part.h"

unsigned int message_part_to_idx(const struct message_part *part)
{
	const struct message_part *p;
	unsigned int n;

	if (part->parent == NULL) {
		/* root */
		return 0;
	}
	for (n = 0, p = part->parent->children; p != part; p = p->next, n++)
		;
	return n + 1 + message_part_to_idx(part->parent);
}

static struct message_part *
message_sub_part_by_idx(struct message_part *parts,
			unsigned int idx)
{
	struct message_part *part = parts;

	for (; part != NULL && idx > 0; part = part->next) {
		if (part->children_count >= idx)
			return message_sub_part_by_idx(part->children, idx-1);
		idx -= part->children_count + 1;
	}
	return part;
}

struct message_part *
message_part_by_idx(struct message_part *parts, unsigned int idx)
{
	i_assert(parts->parent == NULL);

	return message_sub_part_by_idx(parts, idx);
}
