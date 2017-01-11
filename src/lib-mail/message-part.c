/* Copyright (c) 2014-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "message-part.h"

static const struct message_part *
message_part_root(const struct message_part *part)
{
	while (part->parent != NULL)
		part = part->parent;
	return part;
}

static bool message_part_find(const struct message_part *siblings,
			      const struct message_part *part,
			      unsigned int *n)
{
	const struct message_part *p;

	for (p = siblings; p != NULL; p = p->next) {
		if (p == part)
			return TRUE;
		*n += 1;
		if (message_part_find(p->children, part, n))
			return TRUE;
	}
	return FALSE;
}

unsigned int message_part_to_idx(const struct message_part *part)
{
	const struct message_part *root;
	unsigned int n = 0;

	root = message_part_root(part);
	if (!message_part_find(root, part, &n))
		i_unreached();
	return n;
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
