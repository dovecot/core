/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

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

bool message_part_is_equal_ex(const struct message_part *p1,
			      const struct message_part *p2,
			      message_part_comparator_t *equals_ex)
{
	/* This cannot be p1 && p2, because then we would return
	   TRUE when either part is NULL, and we should return FALSE */
	while (p1 != NULL || p2 != NULL) {
		/* If either part is NULL, return false */
		if ((p1 != NULL) != (p2 != NULL))
			return FALSE;

		/* Expect that both either have children, or both
		   do not have children */
		if ((p1->children != NULL) != (p2->children != NULL))
			return FALSE;

		/* If there are children, ensure they are equal */
		if (p1->children != NULL) {
			if (!message_part_is_equal(p1->children, p2->children))
				return FALSE;
		}

		/* If any of these properties differ, then parts are not equal */
		if (p1->physical_pos != p2->physical_pos ||
		    p1->header_size.physical_size != p2->header_size.physical_size ||
		    p1->header_size.virtual_size != p2->header_size.virtual_size ||
		    p1->header_size.lines != p2->header_size.lines ||
		    p1->body_size.physical_size != p2->body_size.physical_size ||
		    p1->body_size.virtual_size != p2->body_size.virtual_size ||
		    p1->body_size.lines != p2->body_size.lines ||
		    p1->children_count != p2->children_count ||
		    p1->flags != p2->flags)
			return FALSE;

		if (equals_ex != NULL && !equals_ex(p1, p2))
			return FALSE;

		/* Move forward */
		p1 = p1->next;
		p2 = p2->next;
	}

	/* Parts are equal */
	return TRUE;
}

bool message_part_is_equal(const struct message_part *p1,
			   const struct message_part *p2) ATTR_NULL(1, 2)
{
	return message_part_is_equal_ex(p1, p2, NULL);
}
