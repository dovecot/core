/*
   Redblack balanced tree algorithm, http://libredblack.sourceforge.net/
   Copyright (C) Damian Ivereigh 2000

   Modified to be suitable for mmap()ing and for IMAP server
   Copyright (C) Timo Sirainen 2002

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 2.1 of the License, or
   (at your option) any later version. See the file COPYING for details.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/* NOTE: currently this code doesn't do any bounds checkings. I'm not sure
   if I should even bother, the code would just get uglier and slower. */

#include "lib.h"
#include "mail-index.h"
#include "mail-tree.h"

/* #define DEBUG_TREE */

#ifndef DEBUG_TREE
#  define rb_check(tree)
#endif

/* Dummy (sentinel) node, so that we can make X->left->up = X
** We then use this instead of NULL to mean the top or bottom
** end of the rb tree. It is a black node.
*/
#define RBNULL 0

/* If highest bit in node_count is set, the node is red. */
#define RED_MASK (1 << (SIZEOF_INT*CHAR_BIT-1))

#define IS_NODE_BLACK(node) \
	(((node).node_count & RED_MASK) == 0)
#define IS_NODE_RED(node) \
	(((node).node_count & RED_MASK) != 0)

#define NODE_SET_BLACK(node) \
	STMT_START { (node).node_count &= ~RED_MASK; } STMT_END
#define NODE_SET_RED(node) \
	STMT_START { (node).node_count |= RED_MASK; } STMT_END

#define NODE_COPY_COLOR(dest, src) \
	STMT_START { \
		if (((src).node_count & RED_MASK) != \
		    ((dest).node_count & RED_MASK)) \
        		(dest).node_count ^= RED_MASK; \
	} STMT_END

#define NODE_COUNT(node) \
	((node).node_count & ~RED_MASK)

#define NODE_COUNT_ADD(node, count) \
	STMT_START { (node).node_count += (count); } STMT_END

/*
** OK here we go, the balanced tree stuff. The algorithm is the
** fairly standard red/black taken from "Introduction to Algorithms"
** by Cormen, Leiserson & Rivest. Maybe one of these days I will
** fully understand all this stuff.
**
** Basically a red/black balanced tree has the following properties:-
** 1) Every node is either red or black (color is RED or BLACK)
** 2) A leaf (RBNULL pointer) is considered black
** 3) If a node is red then its children are black
** 4) Every path from a node to a leaf contains the same no
**    of black nodes
**
** 3) & 4) above guarantee that the longest path (alternating
** red and black nodes) is only twice as long as the shortest
** path (all black nodes). Thus the tree remains fairly balanced.
*/

static unsigned int
rb_alloc(MailTree *tree)
{
	unsigned int x;

	if (tree->mmap_used_length == tree->mmap_full_length) {
		if (!_mail_tree_grow(tree))
			return RBNULL;
	}

	i_assert(tree->header->used_file_size == tree->mmap_used_length);
	i_assert(tree->mmap_used_length + sizeof(MailTreeNode) <=
		 tree->mmap_full_length);

	x = (tree->mmap_used_length - sizeof(MailTreeHeader)) /
		sizeof(MailTreeNode);

	tree->header->used_file_size += sizeof(MailTreeNode);
	tree->mmap_used_length += sizeof(MailTreeNode);

	memset(&tree->node_base[x], 0, sizeof(MailTreeNode));
	return x;
}

static void
rb_move(MailTree *tree, unsigned int src, unsigned int dest)
{
	MailTreeNode *node = tree->node_base;

	/* update parent */
	if (node[src].up != RBNULL) {
		if (node[node[src].up].left == src)
			node[node[src].up].left = dest;
		else if (node[node[src].up].right == src)
			node[node[src].up].right = dest;
	}

	/* update children */
	if (node[src].left != RBNULL)
		node[node[src].left].up = dest;
	if (node[src].right != RBNULL)
		node[node[src].right].up = dest;

	/* update root */
	if (tree->header->root == src)
		tree->header->root = dest;

	memcpy(&node[dest], &node[src], sizeof(MailTreeNode));
	memset(&node[src], 0, sizeof(MailTreeNode));
}

static void
rb_free(MailTree *tree, unsigned int x)
{
	unsigned int last;

	i_assert(tree->mmap_used_length >=
		 sizeof(MailTreeHeader) + sizeof(MailTreeNode));

	/* get index to last used record */
	last = (tree->mmap_used_length - sizeof(MailTreeHeader)) /
		sizeof(MailTreeNode) - 1;

	if (last != x) {
		/* move it over the one we want free'd */
		rb_move(tree, last, x);
	}

	/* mark the moved node unused */
	tree->mmap_used_length -= sizeof(MailTreeNode);
	tree->header->used_file_size -= sizeof(MailTreeNode);

	_mail_tree_truncate(tree);
}

/*
** Rotate our tree thus:-
**
**             X        rb_left_rotate(X)--->            Y
**           /   \                                     /   \
**          A     Y     <---rb_right_rotate(Y)        X     C
**              /   \                               /   \
**             B     C                             A     B
**
** N.B. This does not change the ordering.
**
** We assume that neither X or Y is NULL
**
** Node count changes:
**   X += C+1              X -= C+1
**   Y -= A+1              Y += A+1
*/

static void
rb_left_rotate(MailTree *tree, unsigned int x)
{
	MailTreeNode *node = tree->node_base;
	unsigned int y, a_nodes, c_nodes;

	i_assert(x != RBNULL);
	i_assert(node[x].right != RBNULL);

	y = node[x].right;
	a_nodes = NODE_COUNT(node[node[x].left]);
	c_nodes = NODE_COUNT(node[node[y].right]);

	/* Turn Y's left subtree into X's right subtree (move B) */
	node[x].right = node[y].left;

	/* If B is not null, set it's parent to be X */
	if (node[y].left != RBNULL)
		node[node[y].left].up = x;

	/* Set Y's parent to be what X's parent was */
	node[y].up = node[x].up;

	/* if X was the root */
	if (node[x].up == RBNULL) {
		tree->header->root = y;
	} else {
		/* Set X's parent's left or right pointer to be Y */
		if (x == node[node[x].up].left)
			node[node[x].up].left = y;
		else
			node[node[x].up].right = y;
	}

	/* Put X on Y's left */
	node[y].left = x;

	/* Set X's parent to be Y */
	node[x].up = y;

	/* Update node counts */
        NODE_COUNT_ADD(node[x], -(c_nodes+1));
        NODE_COUNT_ADD(node[y], a_nodes+1);
}

static void
rb_right_rotate(MailTree *tree, unsigned int y)
{
	MailTreeNode *node = tree->node_base;
	unsigned int x, a_nodes, c_nodes;

	i_assert(y != RBNULL);
	i_assert(node[y].left != RBNULL);

	x = node[y].left;
	a_nodes = NODE_COUNT(node[node[x].left]);
	c_nodes = NODE_COUNT(node[node[y].right]);

	/* Turn X's right subtree into Y's left subtree (move B) */
	node[y].left = node[x].right;

	/* If B is not null, set it's parent to be Y */
	if (node[x].right != RBNULL)
		node[node[x].right].up = y;

	/* Set X's parent to be what Y's parent was */
	node[x].up = node[y].up;

	/* if Y was the root */
	if (node[y].up == RBNULL)
		tree->header->root = x;
	else {
		/* Set Y's parent's left or right pointer to be X */
		if (y == node[node[y].up].left)
			node[node[y].up].left = x;
		else
			node[node[y].up].right = x;
	}

	/* Put Y on X's right */
	node[x].right = y;

	/* Set Y's parent to be X */
	node[y].up = x;

	/* Update node counts */
	NODE_COUNT_ADD(node[x], c_nodes+1);
	NODE_COUNT_ADD(node[y], -(a_nodes+1));
}

/* Return index to the smallest key greater than x
*/
static unsigned int 
rb_successor(MailTree *tree, unsigned int x)
{
	MailTreeNode *node = tree->node_base;
	unsigned int y;

	if (node[x].right != RBNULL) {
		/* If right is not NULL then go right one and
		** then keep going left until we find a node with
		** no left pointer.
		*/
		y = node[x].right;
		while (node[y].left != RBNULL)
			y = node[y].left;
	} else {
		/* Go up the tree until we get to a node that is on the
		** left of its parent (or the root) and then return the
		** parent.
		*/
		y = node[x].up;
		while (y != RBNULL && x == node[y].right) {
			x = y;
			y = node[y].up;
		}
	}

	return y;
}

/* Restore the reb-black properties after insert */
static int
rb_insert_fix(MailTree *tree, unsigned int z)
{
	MailTreeNode *node = tree->node_base;
	unsigned int x, y, x_up_up;

	/* color this new node red */
	NODE_SET_RED(node[z]);

	/* Having added a red node, we must now walk back up the tree balancing
	** it, by a series of rotations and changing of colors
	*/
	x = z;

	/* While we are not at the top and our parent node is red
	** N.B. Since the root node is garanteed black, then we
	** are also going to stop if we are the child of the root
	*/

	while (x != tree->header->root && IS_NODE_RED(node[node[x].up])) {
		/* if our parent is on the left side of our grandparent */
		x_up_up = node[node[x].up].up;
		if (node[x].up == node[x_up_up].left) {
			/* get the right side of our grandparent (uncle?) */
			y = node[x_up_up].right;
			if (IS_NODE_RED(node[y])) {
				/* make our parent black */
				NODE_SET_BLACK(node[node[x].up]);
				/* make our uncle black */
				NODE_SET_BLACK(node[y]);
				/* make our grandparent red */
				NODE_SET_RED(node[x_up_up]);

				/* now consider our grandparent */
				x = x_up_up;
			} else {
				/* if we are on the right side of our parent */
				if (x == node[node[x].up].right) {
					/* Move up to our parent */
					x = node[x].up;
					rb_left_rotate(tree, x);
				}

				/* make our parent black */
				NODE_SET_BLACK(node[node[x].up]);
				/* make our grandparent red */
				NODE_SET_RED(node[x_up_up]);
				/* right rotate our grandparent */
				rb_right_rotate(tree, x_up_up);
			}
		} else {
			/* everything here is the same as above, but
			** exchanging left for right
			*/

			y = node[x_up_up].left;
			if (IS_NODE_RED(node[y])) {
				NODE_SET_BLACK(node[node[x].up]);
				NODE_SET_BLACK(node[y]);
				NODE_SET_RED(node[x_up_up]);

				x = x_up_up;
			} else {
				if (x == node[node[x].up].left) {
					x = node[x].up;
					rb_right_rotate(tree, x);
				}

				NODE_SET_BLACK(node[node[x].up]);
				NODE_SET_RED(node[x_up_up]);
				rb_left_rotate(tree, x_up_up);
			}
		}
	}

	/* Set the root node black */
	NODE_SET_BLACK(node[tree->header->root]);
	return z;
}

/* Restore the reb-black properties after a delete */
static void
rb_delete_fix(MailTree *tree, unsigned int x)
{
	MailTreeNode *node = tree->node_base;
	unsigned int w;

	while (x != tree->header->root && IS_NODE_BLACK(node[x])) {
		if (x == node[node[x].up].left) {
			w = node[node[x].up].right;
			if (IS_NODE_RED(node[w])) {
				NODE_SET_BLACK(node[w]);
				NODE_SET_RED(node[node[x].up]);
				rb_left_rotate(tree, node[x].up);
				w = node[node[x].up].right;
			}

			if (IS_NODE_BLACK(node[node[w].left]) &&
			    IS_NODE_BLACK(node[node[w].right])) {
				NODE_SET_RED(node[w]);
				x = node[x].up;
			} else {
				if (IS_NODE_BLACK(node[node[w].right])) {
					NODE_SET_BLACK(node[node[w].left]);
					NODE_SET_RED(node[w]);
					rb_right_rotate(tree, w);
					w = node[node[x].up].right;
				}


				NODE_COPY_COLOR(node[w], node[node[x].up]);
				NODE_SET_BLACK(node[node[x].up]);
				NODE_SET_BLACK(node[node[w].right]);
				rb_left_rotate(tree, node[x].up);
				x = tree->header->root;
			}
		} else {
			w = node[node[x].up].left;
			if (IS_NODE_RED(node[w])) {
				NODE_SET_BLACK(node[w]);
				NODE_SET_RED(node[node[x].up]);
				rb_right_rotate(tree, node[x].up);
				w = node[node[x].up].left;
			}

			if (IS_NODE_BLACK(node[node[w].right]) &&
			    IS_NODE_BLACK(node[node[w].left])) {
				NODE_SET_RED(node[w]);
				x = node[x].up;
			} else {
				if (IS_NODE_BLACK(node[node[w].left])) {
					NODE_SET_BLACK(node[node[w].right]);
					NODE_SET_RED(node[w]);
					rb_left_rotate(tree, w);
					w = node[node[x].up].left;
				}

				NODE_COPY_COLOR(node[w], node[node[x].up]);
				NODE_SET_BLACK(node[node[x].up]);
				NODE_SET_BLACK(node[node[w].left]);
				rb_right_rotate(tree, node[x].up);
				x = tree->header->root;
			}
		}
	}

	NODE_SET_BLACK(node[x]);
}

/*
** case 1 - only one child:
**
**            Z       -->  Y
**           /
**          Y
**
** Node count changes:
**   parents -= 1
**
** case 2 - right child has no left child:
**
**             Z              Y
**           /   \          /   \
**          A     Y   -->  A     X
**                  \
**                   X
**
** Node count changes:
**   parents -= 1
**   Y = Z-1
**
** case 3 - right child has left child:
**
**             Z              Y
**           /   \          /   \
**          A     B   -->  A     B
**              /              /
**            ..             ..
**           /              /
**          Y              X
**           \
**            X
**
** Node count changes:
**   parents -= 1
**   Y = Z-1
**   B .. X.up -= 1 (NOTE: X may not exist)
*/

/* Delete the node z, and free up the space
*/
static void
rb_delete(MailTree *tree, unsigned int z)
{
	MailTreeNode *node = tree->node_base;
        unsigned int x, y, b;

	if (node[z].left == RBNULL || node[z].right == RBNULL) {
		y = z;
		b = RBNULL;
	} else {
		y = rb_successor(tree, z);
		if (y == node[z].right)
			b = RBNULL;
		else
			b = node[z].right;
	}

	if (node[y].left != RBNULL)
		x = node[y].left;
	else
		x = node[y].right;

	/* this may modify RBNULL, which IMHO is a bit nasty,
	   but rb_delete_fix() requires it to work properly. */
	node[x].up = node[y].up;

	if (node[y].up == RBNULL) {
		tree->header->root = x;
	} else {
		if (y == node[node[y].up].left)
			node[node[y].up].left = x;
		else
			node[node[y].up].right = x;
	}

	if (y != z) {
		node[z].key = node[y].key;
		node[z].value = node[y].value;
	}

	if (b != RBNULL) {
		/* case 3 updates */
		while (b != x) {
			NODE_COUNT_ADD(node[b], -1);
			b = node[b].left;
		}
	}

	while (z != RBNULL) {
		NODE_COUNT_ADD(node[z], -1);
		z = node[z].up;
	}

	if (IS_NODE_BLACK(node[y]))
		rb_delete_fix(tree, x);

	rb_free(tree, y);
}

#ifdef DEBUG_TREE
int
rb_check1(MailTree *tree, unsigned int x)
{
        MailTreeNode *node = tree->node_base;

	if (IS_NODE_RED(node[x])) {
		if (!IS_NODE_BLACK(node[node[x].left]) ||
		    !IS_NODE_BLACK(node[node[x].right])) {
			i_error("Children of red node not both black, x=%u", x);
			return -1;
		}
	}

	if (node[x].left != RBNULL) {
		if (node[node[x].left].up != x) {
			i_error("x->left->up != x, x=%u", x);
			return -1;
		}

		if (rb_check1(tree, node[x].left))
			return -1;
	}		

	if (node[x].right != RBNULL) {
		if (node[node[x].right].up != x) {
			i_error("x->right->up != x, x=%u", x);
			return -1;
		}

		if (rb_check1(tree, node[x].right))
			return -1;
	}

	return 0;
}

int count_black(MailTree *tree, unsigned int x)
{
        MailTreeNode *node = tree->node_base;
	int nleft, nright;

	if (x == RBNULL)
		return 1;

	nleft = count_black(tree, node[x].left);
	nright = count_black(tree, node[x].right);

	if (nleft == -1 || nright == -1)
		return -1;

	if (nleft != nright) {
		i_error("Black count not equal on left & right, x=%u", x);
		return -1;
	}

	if (IS_NODE_BLACK(node[x]))
		nleft++;

	return nleft;
}

int count_nodes(MailTree *tree, unsigned int x)
{
        MailTreeNode *node = tree->node_base;
	int nleft, nright;

	if (x == RBNULL)
		return 0;

	nleft = count_nodes(tree, node[x].left);
	nright = count_nodes(tree, node[x].right);

	if (nleft == -1 || nright == -1)
		return -1;

	if (nleft+nright+1 != (int)NODE_COUNT(node[x])) {
		i_error("Invalid node count, x=%u, %d+%d+1 != %u",
			x, nleft, nright, NODE_COUNT(node[x]));
		return -1;
	}

	return nleft+nright+1;
}

void dumptree(MailTree *tree, unsigned int x, int n)
{
        MailTreeNode *node = tree->node_base;

	if (x != RBNULL) {
		n++;
		i_error("Tree: %*s %u: left=%u, right=%u, color=%s, "
			"nodes=%u, key=%u",
			n, "", x, node[x].left, node[x].right,
			IS_NODE_BLACK(node[x]) ? "BLACK" : "RED",
			NODE_COUNT(node[x]), node[x].key);

		dumptree(tree, node[x].left, n);
		dumptree(tree, node[x].right, n);
	}	
}

int
rb_check(MailTree *tree)
{
        MailTreeNode *node = tree->node_base;
	unsigned int root;

	root = tree->header->root;
	if (root == RBNULL)
		return 0;

	if (node[root].up != RBNULL) {
		i_error("Root up pointer not RBNULL");
		dumptree(tree, root, 0);
		return 1;
	}

	if (rb_check1(tree, root)) {
		dumptree(tree, root, 0);
		return 1;
	}

	if (count_black(tree, root) == -1) {
		dumptree(tree, root, 0);
		return -1;
	}

	if (count_nodes(tree, root) == -1) {
		dumptree(tree, root, 0);
		return -1;
	}

	return 0;
}
#endif

unsigned int mail_tree_lookup_uid_range(MailTree *tree, unsigned int *seq_r,
					unsigned int first_uid,
					unsigned int last_uid)
{
	MailTreeNode *node;
	unsigned int x, y, seq;

	i_assert(first_uid > 0 && last_uid > 0);
	i_assert(first_uid <= last_uid);
	i_assert(tree->index->lock_type != MAIL_LOCK_UNLOCK);

	if (!_mail_tree_mmap_update(tree, FALSE))
		return (unsigned int)-1;

	rb_check(tree);
	node = tree->node_base;

	if (seq_r != NULL)
		*seq_r = 0;

	y = RBNULL; /* points to the parent of x */
	x = tree->header->root;

	/* walk x down the tree */
	seq = 0;
	while (x != RBNULL) {
		y = x;

		if (first_uid < node[x].key)
			x = node[x].left;
		else {
			seq += NODE_COUNT(node[node[x].left])+1;
			if (first_uid > node[x].key)
				x = node[x].right;
			else {
				/* found it */
				if (seq_r != NULL)
					*seq_r = seq;
				return node[x].value;
			}
		}
	}

	if (first_uid != last_uid) {
		/* get the next key, make sure it's in range */
		if (node[y].key > first_uid)
			x = y;
		else
			x = rb_successor(tree, y);

		if (node[x].key > last_uid)
			x = RBNULL;
		else {
			if (seq_r != NULL)
				*seq_r = seq+1;
		}
	}

	return x == RBNULL ? (unsigned int)-1 : node[x].value;
}

unsigned int mail_tree_lookup_sequence(MailTree *tree, unsigned int seq)
{
        MailTreeNode *node;
	unsigned int x, upleft_nodes, left_nodes;

	i_assert(seq != 0);
	i_assert(tree->index->lock_type != MAIL_LOCK_UNLOCK);

	if (!_mail_tree_mmap_update(tree, FALSE))
		return (unsigned int)-1;

	rb_check(tree);
	node = tree->node_base;

	x = tree->header->root;

	/* walk x down the tree */
	seq--;
	upleft_nodes = left_nodes = 0;
	while (x != RBNULL) {
		left_nodes = upleft_nodes + NODE_COUNT(node[node[x].left]);

		if (seq < left_nodes)
			x = node[x].left;
		else if (seq > left_nodes) {
			upleft_nodes = left_nodes+1;
			x = node[x].right;
		} else {
			/* found it */
			return node[x].value;
		}
	}

	return (unsigned int)-1;
}

int mail_tree_insert(MailTree *tree, unsigned int uid, unsigned int index)
{
        MailTreeNode *node;
	unsigned int x, z;

	i_assert(uid != 0);
	i_assert(tree->index->lock_type == MAIL_LOCK_EXCLUSIVE);

	if (!_mail_tree_mmap_update(tree, FALSE))
		return FALSE;

	node = tree->node_base;

	/* we'll always insert to right side of the tree */
	x = tree->header->root;
	if (x != RBNULL) {
		while (node[x].right != RBNULL)
			x = node[x].right;
	}

	if (node[x].key >= uid) {
		_mail_tree_set_corrupted(tree,
			"UID to be inserted isn't higher than existing "
			"(%u <= %u)", uid, node[x].key);
		return FALSE;
	}

	if ((z = rb_alloc(tree)) == RBNULL)
		return FALSE;

	/* rb_alloc() may change mmap base */
	node = tree->node_base;

	node[z].key = uid;
	node[z].value = index;
	node[z].up = x;
	node[z].node_count = 1;
	node[z].left = RBNULL;
	node[z].right = RBNULL;

	if (x == RBNULL)
		tree->header->root = z;
	else {
		if (node[z].key < node[x].key)
			node[x].left = z;
		else
			node[x].right = z;
	}

	for (; x != RBNULL; x = node[x].up)
	     NODE_COUNT_ADD(node[x], 1);

        rb_insert_fix(tree, z);
        rb_check(tree);

	tree->modified = TRUE;
	return TRUE;
}

int mail_tree_update(MailTree *tree, unsigned int uid, unsigned int index)
{
	MailTreeNode *node;
	unsigned int x;

	i_assert(uid != 0);
	i_assert(tree->index->lock_type == MAIL_LOCK_EXCLUSIVE);

	if (!_mail_tree_mmap_update(tree, FALSE))
		return FALSE;

	rb_check(tree);
	node = tree->node_base;

	tree->modified = TRUE;

	x = tree->header->root;
	while (x != RBNULL) {
		if (uid < node[x].key)
			x = node[x].left;
		else if (uid > node[x].key)
			x = node[x].right;
		else {
			/* found it */
			node[x].value = index;
			return TRUE;
		}
	}

	_mail_tree_set_corrupted(tree, "Tried to update nonexisting UID %u",
				 uid);
	return FALSE;
}

void mail_tree_delete(MailTree *tree, unsigned int uid)
{
	MailTreeNode *node;
	unsigned int x;

	i_assert(uid != 0);
	i_assert(tree->index->lock_type == MAIL_LOCK_EXCLUSIVE);

	if (!_mail_tree_mmap_update(tree, FALSE))
		return;

	node = tree->node_base;

	x = tree->header->root;
	while (x != RBNULL) {
		if (uid < node[x].key)
			x = node[x].left;
		else if (uid > node[x].key)
			x = node[x].right;
		else {
			/* found it */
			rb_delete(tree, x);
			rb_check(tree);
			break;
		}
	}

	tree->modified = TRUE;
}
