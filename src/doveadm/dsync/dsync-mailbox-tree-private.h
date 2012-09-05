#ifndef DSYNC_MAILBOX_TREE_PRIVATE_H
#define DSYNC_MAILBOX_TREE_PRIVATE_H

#include "dsync-mailbox-tree.h"

struct dsync_mailbox_tree {
	pool_t pool;
	char sep, sep_str[2], remote_sep, alt_char;
	/* root node isn't part of the real mailbox tree. its name is "" and
	   it has no siblings */
	struct dsync_mailbox_node root;

	unsigned int iter_count;

	ARRAY(struct dsync_mailbox_delete) deletes;

	/* guid_128_t => struct dsync_mailbox_node */
	HASH_TABLE(uint8_t *, struct dsync_mailbox_node *) name128_hash;
	HASH_TABLE(uint8_t *, struct dsync_mailbox_node *) name128_remotesep_hash;
	HASH_TABLE(uint8_t *, struct dsync_mailbox_node *) guid_hash;
};

void dsync_mailbox_tree_build_name128_hash(struct dsync_mailbox_tree *tree);

int dsync_mailbox_node_name_cmp(struct dsync_mailbox_node *const *n1,
				struct dsync_mailbox_node *const *n2);

void dsync_mailbox_tree_node_attach(struct dsync_mailbox_node *node,
				    struct dsync_mailbox_node *parent);
void dsync_mailbox_tree_node_detach(struct dsync_mailbox_node *node);

struct dsync_mailbox_tree *
dsync_mailbox_tree_dup(const struct dsync_mailbox_tree *src);
bool dsync_mailbox_trees_equal(struct dsync_mailbox_tree *tree1,
			       struct dsync_mailbox_tree *tree2);

#endif
