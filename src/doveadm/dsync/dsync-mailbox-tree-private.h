#ifndef DSYNC_MAILBOX_TREE_PRIVATE_H
#define DSYNC_MAILBOX_TREE_PRIVATE_H

#include "dsync-mailbox-tree.h"

struct dsync_mailbox_tree {
	pool_t pool;
	char sep, sep_str[2], remote_sep;
	struct dsync_mailbox_node root;

	unsigned int iter_count;

	ARRAY_DEFINE(deletes, struct dsync_mailbox_delete);

	/* guid_128_t => struct dsync_mailbox_node */
	struct hash_table *name128_hash;
	struct hash_table *name128_remotesep_hash;
	struct hash_table *guid_hash;
};

void dsync_mailbox_tree_build_name128_hash(struct dsync_mailbox_tree *tree);

#endif
