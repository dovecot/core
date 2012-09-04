#ifndef MAILBOX_TREE_H
#define MAILBOX_TREE_H

#include "mailbox-list.h"

struct mailbox_node {
	struct mailbox_node *parent;
	struct mailbox_node *next;
	struct mailbox_node *children;

	char *name;
	enum mailbox_info_flags flags;
};
ARRAY_DEFINE_TYPE(mailbox_node, struct mailbox_node *);

struct mailbox_tree_context *mailbox_tree_init(char separator);
struct mailbox_tree_context *
mailbox_tree_init_size(char separator, unsigned int mailbox_node_size);
void mailbox_tree_deinit(struct mailbox_tree_context **tree);

void mailbox_tree_set_separator(struct mailbox_tree_context *tree,
				char separator);
void mailbox_tree_set_parents_nonexistent(struct mailbox_tree_context *tree);
void mailbox_tree_clear(struct mailbox_tree_context *tree);
pool_t mailbox_tree_get_pool(struct mailbox_tree_context *tree);

struct mailbox_node *
mailbox_tree_get(struct mailbox_tree_context *tree, const char *path,
		 bool *created_r);

struct mailbox_node *
mailbox_tree_lookup(struct mailbox_tree_context *tree, const char *path);

struct mailbox_tree_iterate_context * ATTR_NULL(2)
mailbox_tree_iterate_init(struct mailbox_tree_context *tree,
			  struct mailbox_node *root, unsigned int flags_mask);
struct mailbox_node *
mailbox_tree_iterate_next(struct mailbox_tree_iterate_context *ctx,
			  const char **path_r);
void mailbox_tree_iterate_deinit(struct mailbox_tree_iterate_context **ctx);

struct mailbox_tree_context *mailbox_tree_dup(struct mailbox_tree_context *src);
void mailbox_tree_sort(struct mailbox_tree_context *tree);

#endif
